#!/usr/bin/env python3
"""
Universal Kernel SKB Tracer
Uses BTF-discovered functions to trace all packet paths through kernel
"""

import os
import sys
import json
import time
import socket
import argparse
from datetime import datetime
from collections import defaultdict
from typing import Dict, List
from bcc import BPF

# BPF Program Template
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Trace event structure
struct trace_event_t {
    u64 timestamp;
    u64 skb_addr;
    u32 cpu_id;
    u32 pid;
    char func_name[64];
    
    // Packet info
    u8 protocol;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 len;
    
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// Hash to track SKB through different functions
BPF_HASH(skb_tracking, u64, u64, 10240);

// Helper to extract packet info
static inline void extract_packet_info(struct sk_buff *skb, struct trace_event_t *evt) {
    if (!skb) return;
    
    evt->skb_addr = (u64)skb;
    
    unsigned char *head;
    u16 network_header, transport_header;
    u32 len;
    
    bpf_probe_read(&head, sizeof(head), &skb->head);
    bpf_probe_read(&network_header, sizeof(network_header), &skb->network_header);
    bpf_probe_read(&transport_header, sizeof(transport_header), &skb->transport_header);
    bpf_probe_read(&len, sizeof(len), &skb->len);
    
    evt->len = len;
    
    // IP header
    struct iphdr *ip = (struct iphdr *)(head + network_header);
    u8 protocol;
    u32 saddr, daddr;
    
    bpf_probe_read(&protocol, sizeof(protocol), &ip->protocol);
    bpf_probe_read(&saddr, sizeof(saddr), &ip->saddr);
    bpf_probe_read(&daddr, sizeof(daddr), &ip->daddr);
    
    evt->protocol = protocol;
    evt->saddr = saddr;
    evt->daddr = daddr;
    
    // Ports for TCP/UDP
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        u16 *ports = (u16 *)(head + transport_header);
        u16 sport, dport;
        bpf_probe_read(&sport, sizeof(sport), &ports[0]);
        bpf_probe_read(&dport, sizeof(dport), &ports[1]);
        evt->sport = bpf_ntohs(sport);
        evt->dport = bpf_ntohs(dport);
    }
}

// Generic trace function for all SKB functions
int trace_skb_func(struct pt_regs *ctx, struct sk_buff *skb) {
    struct trace_event_t evt = {};
    
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get function name from BPF map (set by Python)
    u64 func_id = ctx->ip;
    
    // Extract packet info
    extract_packet_info(skb, &evt);
    
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    
    // Track this SKB
    if (evt.skb_addr != 0) {
        u64 count = 0;
        u64 *val = skb_tracking.lookup(&evt.skb_addr);
        if (val) count = *val;
        count++;
        skb_tracking.update(&evt.skb_addr, &count);
    }
    
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

class UniversalSKBTracer:
    """Universal tracer for all SKB functions"""
    
    def __init__(self, functions_file: str = None, max_functions: int = 50):
        self.max_functions = max_functions
        self.functions = []
        self.bpf = None
        self.running = False
        
        # Statistics
        self.total_events = 0
        self.events_by_func = defaultdict(int)
        self.events_by_skb = defaultdict(int)
        self.packets = []
        
        # Load functions
        if functions_file and os.path.exists(functions_file):
            self._load_functions_from_json(functions_file)
        else:
            self._load_default_functions()
    
    def _load_functions_from_json(self, filepath: str):
        """Load functions from BTF discoverer output"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Take top functions by priority
        all_funcs = data.get('functions', [])
        sorted_funcs = sorted(all_funcs, key=lambda x: (x['priority'], x['name']))
        
        self.functions = [f['name'] for f in sorted_funcs[:self.max_functions]]
        print(f"[*] Loaded {len(self.functions)} functions from {filepath}")
    
    def _load_default_functions(self):
        """Load default critical functions"""
        self.functions = [
            # Core packet path
            '__netif_receive_skb_core',
            'netif_receive_skb',
            'netif_rx',
            
            # IP layer
            'ip_rcv',
            'ip_rcv_finish',
            'ip_local_deliver',
            'ip_local_deliver_finish',
            'ip_forward',
            'ip_forward_finish',
            'ip_output',
            'ip_finish_output',
            
            # Netfilter
            'nf_hook_slow',
            'nft_do_chain',
            'nft_immediate_eval',
            
            # TCP
            'tcp_v4_rcv',
            'tcp_v4_do_rcv',
            'tcp_rcv_established',
            'tcp_transmit_skb',
            
            # UDP
            'udp_rcv',
            '__udp4_lib_rcv',
            
            # Device
            'dev_queue_xmit',
            '__dev_queue_xmit',
        ]
        print(f"[*] Using {len(self.functions)} default functions")
    
    def start(self):
        """Start tracing"""
        print("[*] Compiling BPF program...")
        
        try:
            self.bpf = BPF(text=BPF_PROGRAM)
            
            # Attach to all functions
            attached = 0
            failed = []
            
            for func_name in self.functions:
                try:
                    self.bpf.attach_kprobe(event=func_name, fn_name="trace_skb_func")
                    attached += 1
                except Exception as e:
                    failed.append((func_name, str(e)))
            
            print(f"[✓] Attached to {attached}/{len(self.functions)} functions")
            
            if failed:
                print(f"[!] Failed to attach {len(failed)} functions:")
                for func, err in failed[:5]:  # Show first 5
                    print(f"    - {func}: {err}")
            
            # Open perf buffer
            self.bpf["events"].open_perf_buffer(self._handle_event)
            self.running = True
            
            print("[✓] Tracer started")
            print("=" * 60)
            return True
            
        except Exception as e:
            print(f"[✗] Error starting tracer: {e}")
            return False
    
    def _handle_event(self, cpu, data, size):
        """Handle trace event"""
        event = self.bpf["events"].event(data)
        
        self.total_events += 1
        
        # Update statistics
        func_name = event.func_name.decode('utf-8', errors='ignore')
        self.events_by_func[func_name] += 1
        
        if event.skb_addr != 0:
            self.events_by_skb[event.skb_addr] += 1
        
        # Store packet info
        packet = {
            'timestamp': event.timestamp,
            'skb': hex(event.skb_addr),
            'function': func_name,
            'protocol': self._proto_name(event.protocol),
            'src': self._format_ip(event.saddr),
            'dst': self._format_ip(event.daddr),
            'sport': event.sport if event.sport > 0 else None,
            'dport': event.dport if event.dport > 0 else None,
            'len': event.len,
            'process': event.comm.decode('utf-8', errors='ignore'),
            'cpu': event.cpu_id
        }
        
        self.packets.append(packet)
        
        # Print first 20 events
        if self.total_events <= 20:
            print(f"[{self.total_events}] {packet['function']}: "
                  f"{packet['src']}:{packet['sport']} → "
                  f"{packet['dst']}:{packet['dport']} ({packet['protocol']})")
    
    def poll(self, timeout: int = 100):
        """Poll for events"""
        if self.bpf and self.running:
            self.bpf.perf_buffer_poll(timeout=timeout)
    
    def stop(self):
        """Stop tracing"""
        self.running = False
        
        if self.bpf:
            self.bpf.cleanup()
        
        print("\n" + "=" * 60)
        print("TRACE SUMMARY")
        print("=" * 60)
        print(f"Total events: {self.total_events}")
        print(f"Unique SKBs: {len(self.events_by_skb)}")
        print(f"Functions hit: {len(self.events_by_func)}")
        
        print("\nTop 10 functions by event count:")
        sorted_funcs = sorted(self.events_by_func.items(), 
                             key=lambda x: x[1], reverse=True)
        for i, (func, count) in enumerate(sorted_funcs[:10]):
            print(f"  {i+1}. {func}: {count} events")
        
        # Export to JSON
        self._export_json()
    
    def _export_json(self):
        """Export trace to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"universal_trace_{timestamp}.json"
        
        output = {
            'summary': {
                'total_events': self.total_events,
                'unique_skbs': len(self.events_by_skb),
                'functions_traced': len(self.functions),
                'functions_hit': len(self.events_by_func),
            },
            'statistics': {
                'by_function': dict(sorted(self.events_by_func.items(), 
                                          key=lambda x: x[1], reverse=True)),
                'by_skb': {hex(k): v for k, v in 
                          sorted(self.events_by_skb.items(), 
                                key=lambda x: x[1], reverse=True)[:100]}
            },
            'packets': self.packets[-1000:]  # Last 1000
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[✓] Exported to {filename}")
    
    @staticmethod
    def _format_ip(ip):
        if ip == 0:
            return None
        return socket.inet_ntoa(ip.to_bytes(4, byteorder='little'))
    
    @staticmethod
    def _proto_name(proto):
        protos = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protos.get(proto, f'PROTO_{proto}')

def main():
    parser = argparse.ArgumentParser(
        description='Universal Kernel SKB Tracer with BTF Discovery'
    )
    parser.add_argument('--functions', '-f', 
                       help='JSON file with discovered functions')
    parser.add_argument('--max-functions', '-m', type=int, default=50,
                       help='Maximum number of functions to trace')
    parser.add_argument('--duration', '-d', type=int, default=30,
                       help='Trace duration in seconds')
    
    args = parser.parse_args()
    
    # Check root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        sys.exit(1)
    
    # Create tracer
    tracer = UniversalSKBTracer(
        functions_file=args.functions,
        max_functions=args.max_functions
    )
    
    # Start
    if not tracer.start():
        sys.exit(1)
    
    print(f"[*] Tracing for {args.duration} seconds...")
    print("[*] Generate traffic to see traces")
    print()
    
    try:
        start_time = time.time()
        while time.time() - start_time < args.duration:
            tracer.poll()
            time.sleep(0.01)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    
    # Stop and export
    tracer.stop()

if __name__ == '__main__':
    main()
