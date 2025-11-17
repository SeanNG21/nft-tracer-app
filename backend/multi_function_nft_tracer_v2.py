#!/usr/bin/env python3
"""
Multi-Function NFT Tracer V2 - FIXED symbol resolution
Uses dynamic code generation instead of runtime address lookup
"""

import os
import sys
import json
import time
import socket
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict
from typing import Dict, List
from bcc import BPF

# Event types
EVENT_FUNCTION = 0
EVENT_NFT_CHAIN = 1
EVENT_NFT_RULE = 2
EVENT_NF_HOOK = 3

# Verdicts
VERDICT_NAMES = {
    0: 'DROP', 1: 'ACCEPT', 2: 'STOLEN', 3: 'QUEUE', 4: 'REPEAT', 5: 'STOP',
    10: 'CONTINUE', 11: 'RETURN', 12: 'JUMP', 13: 'GOTO', 14: 'BREAK', 255: 'UNKNOWN'
}

HOOK_NAMES = {
    0: 'PREROUTING', 1: 'INPUT', 2: 'FORWARD', 3: 'OUTPUT', 4: 'POSTROUTING', 255: 'UNKNOWN'
}

PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}

class PacketTrace:
    """Represents complete trace for one packet"""
    def __init__(self, skb_addr: int):
        self.skb_addr = skb_addr
        self.first_seen = None
        self.last_seen = None
        self.events = []
        self.functions = []
        self.nft_chains = []
        self.nft_rules = []
        self.final_verdict = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.protocol = None

    def add_event(self, event):
        if self.first_seen is None:
            self.first_seen = event['timestamp']
        self.last_seen = event['timestamp']
        self.events.append(event)

        if self.src_ip is None and event.get('src_ip'):
            self.src_ip = event['src_ip']
            self.dst_ip = event['dst_ip']
            self.src_port = event.get('src_port', 0)
            self.dst_port = event.get('dst_port', 0)
            self.protocol = event.get('protocol', 0)

        if event['event_type'] == EVENT_FUNCTION:
            self.functions.append(event)
        elif event['event_type'] == EVENT_NFT_CHAIN:
            self.nft_chains.append(event)
            if event.get('verdict') is not None:
                self.final_verdict = event['verdict']
        elif event['event_type'] == EVENT_NFT_RULE:
            self.nft_rules.append(event)

    def get_summary(self) -> str:
        proto = PROTO_NAMES.get(self.protocol, f'PROTO_{self.protocol}')
        flow = f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"
        verdict = VERDICT_NAMES.get(self.final_verdict, 'N/A')
        return (f"[{proto}] {flow} | Functions: {len(self.functions)}, "
                f"NFT Chains: {len(self.nft_chains)}, Rules: {len(self.nft_rules)} | Verdict: {verdict}")


class MultiFunctionNFTTracerV2:
    """V2 tracer with fixed symbol resolution"""

    def __init__(self, config_file: str = None, max_functions: int = 50, verbose: bool = False, print_interval: int = 100):
        self.config_file = config_file
        self.max_functions = max_functions
        self.verbose = verbose  # Print all events if True
        self.print_interval = print_interval  # Print every N events
        self.bpf = None
        self.running = False

        self.functions_to_trace = []
        self.func_name_to_layer = {}

        self.packet_traces: Dict[int, PacketTrace] = {}
        self.total_events = 0

        self.stats = {
            'packets_seen': 0,
            'functions_hit': set(),
            'nft_chains': 0,
            'nft_rules': 0,
            'by_verdict': defaultdict(int),
            'by_layer': defaultdict(int),
        }

    def load_functions(self):
        print("[*] Loading functions to trace...")

        if self.config_file and os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            self.functions_to_trace = [
                f for f in config['functions']
                if f.get('enabled', True)
            ][:self.max_functions]

            for func in self.functions_to_trace:
                self.func_name_to_layer[func['name']] = func.get('layer', 'Unknown')

            print(f"[✓] Loaded {len(self.functions_to_trace)} functions from config")
        else:
            self._load_critical_functions()

        print(f"[*] Will trace {len(self.functions_to_trace)} functions")

    def _load_critical_functions(self):
        """Load critical functions as fallback"""
        critical = [
            {'name': '__netif_receive_skb_core', 'layer': 'Device', 'priority': 0},
            {'name': 'netif_receive_skb', 'layer': 'Device', 'priority': 0},
            {'name': 'ip_rcv', 'layer': 'IPv4', 'priority': 0},
            {'name': 'ip_local_deliver', 'layer': 'IPv4', 'priority': 0},
            {'name': 'ip_forward', 'layer': 'IPv4', 'priority': 0},
            {'name': 'ip_output', 'layer': 'IPv4', 'priority': 0},
            {'name': 'tcp_v4_rcv', 'layer': 'TCP', 'priority': 0},
            {'name': 'tcp_rcv_established', 'layer': 'TCP', 'priority': 0},
            {'name': 'udp_rcv', 'layer': 'UDP', 'priority': 0},
            {'name': 'dev_queue_xmit', 'layer': 'Xmit', 'priority': 0},
        ]
        self.functions_to_trace = critical
        for func in critical:
            self.func_name_to_layer[func['name']] = func['layer']

    def _generate_bpf_code(self) -> str:
        """Generate BPF code dynamically with wrapper for each function"""
        # Read base BPF template
        base_bpf = open('multi_function_nft_trace_v2.bpf.c', 'r').read()

        # Generate wrapper functions
        wrappers = []
        for idx, func in enumerate(self.functions_to_trace):
            func_name = func['name']
            wrapper = f"""
// Wrapper for {func_name}
int trace_{idx}(struct pt_regs *ctx, struct sk_buff *skb) {{
    return trace_skb_generic(ctx, skb, {idx});
}}
"""
            wrappers.append(wrapper)

        # Combine
        full_code = base_bpf + "\n\n// Generated wrappers:\n" + "\n".join(wrappers)
        return full_code

    def start(self):
        print("[*] Generating BPF code...")
        bpf_code = self._generate_bpf_code()

        print("[*] Compiling BPF program...")
        try:
            self.bpf = BPF(text=bpf_code)

            # Populate function metadata map
            print("[*] Populating function metadata...")
            func_meta = self.bpf.get_table("func_meta")
            for idx, func in enumerate(self.functions_to_trace):
                meta = func_meta.Leaf()
                name = func['name'].encode('utf-8')[:63]
                layer = func.get('layer', 'Unknown').encode('utf-8')[:15]
                meta.name = name + b'\x00'
                meta.layer = layer + b'\x00'
                meta.priority = func.get('priority', 2)
                func_meta[func_meta.Key(idx)] = meta

            # Attach kprobes to kernel functions
            print("[*] Attaching to kernel functions...")
            attached = 0
            failed = []

            for idx, func in enumerate(self.functions_to_trace):
                func_name = func['name']
                wrapper_name = f"trace_{idx}"
                try:
                    self.bpf.attach_kprobe(event=func_name, fn_name=wrapper_name)
                    attached += 1
                except Exception as e:
                    failed.append((func_name, str(e)[:50]))

            print(f"[✓] Attached to {attached}/{len(self.functions_to_trace)} functions")

            if failed and len(failed) <= 10:
                print(f"[!] Failed to attach to {len(failed)} functions:")
                for fname, err in failed[:5]:
                    print(f"    - {fname}: {err}")

            # NFT hooks are auto-attached via naming
            print("[✓] NFT hooks attached (nft_do_chain, nft_immediate_eval, nf_hook_slow)")

            # Open perf buffer with LARGER size to avoid lost samples
            self.bpf["events"].open_perf_buffer(
                self._handle_event,
                page_cnt=256  # Increased from default 8 to 256 (256 * 4KB = 1MB buffer)
            )
            self.running = True

            print("[✓] Tracer started successfully")
            print("="*80)
            return True

        except Exception as e:
            print(f"[✗] Failed to start tracer: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _handle_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        self.total_events += 1

        evt = {
            'timestamp': event.timestamp,
            'skb_addr': event.skb_addr,
            'cpu_id': event.cpu_id,
            'pid': event.pid,
            'event_type': event.event_type,
            'hook': event.hook,
            'pf': event.pf,
            'protocol': event.protocol,
            'src_ip': self._format_ip(event.src_ip),
            'dst_ip': self._format_ip(event.dst_ip),
            'src_port': event.src_port,
            'dst_port': event.dst_port,
            'length': event.length,
            'chain_addr': event.chain_addr,
            'expr_addr': event.expr_addr,
            'chain_depth': event.chain_depth,
            'rule_seq': event.rule_seq,
            'rule_handle': event.rule_handle,
            'verdict_raw': event.verdict_raw,
            'verdict': event.verdict,
            'queue_num': event.queue_num,
            'has_queue_bypass': event.has_queue_bypass,
            'func_name': event.func_name.decode('utf-8', errors='ignore').rstrip('\x00'),
            'layer': event.layer.decode('utf-8', errors='ignore').rstrip('\x00'),
            'comm': event.comm.decode('utf-8', errors='ignore'),
        }

        # Update stats
        if evt['event_type'] == EVENT_FUNCTION:
            self.stats['functions_hit'].add(evt['func_name'])
            self.stats['by_layer'][evt['layer']] += 1
        elif evt['event_type'] == EVENT_NFT_CHAIN:
            self.stats['nft_chains'] += 1
            if evt['verdict'] is not None and evt['verdict'] != 255:
                self.stats['by_verdict'][evt['verdict']] += 1
        elif evt['event_type'] == EVENT_NFT_RULE:
            self.stats['nft_rules'] += 1

        # Add to packet trace
        if evt['skb_addr'] != 0:
            skb = evt['skb_addr']
            if skb not in self.packet_traces:
                self.packet_traces[skb] = PacketTrace(skb)
                self.stats['packets_seen'] += 1

            self.packet_traces[skb].add_event(evt)

        # Print events based on mode
        if self.verbose:
            # Verbose mode: print ALL events
            self._print_event(evt)
        elif self.total_events % self.print_interval == 0:
            # Periodic mode: print every N events with summary
            self._print_event_summary()
        elif self.total_events <= 20:
            # Initial mode: print first 20 events for quick feedback
            self._print_event(evt)

    def _print_event(self, evt):
        ts = evt['timestamp'] / 1_000_000_000
        event_type = ['FUNC', 'NFT_CHAIN', 'NFT_RULE', 'NF_HOOK'][evt['event_type']]
        func = evt.get('func_name', '???') or '???'
        layer = evt.get('layer', 'Unknown') or 'Unknown'
        flow = f"{evt['src_ip']}:{evt['src_port']} → {evt['dst_ip']}:{evt['dst_port']}"

        verdict_str = ""
        if evt.get('verdict') is not None and evt['verdict'] != 255:
            verdict_str = f" [{VERDICT_NAMES.get(evt['verdict'], '???')}]"

        print(f"[{self.total_events:4d}] {event_type:10s} {layer:10s} {func:30s} {flow}{verdict_str}")

    def _print_event_summary(self):
        """Print periodic summary of events"""
        print(f"\n[{self.total_events:6d} events] Packets: {self.stats['packets_seen']:4d} | "
              f"Functions: {len(self.stats['functions_hit']):3d} | "
              f"NFT Chains: {self.stats['nft_chains']:3d} | "
              f"NFT Rules: {self.stats['nft_rules']:3d}")

    def poll(self, timeout: int = 100):
        if self.bpf and self.running:
            self.bpf.perf_buffer_poll(timeout=timeout)

    def stop(self):
        print("\n[*] Stopping tracer...")
        self.running = False

        if self.bpf:
            self.bpf.cleanup()

        self._print_statistics()
        self._export_results()

    def _print_statistics(self):
        print("\n" + "="*80)
        print("TRACE STATISTICS")
        print("="*80)
        print(f"Total events:       {self.total_events}")
        print(f"Packets traced:     {self.stats['packets_seen']}")
        print(f"Functions hit:      {len(self.stats['functions_hit'])}")
        print(f"NFT chains:         {self.stats['nft_chains']}")
        print(f"NFT rules:          {self.stats['nft_rules']}")

        if self.stats['by_layer']:
            print("\nEvents by Layer:")
            for layer, count in sorted(self.stats['by_layer'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {layer:15s}: {count:6d}")

        if self.stats['by_verdict']:
            print("\nPackets by Verdict:")
            for verdict, count in sorted(self.stats['by_verdict'].items()):
                verdict_name = VERDICT_NAMES.get(verdict, f'UNKNOWN_{verdict}')
                print(f"  {verdict_name:15s}: {count:6d}")

        # Sample packet traces
        if self.packet_traces:
            print("\n" + "="*80)
            print("SAMPLE PACKET TRACES (top 5 by event count)")
            print("="*80)
            sorted_packets = sorted(self.packet_traces.values(), key=lambda p: len(p.events), reverse=True)
            for i, pkt in enumerate(sorted_packets[:5]):
                print(f"\nPacket {i+1}:")
                print(f"  {pkt.get_summary()}")
                print(f"  Events: {len(pkt.events)}, Duration: {(pkt.last_seen - pkt.first_seen)/1000:.3f}µs")

    def _export_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"multi_function_nft_trace_{timestamp}.json"

        data = {
            'summary': {
                'total_events': self.total_events,
                'packets_traced': self.stats['packets_seen'],
                'functions_hit': len(self.stats['functions_hit']),
                'nft_chains': self.stats['nft_chains'],
                'nft_rules': self.stats['nft_rules'],
            },
            'statistics': {
                'by_layer': dict(self.stats['by_layer']),
                'by_verdict': {VERDICT_NAMES.get(k, str(k)): v
                              for k, v in self.stats['by_verdict'].items()},
                'functions_hit': list(self.stats['functions_hit']),
            },
            'packet_traces': []
        }

        sorted_packets = sorted(self.packet_traces.values(), key=lambda p: len(p.events), reverse=True)[:100]
        for pkt in sorted_packets:
            data['packet_traces'].append({
                'skb_addr': hex(pkt.skb_addr),
                'flow': f"{pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port}",
                'protocol': PROTO_NAMES.get(pkt.protocol, pkt.protocol),
                'duration_ns': pkt.last_seen - pkt.first_seen if pkt.last_seen else 0,
                'total_events': len(pkt.events),
                'functions': len(pkt.functions),
                'nft_chains': len(pkt.nft_chains),
                'nft_rules': len(pkt.nft_rules),
                'verdict': VERDICT_NAMES.get(pkt.final_verdict, 'N/A'),
                'events': pkt.events
            })

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[✓] Exported to {filename}")

    @staticmethod
    def _format_ip(ip):
        if ip == 0:
            return "0.0.0.0"
        try:
            return socket.inet_ntoa(ip.to_bytes(4, byteorder='little'))
        except:
            return "?.?.?.?"


def main():
    parser = argparse.ArgumentParser(description='Multi-Function NFT Tracer V2 (Fixed)')
    parser.add_argument('--config', '-c', help='Trace configuration JSON')
    parser.add_argument('--max-functions', '-m', type=int, default=50)
    parser.add_argument('--duration', '-d', type=int, default=30)
    parser.add_argument('--discover', action='store_true', help='Run discovery first')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Print ALL events (default: first 20 + periodic summary)')
    parser.add_argument('--print-interval', '-i', type=int, default=100,
                       help='Print summary every N events (default: 100)')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        sys.exit(1)

    if args.discover or not args.config:
        print("[*] Running function discovery...")
        discover_script = os.path.join(os.path.dirname(__file__), 'enhanced_skb_discoverer.py')
        if os.path.exists(discover_script):
            subprocess.run([
                'python3', discover_script,
                '--output', 'enhanced_skb_functions.json',
                '--config', 'trace_config.json',
                '--max-trace', str(args.max_functions)
            ])
            args.config = 'trace_config.json'
        else:
            print("[!] Discovery script not found, using critical functions")

    tracer = MultiFunctionNFTTracerV2(
        config_file=args.config,
        max_functions=args.max_functions,
        verbose=args.verbose,
        print_interval=args.print_interval
    )

    tracer.load_functions()

    if not tracer.start():
        sys.exit(1)

    print(f"[*] Tracing for {args.duration} seconds...")
    print("[*] Generate network traffic to see traces")
    print()

    try:
        start_time = time.time()
        while time.time() - start_time < args.duration:
            tracer.poll()
            time.sleep(0.01)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")

    tracer.stop()


if __name__ == '__main__':
    main()
