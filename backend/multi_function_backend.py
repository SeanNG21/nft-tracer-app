#!/usr/bin/env python3
"""
Multi-Function NFT Tracer - Backend Integration
Compatible với app.py backend và realtime WebSocket
Output format giống NFT/Full tracer để dùng chung frontend
"""

import os
import sys
import json
import time
import socket
import ctypes as ct
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
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

@dataclass
class MultiFunctionEvent:
    """Multi-function trace event - compatible with backend"""
    timestamp: int
    cpu_id: int
    pid: int
    skb_addr: int

    # Event classification
    event_type: int  # FUNCTION, NFT_CHAIN, NFT_RULE, NF_HOOK
    layer: str       # Device, IPv4, TCP, Netfilter, etc.
    func_name: str

    # Packet info
    protocol: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int

    # NFT specific
    hook: int = 255
    pf: int = 0
    chain_addr: int = 0
    chain_depth: int = 0
    rule_seq: int = 0
    rule_handle: int = 0

    # Verdict
    verdict: int = 255
    verdict_raw: int = 0
    verdict_name: str = ''

    # Process
    comm: str = ''

    def to_dict(self):
        """Convert to dict for JSON/WebSocket"""
        return asdict(self)

    def to_log_line(self):
        """Convert to human-readable log line"""
        event_type_str = ['FUNC', 'NFT_CHAIN', 'NFT_RULE', 'NF_HOOK'][self.event_type]
        flow = f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"
        verdict_str = f" [{self.verdict_name}]" if self.verdict_name else ""
        return f"[{event_type_str:10s}] {self.layer:10s} {self.func_name:30s} {flow}{verdict_str}"


class MultiFunctionBackendTracer:
    """
    Multi-function tracer với backend integration
    Compatible với app.py và realtime WebSocket
    """

    def __init__(self,
                 config_file: str = None,
                 max_functions: int = 50,
                 event_callback: Optional[Callable] = None,
                 stats_callback: Optional[Callable] = None):

        self.config_file = config_file
        self.max_functions = max_functions
        self.event_callback = event_callback  # Callback cho mỗi event (WebSocket)
        self.stats_callback = stats_callback  # Callback cho stats (periodic)

        self.bpf = None
        self.running = False
        self.functions_to_trace = []

        # Statistics
        self.total_events = 0
        self.start_time = None
        self.stats = {
            'packets_seen': 0,
            'total_events': 0,
            'functions_hit': set(),
            'nft_chains': 0,
            'nft_rules': 0,
            'by_verdict': defaultdict(int),
            'by_layer': defaultdict(int),
            'by_function': defaultdict(int),
        }

        # Event buffer for batch processing
        self.event_buffer = []
        self.last_stats_emit = time.time()

    def load_functions(self):
        """Load functions to trace from config"""
        if self.config_file and os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            self.functions_to_trace = [
                f for f in config['functions']
                if f.get('enabled', True)
            ][:self.max_functions]

            print(f"[✓] Loaded {len(self.functions_to_trace)} functions from config")
        else:
            # Fallback: critical functions
            self.functions_to_trace = [
                {'name': '__netif_receive_skb_core', 'layer': 'Device', 'priority': 0},
                {'name': 'ip_rcv', 'layer': 'IPv4', 'priority': 0},
                {'name': 'ip_local_deliver', 'layer': 'IPv4', 'priority': 0},
                {'name': 'tcp_v4_rcv', 'layer': 'TCP', 'priority': 0},
                {'name': 'dev_queue_xmit', 'layer': 'Xmit', 'priority': 0},
            ]
            print(f"[!] Using {len(self.functions_to_trace)} critical functions")

    def _generate_bpf_code(self) -> str:
        """Generate BPF code dynamically"""
        bpf_base_path = os.path.join(os.path.dirname(__file__), 'ebpf', 'multi_function_nft_trace_v2.bpf.c')
        with open(bpf_base_path, 'r') as f:
            base_bpf = f.read()

        # Generate wrappers
        wrappers = []
        for idx, func in enumerate(self.functions_to_trace):
            wrapper = f"""
int trace_{idx}(struct pt_regs *ctx, struct sk_buff *skb) {{
    return trace_skb_generic(ctx, skb, {idx});
}}
"""
            wrappers.append(wrapper)

        return base_bpf + "\n\n// Generated wrappers:\n" + "\n".join(wrappers)

    def start(self) -> bool:
        """Start the tracer"""
        try:
            print("[*] Generating BPF code...")
            bpf_code = self._generate_bpf_code()

            print("[*] Compiling BPF program...")
            self.bpf = BPF(text=bpf_code)

            # Populate function metadata
            print("[*] Populating function metadata...")
            func_meta = self.bpf.get_table("func_meta")
            for idx, func in enumerate(self.functions_to_trace):
                meta = func_meta.Leaf()
                meta.name = func['name'].encode('utf-8')[:63] + b'\x00'
                meta.layer = func.get('layer', 'Unknown').encode('utf-8')[:15] + b'\x00'
                meta.priority = func.get('priority', 2)
                func_meta[func_meta.Key(idx)] = meta

            # Attach kprobes
            print("[*] Attaching to kernel functions...")
            attached = 0
            for idx, func in enumerate(self.functions_to_trace):
                try:
                    self.bpf.attach_kprobe(event=func['name'], fn_name=f"trace_{idx}")
                    attached += 1
                except:
                    pass

            print(f"[✓] Attached to {attached}/{len(self.functions_to_trace)} functions")

            # Open perf buffer
            self.bpf["events"].open_perf_buffer(
                self._handle_event,
                page_cnt=256
            )

            self.running = True
            self.start_time = time.time()

            print("[✓] Multi-function tracer started")
            return True

        except Exception as e:
            print(f"[✗] Failed to start: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _handle_event(self, cpu, data, size):
        """Handle BPF event"""
        try:
            event = self.bpf["events"].event(data)
            self.total_events += 1

            # Convert to MultiFunctionEvent
            evt = MultiFunctionEvent(
                timestamp=event.timestamp,
                cpu_id=event.cpu_id,
                pid=event.pid,
                skb_addr=event.skb_addr,
                event_type=event.event_type,
                layer=event.layer.decode('utf-8', errors='ignore').rstrip('\x00'),
                func_name=event.func_name.decode('utf-8', errors='ignore').rstrip('\x00'),
                protocol=event.protocol,
                src_ip=self._format_ip(event.src_ip),
                dst_ip=self._format_ip(event.dst_ip),
                src_port=event.src_port,
                dst_port=event.dst_port,
                length=event.length,
                hook=event.hook,
                pf=event.pf,
                chain_addr=event.chain_addr,
                chain_depth=event.chain_depth,
                rule_seq=event.rule_seq,
                rule_handle=event.rule_handle,
                verdict=event.verdict,
                verdict_raw=event.verdict_raw,
                verdict_name=VERDICT_NAMES.get(event.verdict, ''),
                comm=event.comm.decode('utf-8', errors='ignore')
            )

            # Update stats
            self._update_stats(evt)

            # Callback to frontend (WebSocket emit)
            if self.event_callback:
                self.event_callback(evt)

            # Periodic stats callback
            if self.stats_callback and time.time() - self.last_stats_emit > 1.0:
                self.stats_callback(self.get_stats())
                self.last_stats_emit = time.time()

        except Exception as e:
            print(f"[!] Event handling error: {e}")

    def _update_stats(self, evt: MultiFunctionEvent):
        """Update statistics"""
        self.stats['total_events'] = self.total_events

        if evt.skb_addr != 0:
            self.stats['packets_seen'] += 1

        if evt.event_type == EVENT_FUNCTION:
            self.stats['functions_hit'].add(evt.func_name)
            self.stats['by_layer'][evt.layer] += 1
            self.stats['by_function'][evt.func_name] += 1
        elif evt.event_type == EVENT_NFT_CHAIN:
            self.stats['nft_chains'] += 1
            if evt.verdict != 255:
                self.stats['by_verdict'][evt.verdict_name] += 1
        elif evt.event_type == EVENT_NFT_RULE:
            self.stats['nft_rules'] += 1

    def get_stats(self) -> Dict:
        """Get current statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0

        return {
            'total_events': self.stats['total_events'],
            'packets_seen': self.stats['packets_seen'],
            'functions_hit': len(self.stats['functions_hit']),
            'nft_chains': self.stats['nft_chains'],
            'nft_rules': self.stats['nft_rules'],
            'uptime_seconds': uptime,
            'events_per_second': self.stats['total_events'] / uptime if uptime > 0 else 0,
            'by_layer': dict(self.stats['by_layer']),
            'by_verdict': dict(self.stats['by_verdict']),
            'top_functions': dict(sorted(
                self.stats['by_function'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:20])
        }

    def poll(self, timeout: int = 100):
        """Poll for events"""
        if self.bpf and self.running:
            self.bpf.perf_buffer_poll(timeout=timeout)

    def stop(self):
        """Stop tracer"""
        self.running = False
        if self.bpf:
            self.bpf.cleanup()
        print("[✓] Multi-function tracer stopped")

    @staticmethod
    def _format_ip(ip):
        if ip == 0:
            return "0.0.0.0"
        try:
            return socket.inet_ntoa(ip.to_bytes(4, byteorder='little'))
        except:
            return "?.?.?.?"


# Standalone mode for testing
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Multi-Function Backend Tracer')
    parser.add_argument('--config', '-c', help='Trace config JSON')
    parser.add_argument('--max-functions', '-m', type=int, default=50)
    parser.add_argument('--duration', '-d', type=int, default=30)

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Requires root")
        sys.exit(1)

    # Event callback: print to console
    def print_event(evt: MultiFunctionEvent):
        print(evt.to_log_line())

    # Stats callback: print summary
    def print_stats(stats: Dict):
        print(f"\n[Stats] Events: {stats['total_events']:6d} | "
              f"Packets: {stats['packets_seen']:4d} | "
              f"Functions: {stats['functions_hit']:3d}")

    tracer = MultiFunctionBackendTracer(
        config_file=args.config,
        max_functions=args.max_functions,
        event_callback=print_event,
        stats_callback=print_stats
    )

    tracer.load_functions()

    if not tracer.start():
        sys.exit(1)

    print(f"[*] Tracing for {args.duration} seconds...")

    try:
        start = time.time()
        while time.time() - start < args.duration:
            tracer.poll()
            time.sleep(0.01)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")

    tracer.stop()

    # Final stats
    stats = tracer.get_stats()
    print("\n" + "="*80)
    print("FINAL STATISTICS")
    print("="*80)
    print(json.dumps(stats, indent=2))
