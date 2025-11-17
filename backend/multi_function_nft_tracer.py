#!/usr/bin/env python3
"""
Multi-Function NFT Tracer
Like pwru/cilium but with integrated NFT verdict tracking

Features:
- Auto-discovers ALL kernel functions handling sk_buff
- Classifies by network stack layers
- Traces complete packet journey through kernel
- Captures NFT verdicts for each packet
- Provides comprehensive packet flow visualization
"""

import os
import sys
import json
import time
import socket
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict, OrderedDict
from typing import Dict, List, Set
from bcc import BPF

# Event type constants
EVENT_FUNCTION = 0
EVENT_NFT_CHAIN = 1
EVENT_NFT_RULE = 2
EVENT_NF_HOOK = 3

# Verdict names
VERDICT_NAMES = {
    0: 'DROP',
    1: 'ACCEPT',
    2: 'STOLEN',
    3: 'QUEUE',
    4: 'REPEAT',
    5: 'STOP',
    10: 'CONTINUE',
    11: 'RETURN',
    12: 'JUMP',
    13: 'GOTO',
    14: 'BREAK',
    255: 'UNKNOWN'
}

# NFT hook names
HOOK_NAMES = {
    0: 'PREROUTING',
    1: 'INPUT',
    2: 'FORWARD',
    3: 'OUTPUT',
    4: 'POSTROUTING',
    255: 'UNKNOWN'
}

# Protocol names
PROTO_NAMES = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH'
}

class PacketTrace:
    """Represents a complete trace for a single packet (SKB)"""

    def __init__(self, skb_addr: int):
        self.skb_addr = skb_addr
        self.first_seen = None
        self.last_seen = None
        self.events = []
        self.functions = []  # All functions packet went through
        self.nft_chains = []  # NFT chains
        self.nft_rules = []  # NFT rules
        self.final_verdict = None

        # Packet info
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.protocol = None

    def add_event(self, event):
        """Add event to this packet's trace"""
        if self.first_seen is None:
            self.first_seen = event['timestamp']
        self.last_seen = event['timestamp']

        self.events.append(event)

        # Update packet info if not set
        if self.src_ip is None and event.get('src_ip'):
            self.src_ip = event['src_ip']
            self.dst_ip = event['dst_ip']
            self.src_port = event.get('src_port', 0)
            self.dst_port = event.get('dst_port', 0)
            self.protocol = event.get('protocol', 0)

        # Track different event types
        if event['event_type'] == EVENT_FUNCTION:
            self.functions.append(event)
        elif event['event_type'] == EVENT_NFT_CHAIN:
            self.nft_chains.append(event)
            if event.get('verdict') is not None:
                self.final_verdict = event['verdict']
        elif event['event_type'] == EVENT_NFT_RULE:
            self.nft_rules.append(event)

    def get_summary(self) -> str:
        """Get one-line summary of this packet trace"""
        proto = PROTO_NAMES.get(self.protocol, f'PROTO_{self.protocol}')
        flow = f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"
        func_count = len(self.functions)
        chain_count = len(self.nft_chains)
        rule_count = len(self.nft_rules)
        verdict = VERDICT_NAMES.get(self.final_verdict, 'N/A')

        return (f"[{proto}] {flow} | "
                f"Functions: {func_count}, NFT Chains: {chain_count}, "
                f"Rules: {rule_count} | Verdict: {verdict}")

    def get_detailed_trace(self) -> str:
        """Get detailed multi-line trace"""
        lines = []
        lines.append("=" * 80)
        lines.append(f"PACKET TRACE: {hex(self.skb_addr)}")
        lines.append("=" * 80)
        lines.append(self.get_summary())
        lines.append("")

        # Group events by layer
        by_layer = defaultdict(list)
        for evt in self.events:
            layer = evt.get('layer', 'Unknown')
            by_layer[layer].append(evt)

        # Print by layer
        for layer in ['Device', 'GRO', 'IPv4', 'IPv6', 'Routing', 'Netfilter',
                     'TCP', 'UDP', 'Xmit', 'SoftIRQ', 'Unknown']:
            if layer in by_layer:
                lines.append(f"\n{layer} Layer:")
                for evt in by_layer[layer]:
                    ts = evt['timestamp'] - self.first_seen
                    func = evt.get('func_name', '???')
                    lines.append(f"  [{ts/1000:8.3f}µs] {func}")

        # Print NFT details
        if self.nft_rules:
            lines.append("\nNFT Rules Evaluated:")
            for rule in self.nft_rules:
                ts = rule['timestamp'] - self.first_seen
                handle = rule.get('rule_handle', 0)
                verdict = VERDICT_NAMES.get(rule.get('verdict', 255), 'UNKNOWN')
                hook = HOOK_NAMES.get(rule.get('hook', 255), 'UNKNOWN')
                lines.append(f"  [{ts/1000:8.3f}µs] Rule #{handle} @ {hook}: {verdict}")

        return "\n".join(lines)


class MultiFunctionNFTTracer:
    """Main tracer class - combines multi-function tracing with NFT"""

    def __init__(self, config_file: str = None, max_functions: int = 50):
        self.config_file = config_file
        self.max_functions = max_functions
        self.bpf = None
        self.running = False

        # Function metadata
        self.functions_to_trace = []
        self.func_addr_to_name = {}  # Maps func address -> name
        self.func_name_to_layer = {}  # Maps func name -> layer

        # Packet traces
        self.packet_traces: Dict[int, PacketTrace] = {}
        self.total_events = 0

        # Statistics
        self.stats = {
            'packets_seen': 0,
            'functions_hit': set(),
            'nft_chains': 0,
            'nft_rules': 0,
            'by_verdict': defaultdict(int),
            'by_layer': defaultdict(int),
        }

    def load_functions(self):
        """Load functions to trace"""
        print("[*] Loading functions to trace...")

        if self.config_file and os.path.exists(self.config_file):
            # Load from config
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
            # Use critical functions
            print("[!] No config file, using critical functions only")
            self._load_critical_functions()

        print(f"[*] Will trace {len(self.functions_to_trace)} functions")

    def _load_critical_functions(self):
        """Load critical functions as fallback"""
        critical = [
            # Device
            {'name': '__netif_receive_skb_core', 'layer': 'Device', 'priority': 0},
            {'name': 'netif_receive_skb', 'layer': 'Device', 'priority': 0},

            # IP
            {'name': 'ip_rcv', 'layer': 'IPv4', 'priority': 0},
            {'name': 'ip_local_deliver', 'layer': 'IPv4', 'priority': 0},
            {'name': 'ip_forward', 'layer': 'IPv4', 'priority': 0},
            {'name': 'ip_output', 'layer': 'IPv4', 'priority': 0},

            # Netfilter (already handled by specialized hooks)
            # {'name': 'nf_hook_slow', 'layer': 'Netfilter', 'priority': 0},

            # TCP
            {'name': 'tcp_v4_rcv', 'layer': 'TCP', 'priority': 0},
            {'name': 'tcp_rcv_established', 'layer': 'TCP', 'priority': 0},

            # UDP
            {'name': 'udp_rcv', 'layer': 'UDP', 'priority': 0},

            # Xmit
            {'name': 'dev_queue_xmit', 'layer': 'Xmit', 'priority': 0},
        ]

        self.functions_to_trace = critical
        for func in critical:
            self.func_name_to_layer[func['name']] = func['layer']

    def start(self):
        """Start the tracer"""
        print("[*] Loading BPF program...")

        # Read BPF program
        bpf_file = os.path.join(os.path.dirname(__file__), 'multi_function_nft_trace.bpf.c')
        if not os.path.exists(bpf_file):
            print(f"[✗] BPF program not found: {bpf_file}")
            return False

        try:
            with open(bpf_file, 'r') as f:
                bpf_text = f.read()

            self.bpf = BPF(text=bpf_text)

            # Attach generic function tracer to all discovered functions
            print("[*] Attaching to kernel functions...")
            attached = 0
            failed = []

            for func in self.functions_to_trace:
                func_name = func['name']
                try:
                    self.bpf.attach_kprobe(event=func_name, fn_name="trace_skb_function")
                    attached += 1
                except Exception as e:
                    failed.append((func_name, str(e)))

            print(f"[✓] Attached to {attached}/{len(self.functions_to_trace)} functions")

            if failed and len(failed) <= 10:
                print(f"[!] Failed to attach to {len(failed)} functions:")
                for fname, err in failed[:5]:
                    print(f"    - {fname}: {err[:50]}")

            # NFT hooks are already attached via kprobe__nft_do_chain, etc.
            print("[✓] NFT hooks attached (nft_do_chain, nft_immediate_eval, nf_hook_slow)")

            # Build symbol table for function address lookup
            self._build_symbol_table()

            # Open perf buffer
            self.bpf["events"].open_perf_buffer(self._handle_event)
            self.running = True

            print("[✓] Tracer started successfully")
            print("=" * 80)
            return True

        except Exception as e:
            print(f"[✗] Failed to start tracer: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _build_symbol_table(self):
        """Build function address -> name mapping using /proc/kallsyms"""
        print("[*] Building kernel symbol table...")

        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue

                    addr_str, sym_type, name = parts[0], parts[1], parts[2]

                    # Only text symbols
                    if sym_type not in ['T', 't']:
                        continue

                    # Check if we're tracing this function
                    if name in self.func_name_to_layer:
                        addr = int(addr_str, 16)
                        self.func_addr_to_name[addr] = name

            print(f"[✓] Loaded {len(self.func_addr_to_name)} symbol addresses")

        except Exception as e:
            print(f"[!] Warning: Could not build symbol table: {e}")

    def _handle_event(self, cpu, data, size):
        """Handle incoming BPF event"""
        event = self.bpf["events"].event(data)
        self.total_events += 1

        # Convert event to dict
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
            'func_addr': event.func_addr,
            'func_name': None,
            'layer': 'Unknown',
            'comm': event.comm.decode('utf-8', errors='ignore'),
        }

        # Resolve function name
        if evt['event_type'] == EVENT_FUNCTION and evt['func_addr']:
            func_name = self.func_addr_to_name.get(evt['func_addr'], f"func_{evt['func_addr']:x}")
            evt['func_name'] = func_name
            evt['layer'] = self.func_name_to_layer.get(func_name, 'Unknown')
            self.stats['functions_hit'].add(func_name)
            self.stats['by_layer'][evt['layer']] += 1

        elif evt['event_type'] == EVENT_NFT_CHAIN:
            evt['func_name'] = 'nft_do_chain'
            evt['layer'] = 'Netfilter'
            self.stats['nft_chains'] += 1
            if evt['verdict'] is not None:
                self.stats['by_verdict'][evt['verdict']] += 1

        elif evt['event_type'] == EVENT_NFT_RULE:
            evt['func_name'] = 'nft_immediate_eval'
            evt['layer'] = 'Netfilter'
            self.stats['nft_rules'] += 1

        elif evt['event_type'] == EVENT_NF_HOOK:
            evt['func_name'] = 'nf_hook_slow'
            evt['layer'] = 'Netfilter'

        # Add to packet trace
        if evt['skb_addr'] != 0:
            skb = evt['skb_addr']
            if skb not in self.packet_traces:
                self.packet_traces[skb] = PacketTrace(skb)
                self.stats['packets_seen'] += 1

            self.packet_traces[skb].add_event(evt)

        # Print first 20 events
        if self.total_events <= 20:
            self._print_event(evt)

    def _print_event(self, evt):
        """Print a single event"""
        ts = evt['timestamp'] / 1_000_000_000  # ns to seconds
        event_type = ['FUNC', 'NFT_CHAIN', 'NFT_RULE', 'NF_HOOK'][evt['event_type']]
        func = evt.get('func_name', '???')
        layer = evt.get('layer', 'Unknown')

        flow = f"{evt['src_ip']}:{evt['src_port']} → {evt['dst_ip']}:{evt['dst_port']}"

        verdict_str = ""
        if evt.get('verdict') is not None:
            verdict_str = f" [{VERDICT_NAMES.get(evt['verdict'], '???')}]"

        print(f"[{self.total_events:4d}] {event_type:10s} {layer:10s} {func:30s} {flow}{verdict_str}")

    def poll(self, timeout: int = 100):
        """Poll for events"""
        if self.bpf and self.running:
            self.bpf.perf_buffer_poll(timeout=timeout)

    def stop(self):
        """Stop the tracer"""
        print("\n[*] Stopping tracer...")
        self.running = False

        if self.bpf:
            self.bpf.cleanup()

        self._print_statistics()
        self._print_sample_traces()
        self._export_results()

    def _print_statistics(self):
        """Print statistics"""
        print("\n" + "=" * 80)
        print("TRACE STATISTICS")
        print("=" * 80)
        print(f"Total events:       {self.total_events}")
        print(f"Packets traced:     {self.stats['packets_seen']}")
        print(f"Functions hit:      {len(self.stats['functions_hit'])}")
        print(f"NFT chains:         {self.stats['nft_chains']}")
        print(f"NFT rules:          {self.stats['nft_rules']}")

        print("\nEvents by Layer:")
        for layer, count in sorted(self.stats['by_layer'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {layer:15s}: {count:6d}")

        print("\nPackets by Verdict:")
        for verdict, count in sorted(self.stats['by_verdict'].items()):
            verdict_name = VERDICT_NAMES.get(verdict, f'UNKNOWN_{verdict}')
            print(f"  {verdict_name:15s}: {count:6d}")

    def _print_sample_traces(self, max_traces: int = 5):
        """Print sample packet traces"""
        print("\n" + "=" * 80)
        print(f"SAMPLE PACKET TRACES (showing up to {max_traces})")
        print("=" * 80)

        # Get packets with most events
        sorted_packets = sorted(
            self.packet_traces.values(),
            key=lambda p: len(p.events),
            reverse=True
        )

        for i, pkt in enumerate(sorted_packets[:max_traces]):
            print(f"\nPacket {i+1}:")
            print(pkt.get_summary())
            print(f"  Events: {len(pkt.events)}")
            print(f"  Duration: {(pkt.last_seen - pkt.first_seen)/1000:.3f}µs")

    def _export_results(self):
        """Export results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"multi_function_nft_trace_{timestamp}.json"

        # Prepare data
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

        # Export detailed traces (limit to 100 most interesting)
        sorted_packets = sorted(
            self.packet_traces.values(),
            key=lambda p: len(p.events),
            reverse=True
        )[:100]

        for pkt in sorted_packets:
            data['packet_traces'].append({
                'skb_addr': hex(pkt.skb_addr),
                'flow': f"{pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port}",
                'protocol': PROTO_NAMES.get(pkt.protocol, pkt.protocol),
                'duration_ns': pkt.last_seen - pkt.first_seen,
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
    parser = argparse.ArgumentParser(
        description='Multi-Function NFT Tracer - pwru/cilium-like with NFT integration'
    )
    parser.add_argument('--config', '-c',
                       help='Trace configuration JSON file')
    parser.add_argument('--max-functions', '-m', type=int, default=50,
                       help='Maximum functions to trace (default: 50)')
    parser.add_argument('--duration', '-d', type=int, default=30,
                       help='Trace duration in seconds (default: 30)')
    parser.add_argument('--discover', action='store_true',
                       help='Run discovery first to generate config')

    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        sys.exit(1)

    # Run discovery if requested
    if args.discover or not args.config:
        print("[*] Running enhanced SKB function discovery...")
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
            print("[!] Discovery script not found, using critical functions only")

    # Create and start tracer
    tracer = MultiFunctionNFTTracer(
        config_file=args.config,
        max_functions=args.max_functions
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
