#!/usr/bin/env python3
"""
Multi-Kprobe SKB Tracer
Comprehensive packet tracing across 100+ kernel functions (pwru-style)
Uses enhanced BTF discovery + multi-kprobe eBPF program
"""

import os
import sys
import json
import time
import signal
import argparse
from datetime import datetime
from collections import defaultdict, Counter
from bcc import BPF
import ctypes as ct


class TraceEvent(ct.Structure):
    """Matches the eBPF trace_event structure"""
    _fields_ = [
        ("timestamp", ct.c_ulonglong),
        ("skb_addr", ct.c_ulonglong),
        ("func_addr", ct.c_ulonglong),

        ("cpu_id", ct.c_uint),
        ("pid", ct.c_uint),

        ("event_type", ct.c_ubyte),
        ("param_position", ct.c_ubyte),
        ("hook", ct.c_ubyte),
        ("protocol", ct.c_ubyte),

        ("src_ip", ct.c_uint),
        ("dst_ip", ct.c_uint),
        ("src_port", ct.c_ushort),
        ("dst_port", ct.c_ushort),
        ("length", ct.c_uint),

        ("chain_addr", ct.c_ulonglong),
        ("expr_addr", ct.c_ulonglong),
        ("chain_depth", ct.c_ubyte),
        ("rule_seq", ct.c_ushort),

        ("verdict_raw", ct.c_int),
        ("verdict", ct.c_uint),

        ("comm", ct.c_char * 16),
    ]


class MultiKprobeTracer:
    """
    Comprehensive SKB tracer supporting 100+ kernel functions
    """

    EVENT_TYPES = {
        0: "FUNCTION_CALL",
        1: "NFT_CHAIN",
        2: "NFT_RULE",
        3: "NF_VERDICT",
        4: "DROP",
    }

    VERDICTS = {
        0: "DROP",
        1: "ACCEPT",
        2: "STOLEN",
        3: "QUEUE",
        4: "REPEAT",
        5: "STOP",
        10: "DROP",
        11: "ACCEPT",
        12: "STOLEN",
        13: "QUEUE",
        14: "REPEAT",
        255: "UNKNOWN",
    }

    PROTOCOLS = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
    }

    def __init__(self, function_list=None, priority=1, sample_rate=1, verbose=False):
        """
        Initialize tracer

        Args:
            function_list: List of function names to trace (or None for auto-discovery)
            priority: Priority level (0-3, lower = fewer functions)
            sample_rate: Sample 1 out of N packets (1 = all)
            verbose: Enable verbose output
        """
        self.function_list = function_list
        self.priority = priority
        self.sample_rate = sample_rate
        self.verbose = verbose

        self.bpf = None
        self.function_names = {}  # addr -> name mapping
        self.stats = defaultdict(int)
        self.event_count = 0
        self.start_time = None
        self.running = False

    def load_functions(self):
        """Load function list from discovery or file"""
        if self.function_list:
            # Load from file
            print(f"[*] Loading functions from {self.function_list}")
            with open(self.function_list, 'r') as f:
                functions = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(functions)} functions")
            return functions
        else:
            # Auto-discover
            print(f"[*] Auto-discovering SKB functions (priority <= {self.priority})")
            from enhanced_btf_discoverer import EnhancedBTFDiscoverer

            discoverer = EnhancedBTFDiscoverer()
            discovered = discoverer.discover_all(max_priority=self.priority)

            functions = [f.name for f in discovered]
            print(f"[*] Discovered {len(functions)} functions")

            return functions

    def load_bpf_program(self):
        """Load and compile eBPF program"""
        print("[*] Loading eBPF program...")

        bpf_file = os.path.join(os.path.dirname(__file__), 'multi_kprobe_tracer.bpf.c')

        if not os.path.exists(bpf_file):
            raise FileNotFoundError(f"eBPF program not found: {bpf_file}")

        with open(bpf_file, 'r') as f:
            bpf_code = f.read()

        # Compile
        try:
            self.bpf = BPF(text=bpf_code)
            print("[✓] eBPF program compiled successfully")
        except Exception as e:
            print(f"[!] Failed to compile eBPF program: {e}")
            raise

    def attach_kprobes(self, functions):
        """
        Attach kprobes to all specified functions

        For each function, we try to attach to the correct parameter position
        based on the function signature discovered from BTF
        """
        print(f"[*] Attaching kprobes to {len(functions)} functions...")

        attached = 0
        failed = []

        # NFT functions - attach manually with correct handlers
        nft_functions = {
            'nft_do_chain': ('kprobe__nft_do_chain', 'kretprobe__nft_do_chain'),
            'nft_immediate_eval': ('kprobe__nft_immediate_eval', None),
        }

        for func_name in functions:
            try:
                # Skip NFT functions (handled separately)
                if func_name in nft_functions:
                    kprobe_fn, kretprobe_fn = nft_functions[func_name]

                    # Attach kprobe
                    self.bpf.attach_kprobe(event=func_name, fn_name=kprobe_fn)
                    attached += 1

                    # Attach kretprobe if exists
                    if kretprobe_fn:
                        self.bpf.attach_kretprobe(event=func_name, fn_name=kretprobe_fn)
                        attached += 1

                    if self.verbose:
                        print(f"  [✓] {func_name} (NFT handler)")

                    continue

                # For regular SKB functions, try parameter positions 1-5
                # We'll try position 1 first (most common)
                success = False

                for param_pos in [1, 2, 3, 4, 5]:
                    fn_name = f"trace_skb_{param_pos}"

                    try:
                        self.bpf.attach_kprobe(event=func_name, fn_name=fn_name)
                        attached += 1
                        success = True

                        if self.verbose:
                            print(f"  [✓] {func_name} -> P{param_pos}")

                        # Store function address mapping for name resolution
                        self._store_function_address(func_name)

                        break  # Success, no need to try other positions

                    except Exception as e:
                        # Try next parameter position
                        if param_pos == 5:
                            # All positions failed
                            raise e
                        continue

                if not success:
                    failed.append(func_name)

            except Exception as e:
                failed.append(func_name)
                if self.verbose:
                    print(f"  [!] {func_name}: {e}")

        # Also attach to drop tracking functions
        try:
            self.bpf.attach_kprobe(event="kfree_skb_reason", fn_name="kprobe__kfree_skb_reason")
            attached += 1
            if self.verbose:
                print(f"  [✓] kfree_skb_reason (drop tracking)")
        except:
            try:
                self.bpf.attach_kprobe(event="kfree_skb", fn_name="kprobe__kfree_skb")
                attached += 1
                if self.verbose:
                    print(f"  [✓] kfree_skb (drop tracking)")
            except:
                pass

        print(f"[✓] Attached {attached} kprobes successfully")

        if failed:
            print(f"[!] Failed to attach {len(failed)} kprobes:")
            for func in failed[:10]:
                print(f"    - {func}")
            if len(failed) > 10:
                print(f"    ... and {len(failed) - 10} more")

        return attached, failed

    def _store_function_address(self, func_name):
        """Get function address from kallsyms for name resolution"""
        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2] == func_name:
                        addr = int(parts[0], 16)
                        self.function_names[addr] = func_name
                        return addr
        except:
            pass
        return None

    def configure_sampling(self):
        """Configure eBPF program settings"""
        config_map = self.bpf.get_table("config_map")

        config = config_map.Leaf()
        config.track_drops = 1
        config.sample_rate = self.sample_rate
        config.filter_proto = 0  # 0 = all protocols
        config.filter_port = 0   # 0 = all ports

        config_map[ct.c_uint(0)] = config

        print(f"[*] Configuration: sample_rate={self.sample_rate}, track_drops=1")

    def format_ip(self, ip_int):
        """Convert integer IP to dotted notation"""
        return f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"

    def handle_event(self, cpu, data, size):
        """Handle events from perf buffer"""
        event = ct.cast(data, ct.POINTER(TraceEvent)).contents

        self.event_count += 1
        self.stats['total_events'] += 1

        # Get function name from address
        func_name = self.function_names.get(event.func_addr, f"0x{event.func_addr:x}")

        # Event type
        event_type = self.EVENT_TYPES.get(event.event_type, f"TYPE_{event.event_type}")
        self.stats[f'event_type_{event_type}'] += 1

        # Timestamp
        ts_sec = event.timestamp / 1_000_000_000.0
        time_str = datetime.fromtimestamp(ts_sec).strftime('%H:%M:%S.%f')[:-3]

        # Packet info
        proto = self.PROTOCOLS.get(event.protocol, str(event.protocol))
        src_ip = self.format_ip(event.src_ip)
        dst_ip = self.format_ip(event.dst_ip)

        # Build output string
        output_parts = [
            f"[{time_str}]",
            f"CPU:{event.cpu_id}",
            f"SKB:0x{event.skb_addr:x}",
            f"{event_type}",
        ]

        if event.event_type == 0:  # FUNCTION_CALL
            output_parts.append(f"{func_name}")
            output_parts.append(f"P{event.param_position}")

        elif event.event_type == 1:  # NFT_CHAIN
            verdict = self.VERDICTS.get(event.verdict, str(event.verdict))
            output_parts.append(f"nft_do_chain")
            output_parts.append(f"depth={event.chain_depth}")
            output_parts.append(f"verdict={verdict}")

        elif event.event_type == 2:  # NFT_RULE
            verdict = self.VERDICTS.get(event.verdict, str(event.verdict))
            output_parts.append(f"nft_immediate_eval")
            output_parts.append(f"rule#{event.rule_seq}")
            output_parts.append(f"verdict={verdict}")

        elif event.event_type == 4:  # DROP
            output_parts.append(f"kfree_skb")
            if event.verdict > 0:
                output_parts.append(f"reason={event.verdict}")

        # Packet details
        if event.src_ip != 0:
            output_parts.append(f"{proto} {src_ip}:{event.src_port} → {dst_ip}:{event.dst_port}")
            output_parts.append(f"len={event.length}")

        # Process name
        comm = event.comm.decode('utf-8', 'ignore').rstrip('\x00')
        if comm:
            output_parts.append(f"({comm})")

        print(" ".join(output_parts))

        # Track statistics
        if event.event_type == 0:
            self.stats[f'func_{func_name}'] += 1
        if event.protocol > 0:
            self.stats[f'proto_{proto}'] += 1

    def print_statistics(self):
        """Print tracing statistics"""
        if not self.start_time:
            return

        duration = time.time() - self.start_time
        eps = self.event_count / duration if duration > 0 else 0

        print(f"\n{'='*70}")
        print(f"TRACE STATISTICS")
        print(f"{'='*70}")
        print(f"Duration: {duration:.2f}s")
        print(f"Total Events: {self.event_count}")
        print(f"Events/sec: {eps:.2f}")

        # Event types
        print(f"\nEvent Types:")
        for key, count in sorted(self.stats.items()):
            if key.startswith('event_type_'):
                event_type = key.replace('event_type_', '')
                print(f"  {event_type}: {count}")

        # Top protocols
        print(f"\nTop Protocols:")
        proto_stats = {k: v for k, v in self.stats.items() if k.startswith('proto_')}
        for key, count in sorted(proto_stats.items(), key=lambda x: -x[1])[:5]:
            proto = key.replace('proto_', '')
            print(f"  {proto}: {count}")

        # Top functions
        print(f"\nTop Functions Hit:")
        func_stats = {k: v for k, v in self.stats.items() if k.startswith('func_')}
        for key, count in sorted(func_stats.items(), key=lambda x: -x[1])[:20]:
            func = key.replace('func_', '')
            print(f"  {func}: {count}")

        print(f"{'='*70}\n")

    def run(self):
        """Main run loop"""
        # Load functions
        functions = self.load_functions()

        if not functions:
            print("[!] No functions to trace!")
            return 1

        # Load eBPF program
        self.load_bpf_program()

        # Configure
        self.configure_sampling()

        # Attach kprobes
        attached, failed = self.attach_kprobes(functions)

        if attached == 0:
            print("[!] No kprobes attached!")
            return 1

        # Open perf buffer
        print("[*] Opening perf buffer...")
        self.bpf["events"].open_perf_buffer(self.handle_event, page_cnt=256)

        # Signal handler
        def signal_handler(sig, frame):
            print("\n[*] Stopping trace...")
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start tracing
        print(f"[✓] Tracing {attached} kernel functions... (Ctrl+C to stop)\n")
        self.running = True
        self.start_time = time.time()

        try:
            while self.running:
                self.bpf.perf_buffer_poll(timeout=100)

        except KeyboardInterrupt:
            pass

        finally:
            # Print statistics
            self.print_statistics()

        return 0


def main():
    parser = argparse.ArgumentParser(
        description='Multi-Kprobe SKB Tracer - Comprehensive packet tracing (pwru-style)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover and trace critical functions only
  sudo %(prog)s --priority 0

  # Trace critical + important functions (recommended)
  sudo %(prog)s --priority 1

  # Trace comprehensive set (1000+ functions like pwru)
  sudo %(prog)s --priority 3

  # Use pre-discovered function list
  sudo %(prog)s --functions discovered_functions.txt

  # Sample 1 out of 10 packets (reduce overhead)
  sudo %(prog)s --priority 2 --sample-rate 10

  # Verbose mode
  sudo %(prog)s --priority 1 --verbose
        """
    )

    parser.add_argument('--functions', '-f',
                       help='File containing list of functions to trace (one per line)')

    parser.add_argument('--priority', '-p', type=int, default=1,
                       choices=[0, 1, 2, 3],
                       help='Priority level for auto-discovery: 0=critical, 1=important, 2=normal, 3=all (default: 1)')

    parser.add_argument('--sample-rate', '-s', type=int, default=1,
                       help='Sample 1 out of N packets (1 = all, 10 = 10%%, default: 1)')

    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')

    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges!")
        return 1

    # Run tracer
    tracer = MultiKprobeTracer(
        function_list=args.functions,
        priority=args.priority,
        sample_rate=args.sample_rate,
        verbose=args.verbose
    )

    return tracer.run()


if __name__ == '__main__':
    sys.exit(main())
