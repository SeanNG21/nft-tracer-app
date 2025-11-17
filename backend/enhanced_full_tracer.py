#!/usr/bin/env python3
"""
Enhanced Full Tracer
Combines multi-function tracing with detailed NFT verdict tracking
Shows: ALL functions packet goes through + NFT verdicts
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
        ("rule_handle", ct.c_ulonglong),

        ("verdict_raw", ct.c_int),
        ("verdict", ct.c_uint),
        ("queue_num", ct.c_ushort),
        ("has_queue_bypass", ct.c_ubyte),

        ("function_name", ct.c_char * 64),
        ("comm", ct.c_char * 16),
    ]


class EnhancedFullTracer:
    """
    Comprehensive tracer combining:
    - Multi-function tracing (100+ kernel functions)
    - NFT verdict tracking (nft_do_chain, nft_immediate_eval)
    - Correlation by SKB address
    """

    EVENT_TYPES = {
        0: "FUNC",
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

    NFT_HOOKS = {
        0: "PREROUTING",
        1: "INPUT",
        2: "FORWARD",
        3: "OUTPUT",
        4: "POSTROUTING",
    }

    def __init__(self,
                 function_list=None,
                 priority=1,
                 sample_rate=1,
                 nft_only=False,
                 verbose=False,
                 group_by_skb=False):
        """
        Initialize Enhanced Full Tracer

        Args:
            function_list: File containing functions to trace (or None for auto-discovery)
            priority: Priority level (0-3) for auto-discovery
            sample_rate: Sample 1 out of N packets
            nft_only: If True, only show NFT events, suppress generic function calls
            verbose: Verbose output
            group_by_skb: Group events by SKB address for better readability
        """
        self.function_list = function_list
        self.priority = priority
        self.sample_rate = sample_rate
        self.nft_only = nft_only
        self.verbose = verbose
        self.group_by_skb = group_by_skb

        self.bpf = None
        self.function_names = {}
        self.stats = defaultdict(int)
        self.event_count = 0
        self.start_time = None
        self.running = False

        # For SKB grouping
        self.skb_events = defaultdict(list)
        self.last_flush = time.time()

    def load_functions(self):
        """Load function list from discovery or file"""
        if self.function_list:
            print(f"[*] Loading functions from {self.function_list}")

            if self.function_list.endswith('.json'):
                # JSON format from enhanced_btf_discoverer
                with open(self.function_list, 'r') as f:
                    data = json.load(f)
                    functions = [f['name'] for f in data.get('functions', [])]
            else:
                # Plain text format
                with open(self.function_list, 'r') as f:
                    functions = [line.strip() for line in f if line.strip()]

            print(f"[*] Loaded {len(functions)} functions")
            return functions
        else:
            print(f"[*] Auto-discovering SKB functions (priority <= {self.priority})")

            try:
                from enhanced_btf_discoverer import EnhancedBTFDiscoverer
                discoverer = EnhancedBTFDiscoverer()
                discovered = discoverer.discover_all(max_priority=self.priority)
                functions = [f.name for f in discovered]
                print(f"[*] Discovered {len(functions)} functions")
                return functions
            except Exception as e:
                print(f"[!] Discovery failed: {e}")
                print("[*] Using minimal function set")
                return [
                    '__netif_receive_skb_core',
                    'ip_rcv',
                    'ip_local_deliver',
                    'ip_forward',
                    'ip_output',
                    'tcp_v4_rcv',
                    'udp_rcv',
                ]

    def load_bpf_program(self):
        """Load and compile eBPF program"""
        print("[*] Loading Enhanced Full Tracer eBPF program...")

        bpf_file = os.path.join(os.path.dirname(__file__), 'enhanced_full_tracer.bpf.c')

        if not os.path.exists(bpf_file):
            raise FileNotFoundError(f"eBPF program not found: {bpf_file}")

        with open(bpf_file, 'r') as f:
            bpf_code = f.read()

        try:
            self.bpf = BPF(text=bpf_code)
            print("[✓] eBPF program compiled successfully")
        except Exception as e:
            print(f"[!] Failed to compile eBPF program: {e}")
            raise

    def attach_probes(self, functions):
        """Attach both NFT probes and generic SKB probes"""
        print(f"[*] Attaching probes...")

        attached = 0
        failed = []

        # 1. Attach NFT probes (always attach these)
        nft_probes = {
            'nft_do_chain': ('kprobe__nft_do_chain', 'kretprobe__nft_do_chain'),
            'nft_immediate_eval': ('kprobe__nft_immediate_eval', None),
        }

        print("[*] Attaching NFT probes...")
        for func_name, (kprobe_fn, kretprobe_fn) in nft_probes.items():
            try:
                self.bpf.attach_kprobe(event=func_name, fn_name=kprobe_fn)
                attached += 1
                if self.verbose:
                    print(f"  [✓] {func_name} (kprobe)")

                if kretprobe_fn:
                    self.bpf.attach_kretprobe(event=func_name, fn_name=kretprobe_fn)
                    attached += 1
                    if self.verbose:
                        print(f"  [✓] {func_name} (kretprobe)")

            except Exception as e:
                print(f"  [!] Failed to attach {func_name}: {e}")
                failed.append(func_name)

        # 2. Attach drop tracking
        print("[*] Attaching drop tracking...")
        try:
            self.bpf.attach_kprobe(event="kfree_skb_reason", fn_name="kprobe__kfree_skb_reason")
            attached += 1
            if self.verbose:
                print(f"  [✓] kfree_skb_reason")
        except:
            try:
                self.bpf.attach_kprobe(event="kfree_skb", fn_name="kprobe__kfree_skb")
                attached += 1
                if self.verbose:
                    print(f"  [✓] kfree_skb")
            except:
                pass

        # 3. Attach generic SKB probes to discovered functions
        print(f"[*] Attaching generic SKB probes to {len(functions)} functions...")

        for func_name in functions:
            # Skip NFT functions (already attached)
            if func_name in nft_probes:
                continue

            # Skip kfree_skb (already attached)
            if func_name in ['kfree_skb', 'kfree_skb_reason']:
                continue

            try:
                # Try parameter positions 1-5
                success = False
                for param_pos in [1, 2, 3, 4, 5]:
                    fn_name = f"trace_skb_{param_pos}"
                    try:
                        self.bpf.attach_kprobe(event=func_name, fn_name=fn_name)
                        attached += 1
                        success = True

                        if self.verbose:
                            print(f"  [✓] {func_name} -> P{param_pos}")

                        # Store function address
                        self._store_function_address(func_name)
                        break

                    except Exception:
                        if param_pos == 5:
                            raise
                        continue

                if not success:
                    failed.append(func_name)

            except Exception as e:
                failed.append(func_name)
                if self.verbose:
                    print(f"  [!] {func_name}: {e}")

        print(f"[✓] Attached {attached} probes successfully")

        if failed:
            print(f"[!] Failed to attach {len(failed)} probes")
            if self.verbose:
                for func in failed[:10]:
                    print(f"    - {func}")
                if len(failed) > 10:
                    print(f"    ... and {len(failed) - 10} more")

        return attached, failed

    def _store_function_address(self, func_name):
        """Get function address from kallsyms"""
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

    def configure(self):
        """Configure eBPF program settings"""
        config_map = self.bpf.get_table("config_map")

        config = config_map.Leaf()
        config.track_drops = 1
        config.sample_rate = self.sample_rate
        config.filter_proto = 0
        config.filter_port = 0
        config.nft_only = 1 if self.nft_only else 0

        config_map[ct.c_uint(0)] = config

        mode_desc = "NFT-only" if self.nft_only else "ALL functions + NFT"
        print(f"[*] Mode: {mode_desc}, sample_rate={self.sample_rate}")

    def format_ip(self, ip_int):
        """Convert integer IP to dotted notation"""
        return f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"

    def format_event(self, event):
        """Format event for display"""
        # Get function name
        func_name = self.function_names.get(event.func_addr, f"0x{event.func_addr:x}")

        # Event type
        event_type = self.EVENT_TYPES.get(event.event_type, f"TYPE_{event.event_type}")

        # Timestamp
        ts_sec = event.timestamp / 1_000_000_000.0
        time_str = datetime.fromtimestamp(ts_sec).strftime('%H:%M:%S.%f')[:-3]

        # Packet info
        proto = self.PROTOCOLS.get(event.protocol, str(event.protocol))
        src_ip = self.format_ip(event.src_ip)
        dst_ip = self.format_ip(event.dst_ip)

        # Build output
        output = f"[{time_str}] "
        output += f"CPU:{event.cpu_id} "
        output += f"SKB:0x{event.skb_addr:x} "

        if event.event_type == 0:  # FUNCTION_CALL
            output += f"{event_type:10} "
            output += f"{func_name:30} "
            output += f"P{event.param_position} "

        elif event.event_type == 1:  # NFT_CHAIN
            verdict = self.VERDICTS.get(event.verdict, str(event.verdict))
            hook = self.NFT_HOOKS.get(event.hook, str(event.hook))
            output += f"{event_type:10} "
            output += f"nft_do_chain".ljust(30) + " "
            output += f"hook={hook:12} "
            output += f"depth={event.chain_depth} "
            output += f"verdict={verdict:8} "

        elif event.event_type == 2:  # NFT_RULE
            verdict = self.VERDICTS.get(event.verdict, str(event.verdict))
            output += f"{event_type:10} "
            output += f"nft_immediate_eval".ljust(30) + " "
            output += f"rule#{event.rule_seq:3} "
            if event.rule_handle > 0:
                output += f"handle={event.rule_handle} "
            output += f"verdict={verdict:8} "

        elif event.event_type == 4:  # DROP
            output += f"{event_type:10} "
            output += f"kfree_skb".ljust(30) + " "
            if event.verdict > 0:
                output += f"reason={event.verdict} "

        # Packet details
        if event.src_ip != 0:
            output += f"| {proto:4} {src_ip}:{event.src_port} → {dst_ip}:{event.dst_port} "
            output += f"len={event.length}"

        return output

    def handle_event(self, cpu, data, size):
        """Handle events from perf buffer"""
        event = ct.cast(data, ct.POINTER(TraceEvent)).contents

        self.event_count += 1
        self.stats['total_events'] += 1

        # Track stats
        event_type = self.EVENT_TYPES.get(event.event_type, f"TYPE_{event.event_type}")
        self.stats[f'event_type_{event_type}'] += 1

        if event.protocol > 0:
            proto = self.PROTOCOLS.get(event.protocol, str(event.protocol))
            self.stats[f'proto_{proto}'] += 1

        if event.event_type == 2:  # NFT_RULE
            verdict = self.VERDICTS.get(event.verdict, "UNKNOWN")
            self.stats[f'nft_verdict_{verdict}'] += 1

        # Format and display
        output = self.format_event(event)

        if self.group_by_skb:
            # Group by SKB
            self.skb_events[event.skb_addr].append(output)

            # Flush old SKBs periodically
            now = time.time()
            if now - self.last_flush > 1.0:
                self._flush_old_skbs()
                self.last_flush = now
        else:
            # Print immediately
            print(output)

    def _flush_old_skbs(self):
        """Flush old SKB event groups"""
        # Print complete SKB traces
        for skb_addr, events in sorted(self.skb_events.items()):
            if len(events) > 0:
                print(f"\n{'='*120}")
                print(f"Packet Journey: SKB 0x{skb_addr:x} ({len(events)} events)")
                print(f"{'='*120}")
                for evt in events:
                    print(evt)
                print("")

        self.skb_events.clear()

    def print_statistics(self):
        """Print tracing statistics"""
        if not self.start_time:
            return

        duration = time.time() - self.start_time
        eps = self.event_count / duration if duration > 0 else 0

        print(f"\n{'='*80}")
        print(f"ENHANCED FULL TRACER STATISTICS")
        print(f"{'='*80}")
        print(f"Duration: {duration:.2f}s")
        print(f"Total Events: {self.event_count}")
        print(f"Events/sec: {eps:.2f}")

        # Event types
        print(f"\nEvent Types:")
        for key, count in sorted(self.stats.items()):
            if key.startswith('event_type_'):
                event_type = key.replace('event_type_', '')
                pct = (count / self.event_count * 100) if self.event_count > 0 else 0
                print(f"  {event_type:15} {count:6} ({pct:5.1f}%)")

        # NFT Verdicts
        nft_verdicts = {k: v for k, v in self.stats.items() if k.startswith('nft_verdict_')}
        if nft_verdicts:
            print(f"\nNFT Verdicts:")
            for key, count in sorted(nft_verdicts.items(), key=lambda x: -x[1]):
                verdict = key.replace('nft_verdict_', '')
                print(f"  {verdict:10} {count}")

        # Protocols
        print(f"\nTop Protocols:")
        proto_stats = {k: v for k, v in self.stats.items() if k.startswith('proto_')}
        for key, count in sorted(proto_stats.items(), key=lambda x: -x[1])[:5]:
            proto = key.replace('proto_', '')
            print(f"  {proto:4} {count}")

        print(f"{'='*80}\n")

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
        self.configure()

        # Attach probes
        attached, failed = self.attach_probes(functions)

        if attached == 0:
            print("[!] No probes attached!")
            return 1

        # Open perf buffer
        print("[*] Opening perf buffer...")
        self.bpf["events"].open_perf_buffer(self.handle_event, page_cnt=256)

        # Signal handler
        def signal_handler(sig, frame):
            print("\n[*] Stopping trace...")
            if self.group_by_skb:
                self._flush_old_skbs()
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start tracing
        mode_desc = "NFT verdicts only" if self.nft_only else "ALL functions + NFT verdicts"
        print(f"\n[✓] Tracing {mode_desc}... (Ctrl+C to stop)")
        print(f"[✓] {attached} probes attached\n")

        self.running = True
        self.start_time = time.time()

        try:
            while self.running:
                self.bpf.perf_buffer_poll(timeout=100)

        except KeyboardInterrupt:
            pass

        finally:
            if self.group_by_skb:
                self._flush_old_skbs()
            self.print_statistics()

        return 0


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Full Tracer - Multi-function + NFT verdict tracking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Trace ALL functions + NFT verdicts (priority 1)
  sudo %(prog)s --priority 1

  # Trace only NFT verdicts (suppress function calls)
  sudo %(prog)s --priority 1 --nft-only

  # Trace comprehensive (priority 2) with sampling
  sudo %(prog)s --priority 2 --sample-rate 10

  # Group events by packet (SKB address)
  sudo %(prog)s --priority 1 --group-by-skb

  # Use pre-discovered function list
  sudo %(prog)s --functions discovered_functions.json

  # Verbose mode
  sudo %(prog)s --priority 1 --verbose
        """
    )

    parser.add_argument('--functions', '-f',
                       help='File containing functions to trace (JSON or text)')

    parser.add_argument('--priority', '-p', type=int, default=1,
                       choices=[0, 1, 2, 3],
                       help='Priority for auto-discovery: 0=critical, 1=important, 2=normal, 3=all (default: 1)')

    parser.add_argument('--sample-rate', '-s', type=int, default=1,
                       help='Sample 1 out of N packets (default: 1 = all)')

    parser.add_argument('--nft-only', action='store_true',
                       help='Only show NFT events (suppress generic function calls)')

    parser.add_argument('--group-by-skb', action='store_true',
                       help='Group events by SKB address (packet journey view)')

    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges!")
        return 1

    # Run tracer
    tracer = EnhancedFullTracer(
        function_list=args.functions,
        priority=args.priority,
        sample_rate=args.sample_rate,
        nft_only=args.nft_only,
        verbose=args.verbose,
        group_by_skb=args.group_by_skb
    )

    return tracer.run()


if __name__ == '__main__':
    sys.exit(main())
