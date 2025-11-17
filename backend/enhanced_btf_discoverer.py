#!/usr/bin/env python3
"""
Enhanced BTF SKB Function Discoverer v2
Discovers ALL kernel functions that handle sk_buff (pwru-style)
Supports comprehensive network stack tracing
"""

import os
import re
import json
import subprocess
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

@dataclass
class SKBFunction:
    """Represents a kernel function that handles sk_buff"""
    name: str
    param_position: int  # Which parameter is sk_buff (1-5)
    category: str
    priority: int  # 0=critical, 1=important, 2=normal, 3=optional
    signature: str = ""

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, SKBFunction):
            return self.name == other.name
        return False


class EnhancedBTFDiscoverer:
    """
    Discovers ALL kernel functions handling sk_buff using BTF
    Similar to pwru's comprehensive approach
    """

    # Extended categories for comprehensive classification
    CATEGORIES = {
        # NFT/Netfilter (highest priority for this project)
        'nft': [
            'nft_', 'nf_tables_'
        ],
        'netfilter': [
            'nf_', 'xt_', 'ipt_', 'ip6t_', 'ebt_', 'arpt_'
        ],

        # Core network device layer
        'netdev': [
            '__netif_', 'netif_', 'dev_', '__dev_',
            'napi_', '__napi_', 'eth_', 'vlan_'
        ],

        # IP layer
        'ip': [
            'ip_', '__ip_', 'ipv4_', 'ip6_', 'ipv6_', '__ipv6_'
        ],

        # TCP layer
        'tcp': [
            'tcp_', '__tcp_'
        ],

        # UDP layer
        'udp': [
            'udp_', '__udp_', 'udp6_', 'udplite_'
        ],

        # ICMP
        'icmp': [
            'icmp_', 'icmp6_', 'icmpv6_'
        ],

        # Routing and forwarding
        'routing': [
            'fib_', 'rt_', 'rt6_', 'dst_', 'ip_route_', 'ip6_route_'
        ],

        # Connection tracking
        'conntrack': [
            'nf_ct_', 'nf_conntrack_', '__nf_ct_'
        ],

        # NAT
        'nat': [
            'nf_nat_', '__nf_nat_', 'masquerade_'
        ],

        # Bridge
        'bridge': [
            'br_', '__br_', 'nbp_'
        ],

        # Packet socket
        'packet': [
            'packet_', 'tpacket_'
        ],

        # QoS/Traffic control
        'qdisc': [
            'qdisc_', 'sch_', 'tbf_', 'pfifo_', 'sfq_'
        ],

        # IPsec
        'ipsec': [
            'xfrm_', 'esp_', 'ah_', 'ipcomp_'
        ],

        # Tunneling
        'tunnel': [
            'ip_tunnel_', 'ip6_tunnel_', 'gre_', 'vxlan_', 'geneve_'
        ],

        # Socket layer
        'socket': [
            'sock_', '__sock_', 'sk_', '__sk_'
        ],

        # SKB management
        'skb': [
            'skb_', '__skb_', 'pskb_', '__pskb_', 'kfree_skb'
        ],
    }

    # High-priority functions that should always be traced
    PRIORITY_FUNCTIONS = {
        0: [  # CRITICAL - Core packet path (NFT + main path)
            # NFT core
            'nft_do_chain',
            'nft_immediate_eval',

            # Main receive path
            '__netif_receive_skb_core',
            'netif_receive_skb',
            'netif_receive_skb_internal',

            # IP layer
            'ip_rcv',
            'ip_rcv_finish',
            'ip_output',
            'ip_local_deliver',

            # Netfilter hooks
            'nf_hook_slow',
            'NF_HOOK',

            # Drop/free
            'kfree_skb_reason',
            'consume_skb',
        ],

        1: [  # IMPORTANT - Detailed processing
            # NFT rules
            'nft_lookup_eval',
            'nft_payload_eval',
            'nft_cmp_eval',
            'nft_counter_eval',
            'nft_meta_eval',

            # IP forwarding
            'ip_forward',
            'ip_forward_finish',

            # Local delivery
            'ip_local_deliver_finish',

            # Output path
            'ip_finish_output',
            '__ip_finish_output',
            'ip_output',

            # TCP/UDP
            'tcp_v4_rcv',
            'tcp_v4_do_rcv',
            'udp_rcv',
            '__udp4_lib_rcv',

            # Connection tracking
            'nf_conntrack_in',
            'nf_ct_deliver_cached_events',

            # NAT
            'nf_nat_ipv4_in',
            'nf_nat_ipv4_out',
            'nf_nat_ipv4_local_fn',
        ],

        2: [  # NORMAL - Useful for debugging
            # GRO/GSO
            'napi_gro_receive',
            'dev_gro_receive',
            'inet_gro_receive',

            # Queue management
            'dev_queue_xmit',
            '__dev_queue_xmit',
            'dev_hard_start_xmit',

            # Routing
            'ip_route_input_slow',
            'ip_route_input_noref',
            'fib_validate_source',

            # Fragment handling
            'ip_fragment',
            'ip_defrag',

            # Bridge
            'br_handle_frame',
            'br_forward',
        ],
    }

    # Functions to explicitly exclude (not useful or too noisy)
    EXCLUDE_PATTERNS = [
        r'.*_init$',
        r'.*_exit$',
        r'.*_setup$',
        r'.*_destroy$',
        r'.*_alloc$',
        r'.*_free$',
        r'.*_get$',
        r'.*_put$',
        r'.*_lock$',
        r'.*_unlock$',
        r'.*_show$',
        r'.*_seq_.*',
        r'.*_debugfs_.*',
        r'.*_sysctl_.*',
        r'.*_proc_.*',
    ]

    def __init__(self):
        self.functions: Set[SKBFunction] = set()
        self.function_signatures: Dict[str, str] = {}

    def discover_all(self, max_priority: int = 2) -> List[SKBFunction]:
        """
        Discover ALL SKB functions from kernel BTF

        Args:
            max_priority: Only return functions with priority <= max_priority
                         0 = critical only (~20 functions)
                         1 = critical + important (~60 functions)
                         2 = normal set (~200 functions)
                         3 = comprehensive set (1000+ functions, like pwru)
        """
        print(f"[*] Enhanced BTF Discovery (max_priority={max_priority})")
        print("[*] Discovering SKB functions from kernel BTF...")

        # Method 1: Parse BTF using bpftool (most accurate)
        success = self._discover_via_bpftool()

        # Method 2: Fallback to kallsyms if BTF fails
        if not success or len(self.functions) < 10:
            print("[*] BTF discovery incomplete, using kallsyms fallback...")
            self._discover_via_kallsyms()

        # Categorize and prioritize
        self._categorize_functions()

        # Filter by priority
        filtered_funcs = [f for f in self.functions if f.priority <= max_priority]

        # Sort by priority then name
        sorted_funcs = sorted(filtered_funcs, key=lambda x: (x.priority, x.name))

        # Print statistics
        self._print_statistics(sorted_funcs)

        return sorted_funcs

    def _discover_via_bpftool(self) -> bool:
        """Discover using bpftool BTF dump (most accurate)"""
        try:
            print("[*] Running bpftool to dump kernel BTF...")

            result = subprocess.run(
                ['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                print(f"[!] bpftool failed: {result.stderr}")
                return False

            # Parse BTF output
            found_count = self._parse_btf_c_output(result.stdout)
            print(f"[✓] Found {found_count} sk_buff functions via BTF")

            return found_count > 0

        except FileNotFoundError:
            print("[!] bpftool not found, install: apt-get install linux-tools-$(uname -r)")
            return False
        except subprocess.TimeoutExpired:
            print("[!] bpftool timeout")
            return False
        except Exception as e:
            print(f"[!] Error discovering via BTF: {e}")
            return False

    def _parse_btf_c_output(self, btf_output: str) -> int:
        """
        Parse bpftool BTF C output to find sk_buff functions
        Looks for: return_type function_name(...struct sk_buff *...);
        """
        count = 0

        # Pattern to match function declarations with sk_buff parameter
        # Examples:
        #   int nft_do_chain(struct nft_pktinfo *pkt, void *priv);
        #   int ip_rcv(struct sk_buff *skb, struct net_device *dev, ...);
        func_pattern = re.compile(
            r'^\s*(?P<return_type>\w+(?:\s+\w+)*)\s+'  # return type
            r'(?P<func_name>\w+)\s*'                    # function name
            r'\((?P<params>[^)]+)\);',                  # parameters
            re.MULTILINE
        )

        for match in func_pattern.finditer(btf_output):
            func_name = match.group('func_name')
            params = match.group('params')
            signature = match.group(0).strip()

            # Check if any parameter is struct sk_buff *
            if 'struct sk_buff' not in params:
                continue

            # Skip if in exclude list
            if self._should_exclude(func_name):
                continue

            # Find which parameter position has sk_buff
            param_position = self._find_skb_param_position(params)

            # Create function entry
            func = SKBFunction(
                name=func_name,
                param_position=param_position,
                category='unknown',
                priority=3,  # Default to optional
                signature=signature
            )

            self.functions.add(func)
            self.function_signatures[func_name] = signature
            count += 1

        return count

    def _find_skb_param_position(self, params: str) -> int:
        """Find which parameter position (1-5) has struct sk_buff"""
        param_list = [p.strip() for p in params.split(',')]

        for i, param in enumerate(param_list, start=1):
            if 'struct sk_buff' in param and '*' in param:
                return min(i, 5)  # Cap at 5 like pwru

        return 1  # Default to first parameter

    def _should_exclude(self, func_name: str) -> bool:
        """Check if function should be excluded"""
        for pattern in self.EXCLUDE_PATTERNS:
            if re.match(pattern, func_name):
                return True
        return False

    def _discover_via_kallsyms(self):
        """Fallback: discover using kallsyms (heuristic-based)"""
        try:
            print("[*] Parsing /proc/kallsyms for SKB functions...")
            count = 0

            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue

                    func_type = parts[1]
                    func_name = parts[2]

                    # Only look at text symbols (functions)
                    if func_type not in ['T', 't']:
                        continue

                    # Heuristic: likely SKB functions
                    if self._is_likely_skb_function(func_name) and not self._should_exclude(func_name):
                        func = SKBFunction(
                            name=func_name,
                            param_position=1,  # Assume first param
                            category='unknown',
                            priority=3,
                        )
                        self.functions.add(func)
                        count += 1

            print(f"[✓] Found {count} likely SKB functions via kallsyms")

        except Exception as e:
            print(f"[!] Error reading kallsyms: {e}")

    def _is_likely_skb_function(self, func_name: str) -> bool:
        """Heuristic to determine if function likely handles SKB"""
        skb_indicators = [
            'skb_', '__skb_', 'pskb_',
            '_rcv', '_xmit', '_transmit', '_receive',
            '_forward', '_output', '_input',
            'nft_', 'nf_', 'netif_',
            'tcp_', 'udp_', 'ip_', 'ip6_',
            'kfree_skb', 'consume_skb',
        ]

        return any(indicator in func_name for indicator in skb_indicators)

    def _categorize_functions(self):
        """Categorize and prioritize discovered functions"""
        for func in self.functions:
            # Assign category based on prefix
            for category, prefixes in self.CATEGORIES.items():
                if any(func.name.startswith(prefix) for prefix in prefixes):
                    func.category = category
                    break

            # Assign priority (0=critical, 1=important, 2=normal, 3=optional)
            if func.name in self.PRIORITY_FUNCTIONS.get(0, []):
                func.priority = 0
            elif func.name in self.PRIORITY_FUNCTIONS.get(1, []):
                func.priority = 1
            elif func.name in self.PRIORITY_FUNCTIONS.get(2, []):
                func.priority = 2
            # Higher priority for NFT/netfilter (this project's focus)
            elif func.category in ['nft', 'netfilter', 'conntrack', 'nat']:
                func.priority = min(func.priority, 1)
            # Keep priority=3 for everything else

    def _print_statistics(self, functions: List[SKBFunction]):
        """Print discovery statistics"""
        print(f"\n{'='*60}")
        print(f"[✓] DISCOVERY COMPLETE: {len(functions)} functions")
        print(f"{'='*60}")

        # By priority
        by_priority = defaultdict(int)
        for f in functions:
            by_priority[f.priority] += 1

        print("\nBy Priority:")
        priority_names = {0: "Critical", 1: "Important", 2: "Normal", 3: "Optional"}
        for priority in sorted(by_priority.keys()):
            print(f"  [{priority}] {priority_names.get(priority, 'Unknown')}: {by_priority[priority]}")

        # By category
        by_category = defaultdict(int)
        for f in functions:
            by_category[f.category] += 1

        print("\nTop Categories:")
        for category, count in sorted(by_category.items(), key=lambda x: -x[1])[:10]:
            print(f"  {category}: {count}")

        # By parameter position
        by_param_pos = defaultdict(int)
        for f in functions:
            by_param_pos[f.param_position] += 1

        print("\nBy Parameter Position:")
        for pos in sorted(by_param_pos.keys()):
            print(f"  Position {pos}: {by_param_pos[pos]}")

        print(f"{'='*60}\n")

    def export_json(self, filepath: str, functions: List[SKBFunction]):
        """Export discovered functions to JSON"""
        data = {
            'metadata': {
                'total': len(functions),
                'timestamp': subprocess.run(['date', '-Iseconds'], capture_output=True, text=True).stdout.strip(),
                'kernel': subprocess.run(['uname', '-r'], capture_output=True, text=True).stdout.strip(),
            },
            'statistics': {
                'by_priority': {},
                'by_category': {},
                'by_param_position': {},
            },
            'functions': []
        }

        # Group statistics
        for func in functions:
            # By priority
            pri_key = str(func.priority)
            if pri_key not in data['statistics']['by_priority']:
                data['statistics']['by_priority'][pri_key] = []
            data['statistics']['by_priority'][pri_key].append(func.name)

            # By category
            if func.category not in data['statistics']['by_category']:
                data['statistics']['by_category'][func.category] = []
            data['statistics']['by_category'][func.category].append(func.name)

            # By param position
            pos_key = str(func.param_position)
            if pos_key not in data['statistics']['by_param_position']:
                data['statistics']['by_param_position'][pos_key] = []
            data['statistics']['by_param_position'][pos_key].append(func.name)

            # Function details
            data['functions'].append(asdict(func))

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[✓] Exported to {filepath}")

    def generate_attach_list(self, functions: List[SKBFunction], output_file: str):
        """Generate a simple list of function names for attaching kprobes"""
        with open(output_file, 'w') as f:
            for func in sorted(functions, key=lambda x: x.name):
                f.write(f"{func.name}\n")
        print(f"[✓] Generated function list: {output_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Enhanced BTF SKB Function Discoverer - Discover ALL kernel functions handling sk_buff',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover critical functions only (NFT + core path)
  %(prog)s --priority 0

  # Discover critical + important (recommended for NFT debugging)
  %(prog)s --priority 1

  # Discover normal set (~200 functions, good balance)
  %(prog)s --priority 2

  # Discover everything (1000+ functions, like pwru)
  %(prog)s --priority 3

  # Filter by category
  %(prog)s --category nft --category netfilter --priority 2
        """
    )

    parser.add_argument('--priority', '-p', type=int, default=1,
                       choices=[0, 1, 2, 3],
                       help='Max priority: 0=critical, 1=important, 2=normal, 3=all (default: 1)')

    parser.add_argument('--category', '-c', action='append',
                       help='Filter by category (can specify multiple). Available: nft, netfilter, ip, tcp, udp, etc.')

    parser.add_argument('--output', '-o', default='discovered_functions.json',
                       help='Output JSON file (default: discovered_functions.json)')

    parser.add_argument('--function-list', '-f',
                       help='Output plain text function list (one per line)')

    parser.add_argument('--show-top', '-t', type=int, default=30,
                       help='Show top N functions in console (default: 30)')

    args = parser.parse_args()

    # Discover
    discoverer = EnhancedBTFDiscoverer()
    functions = discoverer.discover_all(max_priority=args.priority)

    # Filter by category if specified
    if args.category:
        functions = [f for f in functions if f.category in args.category]
        print(f"[*] Filtered to categories: {args.category}")
        print(f"[*] Remaining functions: {len(functions)}")

    if not functions:
        print("[!] No functions found!")
        return 1

    # Export JSON
    discoverer.export_json(args.output, functions)

    # Export function list if requested
    if args.function_list:
        discoverer.generate_attach_list(functions, args.function_list)

    # Show top functions
    print(f"\n{'='*60}")
    print(f"TOP {min(args.show_top, len(functions))} FUNCTIONS")
    print(f"{'='*60}")
    print(f"{'#':<4} {'Pri':<4} {'Pos':<4} {'Category':<12} {'Function Name'}")
    print(f"{'-'*60}")

    for i, func in enumerate(functions[:args.show_top], 1):
        print(f"{i:<4} [{func.priority}]  P{func.param_position}   {func.category:<12} {func.name}")

    if len(functions) > args.show_top:
        print(f"... and {len(functions) - args.show_top} more")

    print(f"\n[✓] Done! Use the JSON file to configure your tracer.")

    return 0


if __name__ == '__main__':
    exit(main())
