#!/usr/bin/env python3
"""
Enhanced BTF SKB Function Discoverer
Automatically discovers and classifies ALL kernel functions with sk_buff parameter
Organized by network stack layers: Device, GRO, Netfilter, IPv4, IPv6, TCP, UDP, Routing, Xmit, SoftIRQ
Similar to pwru/cilium but with comprehensive layer classification
"""

import os
import re
import json
import subprocess
from typing import List, Dict, Set
from dataclasses import dataclass, asdict
from collections import defaultdict

@dataclass
class SKBFunction:
    """Represents a kernel function that handles sk_buff"""
    name: str
    layer: str  # Device, GRO, Netfilter, IPv4, IPv6, TCP, UDP, Routing, Xmit, SoftIRQ, etc.
    category: str  # More specific categorization
    priority: int  # 0=critical, 1=important, 2=optional
    params: List[str] = None
    return_type: str = None

    def __hash__(self):
        return hash(self.name)

    def __post_init__(self):
        if self.params is None:
            self.params = []

class EnhancedSKBDiscoverer:
    """Enhanced discoverer with comprehensive layer classification"""

    # Layer-based classification (matching pwru/cilium approach)
    LAYER_PATTERNS = {
        # Device Layer - packet enters/exits network device
        'Device': [
            'netif_receive_skb', '__netif_receive_skb', 'netif_rx',
            'dev_queue_xmit', '__dev_queue_xmit', 'dev_hard_start_xmit',
            'dev_gro_receive', 'napi_gro_receive',
            'eth_type_trans', 'arp_rcv',
        ],

        # GRO (Generic Receive Offload) Layer
        'GRO': [
            'napi_gro_receive', 'napi_gro_complete', 'napi_gro_flush',
            'dev_gro_receive', 'gro_cells_receive',
            'inet_gro_receive', 'tcp4_gro_receive', 'udp4_gro_receive',
            'tcp6_gro_receive', 'udp6_gro_receive',
        ],

        # Netfilter/NFT Layer - firewall and packet filtering
        'Netfilter': [
            'nf_hook_slow', 'nf_hook', 'NF_HOOK',
            'nft_do_chain', 'nft_immediate_eval', 'nft_payload_eval',
            'nf_conntrack_in', 'nf_conntrack_confirm',
            'ipt_do_table', 'ip6t_do_table',
            'xt_', 'ipt_', 'ip6t_', 'nft_', 'nf_',
        ],

        # IPv4 Layer
        'IPv4': [
            'ip_rcv', 'ip_rcv_core', 'ip_rcv_finish',
            'ip_local_deliver', 'ip_local_deliver_finish',
            'ip_forward', 'ip_forward_finish',
            'ip_output', 'ip_finish_output', 'ip_finish_output2',
            'ip_send_skb', 'ip_push_pending_frames',
            'ip_fragment', 'ip_do_fragment',
            'ip_route_input', 'ip_route_output',
        ],

        # IPv6 Layer
        'IPv6': [
            'ip6_rcv', 'ip6_rcv_finish', 'ipv6_rcv',
            'ip6_input', 'ip6_input_finish',
            'ip6_forward', 'ip6_forward_finish',
            'ip6_output', 'ip6_finish_output', 'ip6_finish_output2',
            'ip6_send_skb', 'ip6_push_pending_frames',
            'ip6_fragment',
        ],

        # TCP Layer
        'TCP': [
            'tcp_v4_rcv', 'tcp_v4_do_rcv', 'tcp_rcv_established',
            'tcp_v6_rcv', 'tcp_v6_do_rcv',
            'tcp_transmit_skb', 'tcp_write_xmit', 'tcp_send_skb',
            'tcp_ack', 'tcp_data_queue', 'tcp_clean_rtx_queue',
            'tcp_fastopen_', 'tcp_syn_', 'tcp_connect',
        ],

        # UDP Layer
        'UDP': [
            'udp_rcv', '__udp4_lib_rcv', 'udp_queue_rcv_skb',
            'udp6_rcv', '__udp6_lib_rcv',
            'udp_send_skb', 'udp_sendmsg', 'udp_sendpage',
        ],

        # Routing Layer
        'Routing': [
            'ip_route_input', 'ip_route_output', 'ip_route_input_slow',
            'fib_lookup', 'fib_validate_source', 'fib_table_lookup',
            'rt_dst_alloc', 'rt_cache_route',
            'ip6_route_input', 'ip6_route_output',
            'ip6_pol_route', 'fib6_lookup',
        ],

        # Xmit (Transmit) Layer
        'Xmit': [
            'dev_queue_xmit', '__dev_queue_xmit', 'dev_hard_start_xmit',
            'sch_direct_xmit', '__qdisc_run',
            'dev_direct_xmit', 'packet_direct_xmit',
            'validate_xmit_skb', '__dev_xmit_skb',
        ],

        # SoftIRQ/NAPI Layer
        'SoftIRQ': [
            'net_rx_action', '__napi_poll', 'napi_poll',
            'process_backlog', 'net_tx_action',
            '__raise_softirq', 'do_softirq',
        ],

        # Bridge Layer
        'Bridge': [
            'br_handle_frame', 'br_forward', 'br_pass_frame_up',
            'br_netif_receive_skb', 'br_dev_xmit',
        ],

        # QoS/QDisc Layer
        'QDisc': [
            'qdisc_', 'sch_', 'pfifo_', 'tbf_', 'htb_',
            '__qdisc_run', 'qdisc_restart',
        ],

        # Tunneling Layer
        'Tunnel': [
            'ip_tunnel_', 'gre_', 'vxlan_', 'geneve_',
            'ipip_', 'ip6_tunnel_', 'sit_',
        ],

        # Socket Layer
        'Socket': [
            'sock_def_readable', 'sock_queue_rcv_skb',
            '__sock_queue_rcv_skb', 'sk_receive_skb',
            'sock_wfree', 'sock_rfree',
        ],
    }

    # Critical functions (always trace these)
    CRITICAL_FUNCTIONS = [
        # Core packet receive path
        '__netif_receive_skb_core',
        'netif_receive_skb',
        'netif_rx',

        # IP layer critical
        'ip_rcv',
        'ip_local_deliver',
        'ip_forward',
        'ip_output',
        'ip6_rcv',
        'ip6_input',

        # Netfilter critical
        'nf_hook_slow',
        'nft_do_chain',
        'nft_immediate_eval',

        # Transport critical
        'tcp_v4_rcv',
        'tcp_rcv_established',
        'udp_rcv',

        # Xmit critical
        'dev_queue_xmit',
        '__dev_queue_xmit',
        'dev_hard_start_xmit',
    ]

    def __init__(self):
        self.functions: Set[SKBFunction] = set()
        self.layer_stats = defaultdict(int)

    def discover_all(self) -> List[SKBFunction]:
        """Discover ALL SKB functions using multiple methods"""
        print("[*] Starting comprehensive SKB function discovery...")
        print("[*] This may take a minute...\n")

        # Method 1: BTF-based discovery (most accurate)
        self._discover_via_btf()

        # Method 2: kallsyms heuristic (broader coverage)
        self._discover_via_kallsyms()

        # Classify all discovered functions
        self._classify_all_functions()

        # Generate statistics
        self._print_statistics()

        return sorted(self.functions, key=lambda x: (x.priority, x.layer, x.name))

    def _discover_via_btf(self):
        """Discover using BTF (most accurate)"""
        print("[*] Method 1: BTF-based discovery...")

        try:
            result = subprocess.run(
                ['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                self._parse_btf_output(result.stdout)
                print(f"    ✓ Found {len(self.functions)} functions via BTF")
            else:
                print(f"    ! BTF dump failed: {result.stderr[:100]}")

        except FileNotFoundError:
            print("    ! bpftool not found, skipping BTF discovery")
        except subprocess.TimeoutExpired:
            print("    ! BTF dump timeout, skipping")
        except Exception as e:
            print(f"    ! BTF error: {e}")

    def _parse_btf_output(self, btf_output: str):
        """Parse BTF output for sk_buff functions"""
        # Pattern: any function with 'struct sk_buff *' parameter
        pattern = r'(\w+)\s*\([^)]*struct\s+sk_buff\s*\*'

        for line in btf_output.split('\n'):
            match = re.search(pattern, line)
            if match:
                func_name = match.group(1)

                # Skip internal/compiler symbols
                if func_name.startswith('__pfx_') or func_name.startswith('__SCT__'):
                    continue
                if func_name.startswith('__kstrtab') or func_name.startswith('__ksymtab'):
                    continue
                if func_name.startswith('__crc_') or func_name.startswith('__BTF_ID'):
                    continue

                func = SKBFunction(
                    name=func_name,
                    layer='Unknown',
                    category='unknown',
                    priority=2,
                    params=['struct sk_buff *skb']
                )
                self.functions.add(func)

    def _discover_via_kallsyms(self):
        """Discover via kallsyms using heuristics"""
        print("[*] Method 2: kallsyms heuristic discovery...")

        initial_count = len(self.functions)
        skb_keywords = ['_skb_', '_rcv', '_xmit', '_forward', 'netif_', 'nf_', 'nft_',
                       'tcp_', 'udp_', 'ip_', 'ip6_', 'dev_', 'gro_', 'napi_']

        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue

                    symbol_type = parts[1]
                    func_name = parts[2]

                    # Only T (text) symbols (actual functions)
                    if symbol_type not in ['T', 't']:
                        continue

                    # Skip compiler/internal symbols
                    if func_name.startswith('__pfx_') or func_name.startswith('__SCT__'):
                        continue
                    if any(x in func_name for x in ['__kstrtab', '__ksymtab', '__crc_', '__BTF_ID']):
                        continue

                    # Check if likely SKB function
                    if any(kw in func_name for kw in skb_keywords):
                        func = SKBFunction(
                            name=func_name,
                            layer='Unknown',
                            category='unknown',
                            priority=2,
                            params=['struct sk_buff *skb']
                        )
                        self.functions.add(func)

            added = len(self.functions) - initial_count
            print(f"    ✓ Added {added} additional functions via kallsyms")

        except Exception as e:
            print(f"    ! kallsyms error: {e}")

    def _classify_all_functions(self):
        """Classify all functions by layer and category"""
        print("\n[*] Classifying functions by network stack layer...")

        for func in self.functions:
            # Check each layer's patterns
            for layer, patterns in self.LAYER_PATTERNS.items():
                matched = False

                for pattern in patterns:
                    if callable(pattern):
                        if pattern(func.name):
                            func.layer = layer
                            matched = True
                            break
                    elif func.name.startswith(pattern) or pattern in func.name:
                        func.layer = layer
                        matched = True
                        break

                if matched:
                    break

            # Set category (more specific than layer)
            func.category = self._determine_category(func.name)

            # Set priority
            if func.name in self.CRITICAL_FUNCTIONS:
                func.priority = 0
            elif func.layer in ['Netfilter', 'IPv4', 'IPv6', 'TCP', 'UDP']:
                func.priority = 1
            elif func.layer != 'Unknown':
                func.priority = 2
            else:
                func.priority = 3

            # Update stats
            self.layer_stats[func.layer] += 1

    def _determine_category(self, func_name: str) -> str:
        """Determine specific category"""
        categories = {
            'nft': ['nft_', 'nf_tables_'],
            'netfilter': ['nf_', 'xt_', 'ipt_', 'ip6t_'],
            'conntrack': ['nf_conntrack_', 'ct_'],
            'tcp': ['tcp_', '__tcp_'],
            'udp': ['udp_', '__udp_'],
            'ip': ['ip_', '__ip_', 'ipv4_'],
            'ipv6': ['ip6_', 'ipv6_'],
            'routing': ['fib_', 'rt_', 'route_'],
            'device': ['dev_', 'netdev_'],
            'gro': ['gro_', 'napi_gro_'],
            'qdisc': ['qdisc_', 'sch_'],
            'bridge': ['br_'],
            'tunnel': ['tunnel_', 'gre_', 'vxlan_'],
            'socket': ['sock_', 'sk_'],
        }

        for cat, prefixes in categories.items():
            if any(func_name.startswith(p) for p in prefixes):
                return cat

        return 'general'

    def _print_statistics(self):
        """Print discovery statistics"""
        print("\n" + "="*70)
        print("DISCOVERY STATISTICS")
        print("="*70)
        print(f"Total functions discovered: {len(self.functions)}")
        print(f"\nBy Priority:")
        print(f"  Critical (0):  {sum(1 for f in self.functions if f.priority == 0)}")
        print(f"  Important (1): {sum(1 for f in self.functions if f.priority == 1)}")
        print(f"  Optional (2):  {sum(1 for f in self.functions if f.priority == 2)}")
        print(f"  Unknown (3):   {sum(1 for f in self.functions if f.priority == 3)}")

        print(f"\nBy Layer:")
        for layer in sorted(self.layer_stats.keys(), key=lambda x: self.layer_stats[x], reverse=True):
            count = self.layer_stats[layer]
            pct = (count / len(self.functions)) * 100
            print(f"  {layer:15s}: {count:4d} ({pct:5.1f}%)")

    def export_json(self, filepath: str):
        """Export to JSON with layer organization"""
        data = {
            'total': len(self.functions),
            'by_layer': {},
            'by_category': {},
            'by_priority': {},
            'functions': []
        }

        # Organize by layer
        for func in self.functions:
            if func.layer not in data['by_layer']:
                data['by_layer'][func.layer] = []
            data['by_layer'][func.layer].append(func.name)

            if func.category not in data['by_category']:
                data['by_category'][func.category] = []
            data['by_category'][func.category].append(func.name)

            pri = str(func.priority)
            if pri not in data['by_priority']:
                data['by_priority'][pri] = []
            data['by_priority'][pri].append(func.name)

            data['functions'].append(asdict(func))

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[✓] Exported to {filepath}")

    def get_by_layers(self, layers: List[str]) -> List[SKBFunction]:
        """Get functions from specific layers"""
        return [f for f in self.functions if f.layer in layers]

    def get_by_priority(self, max_priority: int) -> List[SKBFunction]:
        """Get functions up to priority level"""
        return [f for f in self.functions if f.priority <= max_priority]

    def generate_trace_config(self, filepath: str, max_functions: int = 100):
        """Generate trace configuration for top functions"""
        # Get top functions by priority
        top_funcs = sorted(self.functions, key=lambda x: (x.priority, x.layer, x.name))[:max_functions]

        config = {
            'version': '1.0',
            'description': 'Auto-generated multi-function trace configuration',
            'total_functions': len(top_funcs),
            'functions': []
        }

        for func in top_funcs:
            config['functions'].append({
                'name': func.name,
                'layer': func.layer,
                'category': func.category,
                'priority': func.priority,
                'enabled': func.priority <= 1  # Enable critical and important by default
            })

        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"[✓] Generated trace config: {filepath}")

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Enhanced SKB Function Discoverer with Layer Classification'
    )
    parser.add_argument('--output', '-o', default='enhanced_skb_functions.json',
                       help='Output JSON file')
    parser.add_argument('--config', '-c', default='trace_config.json',
                       help='Trace configuration output')
    parser.add_argument('--max-trace', '-m', type=int, default=100,
                       help='Max functions in trace config')
    parser.add_argument('--layers', '-l', action='append',
                       help='Filter by layers (can specify multiple)')
    parser.add_argument('--priority', '-p', type=int, default=3,
                       help='Max priority (0=critical, 1=important, 2=optional, 3=all)')

    args = parser.parse_args()

    # Discover
    discoverer = EnhancedSKBDiscoverer()
    functions = discoverer.discover_all()

    # Filter by layers if specified
    if args.layers:
        functions = discoverer.get_by_layers(args.layers)
        print(f"\n[*] Filtered to layers: {args.layers}")

    # Filter by priority
    functions = discoverer.get_by_priority(args.priority)
    print(f"[*] Filtered to priority <= {args.priority}: {len(functions)} functions")

    # Export
    discoverer.export_json(args.output)
    discoverer.generate_trace_config(args.config, args.max_trace)

    # Print sample functions
    print("\n" + "="*70)
    print("SAMPLE FUNCTIONS BY LAYER")
    print("="*70)

    by_layer = defaultdict(list)
    for func in functions:
        by_layer[func.layer].append(func)

    for layer in sorted(by_layer.keys()):
        funcs = by_layer[layer][:5]  # Show 5 per layer
        print(f"\n{layer}:")
        for f in funcs:
            print(f"  [{f.priority}] {f.name} ({f.category})")

if __name__ == '__main__':
    main()
