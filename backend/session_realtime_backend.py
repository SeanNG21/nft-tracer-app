#!/usr/bin/env python3
"""
Session Realtime Backend - Identical logic to Global Realtime
Used by SessionStatsTracker for full mode session realtime stats
Copy y nguyên từ realtime_extension.py để tách riêng nhưng logic giống nhau
"""

import time
import socket
import struct
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict, field

# ============================================
# CONSTANTS - Copy từ realtime_extension.py
# ============================================

VERDICT_MAP = {
    0: "ACCEPT",
    1: "DROP",
    2: "STOLEN",
    3: "QUEUE",
    4: "REPEAT",
    5: "STOP",
    10: "DROP",
    11: "STOLEN",
    12: "QUEUE",
    13: "REPEAT",
    14: "STOP",
    255: "UNKNOWN"
}

# Function → Pipeline Layer mapping (aligned with full trace mode)
FUNCTION_TO_LAYER = {
    # === INBOUND PIPELINE ===
    # NIC Layer
    'napi_gro_receive': 'NIC',
    'netif_receive_skb': 'NIC',
    'netif_receive_skb_list_internal': 'NIC',

    # Driver (NAPI)
    'napi_poll': 'Driver (NAPI)',
    'net_rx_action': 'Driver (NAPI)',
    'process_backlog': 'Driver (NAPI)',

    # GRO
    'gro_normal_list': 'GRO',
    'dev_gro_receive': 'GRO',
    'skb_gro_receive': 'GRO',

    # TC Ingress
    'tcf_classify': 'TC Ingress',
    'ingress_redirect': 'TC Ingress',
    'dev_queue_xmit_nit': 'TC Ingress',

    # Netfilter (will be refined by hook value)
    'nf_hook_slow': 'Netfilter',
    'nf_hook_thresh': 'Netfilter',
    'nf_reinject': 'Netfilter',
    'nft_do_chain': 'Netfilter',
    'nft_immediate_eval': 'Netfilter',

    # Conntrack
    'nf_conntrack_in': 'Conntrack',
    'nf_ct_invert_tuple': 'Conntrack',
    'nf_confirm': 'Conntrack',

    # NAT
    'nf_nat_ipv4_pre_routing': 'NAT PREROUTING',
    'nf_nat_ipv4_fn': 'NAT',

    # Routing Decision
    'ip_route_input_slow': 'Routing Decision',
    'fib_validate_source': 'Routing Decision',
    'ip_route_output_key_hash': 'Routing',

    # Local Delivery
    'ip_local_deliver': 'Local Delivery',
    'ip_local_deliver_finish': 'Local Delivery',

    # Netfilter INPUT
    'nf_queue': 'Netfilter',

    # TCP/UDP (Inbound)
    'tcp_v4_rcv': 'TCP/UDP',
    'tcp_v4_do_rcv': 'TCP/UDP',
    'tcp_rcv_established': 'TCP/UDP',
    'udp_rcv': 'TCP/UDP',
    'udp_unicast_rcv_skb': 'TCP/UDP',

    # Socket
    'sk_filter_trim_cap': 'Socket',

    # Forward
    'ip_forward': 'Forward',
    'ip_forward_finish': 'Forward',

    # === OUTBOUND PIPELINE ===
    # Application
    'tcp_sendmsg': 'Application',
    'udp_sendmsg': 'Application',

    # TCP/UDP Output
    'tcp_write_xmit': 'TCP/UDP Output',
    'tcp_transmit_skb': 'TCP/UDP Output',
    'udp_send_skb': 'TCP/UDP Output',

    # Routing Lookup (outbound)
    'ip_route_output_flow': 'Routing Lookup',

    # NAT (outbound)
    'nf_nat_ipv4_out': 'NAT',
    'nf_nat_ipv4_local_fn': 'NAT',

    # TC Egress
    'sch_direct_xmit': 'TC Egress',

    # Driver TX / NIC TX
    'dev_queue_xmit': 'Driver TX',
    '__dev_queue_xmit': 'Driver TX',
    'dev_hard_start_xmit': 'Driver TX',
}

def refine_layer_by_hook(func_name: str, base_layer: str, hook: int) -> str:
    """
    Refine generic layer name based on netfilter hook value.
    Hook values: 0=PREROUTING, 1=INPUT, 2=FORWARD, 3=OUTPUT, 4=POSTROUTING
    """
    # nf_hook_slow and similar functions need to be refined by hook
    if base_layer == 'Netfilter' or 'nf_hook' in func_name or 'nf_queue' in func_name:
        hook_map = {
            0: 'Netfilter PREROUTING',
            1: 'Netfilter INPUT',
            2: 'Netfilter FORWARD',
            3: 'Netfilter OUTPUT',
            4: 'Netfilter POSTROUTING',
        }
        return hook_map.get(hook, base_layer)

    # NAT functions need hook context
    if 'NAT' in base_layer or 'nf_nat' in func_name:
        if hook == 0:
            return 'NAT PREROUTING'
        elif hook in [3, 4]:
            return 'NAT'  # POSTROUTING or OUTPUT - both are NAT stage
        return 'NAT'

    # Routing functions
    if 'Routing' in base_layer:
        if 'input' in func_name:
            return 'Routing Decision'
        elif 'output' in func_name:
            return 'Routing Lookup'
        return base_layer

    return base_layer

def detect_packet_direction_new(func_name: str, layer: str, hook: int) -> str:
    """
    Detect packet direction (Inbound or Outbound) based on function name, layer, and hook.

    Hook-based detection (most reliable):
    - PRE_ROUTING (0), LOCAL_IN (1), FORWARD (2) → Inbound
    - LOCAL_OUT (3), POST_ROUTING (4) → Outbound
    """
    # Hook-based detection (most reliable)
    if hook in [0, 1, 2]:  # PREROUTING, INPUT, FORWARD
        return 'Inbound'
    elif hook in [3, 4]:  # OUTPUT, POSTROUTING
        return 'Outbound'

    # Layer-based detection
    inbound_layers = [
        'NIC', 'Driver (NAPI)', 'GRO', 'TC Ingress',
        'Netfilter PREROUTING', 'Netfilter INPUT', 'Netfilter FORWARD',
        'Conntrack', 'NAT PREROUTING', 'Routing Decision',
        'Local Delivery', 'Socket'
    ]
    outbound_layers = [
        'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
        'Routing Lookup', 'NAT', 'TC Egress', 'Driver TX', 'NIC'
    ]

    if layer in inbound_layers:
        return 'Inbound'
    if layer in outbound_layers:
        return 'Outbound'

    # Function name heuristics
    func_lower = func_name.lower()
    inbound_keywords = ['rcv', 'receive', 'input', 'ingress', 'deliver']
    outbound_keywords = ['sendmsg', 'xmit', 'transmit', 'output', 'egress']

    for keyword in inbound_keywords:
        if keyword in func_lower:
            return 'Inbound'
    for keyword in outbound_keywords:
        if keyword in func_lower:
            return 'Outbound'

    # TCP/UDP and Forward are special
    if layer in ['TCP/UDP', 'Forward']:
        if 'sendmsg' in func_lower:
            return 'Outbound'
        return 'Inbound'

    # Default to Inbound
    return 'Inbound'

def format_ip(ip_int: int) -> str:
    """Format IP address from integer"""
    if ip_int == 0:
        return "0.0.0.0"
    try:
        return socket.inet_ntoa(struct.pack('<I', ip_int))
    except:
        return "0.0.0.0"

# ============================================
# DATA STRUCTURES - Copy từ realtime_extension.py
# ============================================

@dataclass
class NodeStats:
    """Statistics for a pipeline node (e.g., NIC, Netfilter PREROUTING, etc.)"""
    count: int = 0
    unique_skbs: set = field(default_factory=set)
    latencies_us: List[float] = field(default_factory=list)  # microseconds
    function_calls: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    verdict_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_count: int = 0
    drop_count: int = 0
    truncated_count: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    in_flight_packets: set = field(default_factory=set)  # packets currently on this node

    # For packet rate calculation
    previous_count: int = 0
    previous_ts: Optional[float] = None

    def add_event(self, skb_addr: str, latency_us: float = 0, function: str = None,
                  verdict: str = None, error: bool = False):
        """Add an event to this node's statistics

        Note: Verdict should only be passed if already filtered by caller
        (trace_type == "chain_exit" for NFT events, or deduplicated for function events)
        """
        self.count += 1
        # Only track unique SKBs if skb_addr is valid (not empty/None)
        if skb_addr and skb_addr != '':
            self.unique_skbs.add(skb_addr)
        if latency_us > 0:
            self.latencies_us.append(latency_us)
        if function:
            self.function_calls[function] += 1

        # Count verdict if provided (caller must have filtered already)
        if verdict and verdict != 'UNKNOWN':
            self.verdict_breakdown[verdict] += 1
            if verdict == 'DROP':
                self.drop_count += 1

        if error:
            self.error_count += 1

    def get_latency_percentiles(self) -> Dict[str, float]:
        """Calculate latency percentiles"""
        if not self.latencies_us:
            return {'p50': 0, 'p90': 0, 'p99': 0, 'avg': 0}

        import numpy as np
        latencies = np.array(self.latencies_us)
        return {
            'p50': float(np.percentile(latencies, 50)),
            'p90': float(np.percentile(latencies, 90)),
            'p99': float(np.percentile(latencies, 99)),
            'avg': float(np.mean(latencies))
        }

    def get_top_functions(self, limit: int = 3) -> List[Dict]:
        """Get top N functions with count and percentage"""
        if not self.function_calls:
            return []

        total = sum(self.function_calls.values())
        top_funcs = sorted(self.function_calls.items(), key=lambda x: x[1], reverse=True)[:limit]

        return [
            {
                'name': func,
                'count': count,
                'pct': round((count / total) * 100, 1) if total > 0 else 0
            }
            for func, count in top_funcs
        ]

    def calculate_packet_rate(self, current_ts: float) -> float:
        """Calculate packets/sec based on count delta and time delta"""
        if self.previous_ts is None:
            # First calculation - initialize
            self.previous_count = self.count
            self.previous_ts = current_ts
            return 0.0

        time_delta = current_ts - self.previous_ts
        if time_delta <= 0:
            return 0.0

        count_delta = self.count - self.previous_count
        rate = count_delta / time_delta

        # Update for next calculation
        self.previous_count = self.count
        self.previous_ts = current_ts

        return round(rate, 1)

    def to_dict(self, current_ts: Optional[float] = None) -> Dict:
        """Convert to dict for JSON serialization"""
        latency = self.get_latency_percentiles()
        verdict_dict = dict(self.verdict_breakdown) if self.verdict_breakdown else None

        # Calculate packet rate if timestamp provided
        packet_rate = 0.0
        if current_ts is not None:
            packet_rate = self.calculate_packet_rate(current_ts)

        return {
            'count': self.count,
            'unique_packets': len(self.unique_skbs),
            'latency': latency,
            'top_functions': self.get_top_functions(3),
            'verdict': verdict_dict,
            'errors': self.error_count,
            'drops': self.drop_count,
            'truncated': self.truncated_count,
            'in_flight': len(self.in_flight_packets),
            'packet_rate': packet_rate  # packets/sec
        }

@dataclass
class EdgeStats:
    """Statistics for traffic flow between two nodes"""
    from_node: str
    to_node: str
    count: int = 0

    def to_dict(self) -> Dict:
        return {
            'from': self.from_node,
            'to': self.to_node,
            'count': self.count
        }

@dataclass
class PipelineStats:
    """Statistics for packet pipelines (Inbound, Outbound, Local Delivery, Forward)"""
    unique_skbs: set = field(default_factory=set)  # all SKBs that ever entered this pipeline
    active_nodes: set = field(default_factory=set)  # nodes that belong to this pipeline

    def to_dict(self, nodes_dict: Dict[str, NodeStats]) -> Dict:
        """
        Calculate statistics from node-level data.

        - started: Total unique SKBs that entered this pipeline (ever)
        - in_flight: SKBs currently on nodes of this pipeline (real-time)
        - completed: SKBs that entered but left this pipeline (started - in_flight)
        """
        started = len(self.unique_skbs)
        in_flight = self.calculate_in_flight_from_nodes(nodes_dict)
        completed = started - in_flight

        return {
            'started': started,
            'completed': completed,
            'in_progress': in_flight,  # renamed from in_progress to match
            'calculated_in_flight': in_flight
        }

    def calculate_in_flight_from_nodes(self, nodes_dict: Dict[str, NodeStats]) -> int:
        """Calculate total in-flight packets from nodes belonging to this pipeline"""
        total = 0
        for node_name in self.active_nodes:
            if node_name in nodes_dict:
                total += len(nodes_dict[node_name].in_flight_packets)
        return total

# ============================================
# SESSION REALTIME STATS - Copy y nguyên từ RealtimeStats
# ============================================

class SessionRealtimeStats:
    """
    Session Realtime Statistics Backend
    Copy y nguyên logic từ RealtimeStats để có cách tính toán giống nhau
    """

    def __init__(self):
        self.skb_tracking: Dict[str, Dict] = {}
        self.total_packets = 0
        self.start_time = time.time()
        self._lock = threading.Lock()

        # FINAL VERDICT TRACKING - Track latest verdict per packet for accurate counting
        self.packet_final_verdicts: Dict[str, str] = {}  # skb_addr -> final_verdict_name

        # Pipeline stats for Inbound/Outbound visualization
        self.stats_by_direction_layer = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int)
        }

        # Node-based statistics with detailed metrics
        self.nodes: Dict[str, NodeStats] = {}  # node_name -> NodeStats
        self.edges: Dict[tuple, EdgeStats] = {}  # (from, to) -> EdgeStats
        self.skb_paths: Dict[str, List[str]] = {}  # skb_addr -> [node1, node2, ...]

        # Pipeline completion tracking with node definitions (ORDER MATTERS for display)
        self.pipeline_order = ['Inbound', 'Outbound', 'Local Delivery', 'Forward']
        self.pipelines: Dict[str, PipelineStats] = {
            'Inbound': PipelineStats(active_nodes={
                'NIC', 'Driver (NAPI)', 'GRO', 'TC Ingress',
                'Netfilter PREROUTING', 'Conntrack', 'NAT PREROUTING', 'Routing Decision'
            }),
            'Outbound': PipelineStats(active_nodes={
                'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
                'Routing Lookup', 'NAT POSTROUTING', 'TC Egress', 'Driver TX'
            }),
            'Local Delivery': PipelineStats(active_nodes={
                'Netfilter INPUT', 'TCP/UDP', 'Socket'
            }),
            'Forward': PipelineStats(active_nodes={
                'Netfilter FORWARD', 'Netfilter POSTROUTING', 'NIC TX'
            })
        }

    def get_node(self, node_name: str) -> NodeStats:
        """Get or create a node's statistics"""
        if node_name not in self.nodes:
            self.nodes[node_name] = NodeStats()
        return self.nodes[node_name]

    def add_edge(self, from_node: str, to_node: str):
        """Track an edge (transition) between two nodes"""
        edge_key = (from_node, to_node)
        if edge_key not in self.edges:
            self.edges[edge_key] = EdgeStats(from_node=from_node, to_node=to_node)
        self.edges[edge_key].count += 1

    def _detect_direction(self, func_name: str, hook: int) -> str:
        """Detect packet direction (Inbound or Outbound) using function and hook"""
        if func_name in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[func_name]
            refined_layer = refine_layer_by_hook(func_name, base_layer, hook)
            return detect_packet_direction_new(func_name, refined_layer, hook)

        # Hook-based fallback
        if hook in [0, 1, 2]:  # PREROUTING, INPUT, FORWARD
            return 'Inbound'
        elif hook in [3, 4]:  # OUTPUT, POSTROUTING
            return 'Outbound'

        # Default to Inbound
        return 'Inbound'

    def _map_to_pipeline_layer(self, func_name: str, hook: int) -> str:
        """Map function to pipeline layer name using FUNCTION_TO_LAYER"""
        # First priority: Use FUNCTION_TO_LAYER mapping
        if func_name in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[func_name]
            # Refine by hook if needed (e.g., Netfilter → Netfilter PREROUTING)
            refined_layer = refine_layer_by_hook(func_name, base_layer, hook)
            return refined_layer

        # Fallback: Function-based heuristics
        func_lower = func_name.lower()
        if 'napi' in func_lower:
            return 'Driver (NAPI)'
        elif 'gro' in func_lower:
            return 'GRO'
        elif 'tc' in func_lower:
            return 'TC Ingress' if 'ingress' in func_lower else 'TC Egress'
        elif 'conntrack' in func_lower:
            return 'Conntrack'
        elif 'nat' in func_lower:
            if hook == 0:
                return 'NAT PREROUTING'
            return 'NAT'
        elif 'route' in func_lower:
            if 'input' in func_lower:
                return 'Routing Decision'
            elif 'output' in func_lower:
                return 'Routing Lookup'
            return 'Routing'
        elif 'local_deliver' in func_lower:
            return 'Local Delivery'
        elif 'forward' in func_lower:
            return 'Forward'
        elif 'tcp' in func_lower or 'udp' in func_lower:
            if 'sendmsg' in func_lower or 'write' in func_lower or 'xmit' in func_lower:
                return 'TCP/UDP Output'
            return 'TCP/UDP'
        elif 'sendmsg' in func_lower:
            return 'Application'
        elif 'nf_hook' in func_lower or 'nft_' in func_lower or 'netfilter' in func_lower:
            return refine_layer_by_hook(func_name, 'Netfilter', hook)

        return 'Unknown'

    def _track_pipeline_membership(self, skb_addr: str, node_name: str):
        """
        Track which pipelines this SKB has entered.
        SIMPLIFIED LOGIC: Just track unique SKBs per pipeline.

        Rules:
        - started: Count of unique SKBs that entered ANY node of this pipeline
        - in_flight: Real-time count from nodes (calculated from node.in_flight_packets)
        - completed: started - in_flight (packets that left the pipeline)
        """
        # Check which pipelines this node belongs to
        for pipeline_name, pipeline_stats in self.pipelines.items():
            if node_name in pipeline_stats.active_nodes:
                # Add this SKB to the pipeline's unique set
                pipeline_stats.unique_skbs.add(skb_addr)

    def process_event(self, event: Dict):
        """Process a single packet event and update statistics

        Event structure:
        {
            'func_name': str,
            'hook': int (0-4, 255=unknown),
            'verdict': int (0=ACCEPT, 1=DROP, etc., 255=UNKNOWN),
            'skb_addr': str (hex),
            'trace_type': str (optional, 'chain_exit'/'rule_eval'/'hook_exit'),
            'timestamp': float,
            ...
        }
        """
        with self._lock:
            func_name = event.get('func_name', '')
            hook = event.get('hook', 255)
            verdict = event.get('verdict', 255)
            verdict_name = VERDICT_MAP.get(verdict, 'UNKNOWN')
            skb_addr = event.get('skb_addr', '')
            trace_type = event.get('trace_type', None)
            timestamp = event.get('timestamp', time.time())

            if not func_name:
                return

            # Detect direction and map to pipeline layer
            direction = self._detect_direction(func_name, hook)
            pipeline_layer = self._map_to_pipeline_layer(func_name, hook)

            self.stats_by_direction_layer[direction][pipeline_layer] += 1

            # Get or create node
            node = self.get_node(pipeline_layer)

            # Calculate latency in microseconds
            latency_us = 0.0
            if skb_addr and skb_addr in self.skb_tracking:
                first_ts = self.skb_tracking[skb_addr]['first_ts']
                latency_us = (timestamp - first_ts) * 1_000_000  # convert to microseconds

            # VERDICT FILTERING LOGIC - Giống y nguyên RealtimeStats
            # Support both NFT events and function trace events:
            # 1. If trace_type exists (NFT events): ONLY count from "chain_exit" events
            # 2. If no trace_type (function trace events): Count from netfilter functions with deduplication
            verdict_to_count = None
            if verdict_name and verdict_name != 'UNKNOWN':
                if trace_type:
                    # Case 1: NFT events with trace_type (session events from nft_tracer.bpf.c)
                    # ONLY count chain_exit to avoid double-counting from rule_eval/hook_exit
                    if trace_type == 'chain_exit':
                        verdict_to_count = verdict_name
                else:
                    # Case 2: Function trace events without trace_type (from full_tracer.bpf.c)
                    # Count from netfilter functions with per-packet deduplication
                    is_netfilter = any(kw in func_name.lower() for kw in ['nf_', 'nft_', 'netfilter'])
                    if is_netfilter and skb_addr:
                        # Initialize counted_verdicts set for this node if not exists
                        if not hasattr(node, 'counted_verdicts'):
                            node.counted_verdicts = set()

                        # Deduplicate by (skb_addr, verdict) - count each verdict once per packet
                        verdict_key = (skb_addr, verdict_name)
                        if verdict_key not in node.counted_verdicts:
                            verdict_to_count = verdict_name
                            node.counted_verdicts.add(verdict_key)

                            # Cleanup to prevent memory bloat
                            if len(node.counted_verdicts) > 10000:
                                old_entries = list(node.counted_verdicts)[:2000]
                                for entry in old_entries:
                                    node.counted_verdicts.discard(entry)

            # Add event to node (only pass filtered verdict)
            node.add_event(
                skb_addr=skb_addr,
                latency_us=latency_us,
                function=func_name,
                verdict=verdict_to_count,
                error=False
            )

            # FINAL VERDICT TRACKING - Track latest verdict per packet
            # This will be used for accurate total_verdicts counting (count unique packets by final verdict)
            if verdict_to_count and skb_addr:
                # Update latest verdict for this packet
                # DROP verdicts are final, ACCEPT might be overridden by later DROP
                current_verdict = self.packet_final_verdicts.get(skb_addr)
                if current_verdict != 'DROP':  # Don't override DROP verdict
                    self.packet_final_verdicts[skb_addr] = verdict_to_count

            # Track edges (transitions between nodes) and in-flight packets
            if skb_addr:
                if skb_addr not in self.skb_paths:
                    self.skb_paths[skb_addr] = []

                # If there's a previous node, create an edge and update in-flight tracking
                if self.skb_paths[skb_addr]:
                    prev_node = self.skb_paths[skb_addr][-1]
                    if prev_node != pipeline_layer:  # Avoid self-loops
                        self.add_edge(prev_node, pipeline_layer)
                        # Remove from previous node's in-flight set
                        prev_node_stats = self.get_node(prev_node)
                        prev_node_stats.in_flight_packets.discard(skb_addr)

                # Add packet to current node's in-flight set
                node.in_flight_packets.add(skb_addr)

                # Add current node to path
                self.skb_paths[skb_addr].append(pipeline_layer)

                # Track pipeline membership (which pipelines this SKB has entered)
                self._track_pipeline_membership(skb_addr, pipeline_layer)

                # Track SKB first seen time
                if skb_addr not in self.skb_tracking:
                    self.skb_tracking[skb_addr] = {
                        'first_ts': timestamp,
                    }

                # Limit path history and cleanup old SKB tracking
                if len(self.skb_paths) > 10000:
                    oldest_keys = list(self.skb_paths.keys())[:1000]
                    for key in oldest_keys:
                        # Cleanup in-flight packets for stale SKBs
                        for node_stats in self.nodes.values():
                            node_stats.in_flight_packets.discard(key)
                        del self.skb_paths[key]

                if len(self.skb_tracking) > 10000:
                    oldest_keys = list(self.skb_tracking.keys())[:1000]
                    for key in oldest_keys:
                        del self.skb_tracking[key]
                        # Also cleanup final verdict tracking
                        if key in self.packet_final_verdicts:
                            del self.packet_final_verdicts[key]

            # Cleanup packet_final_verdicts to prevent memory bloat
            if len(self.packet_final_verdicts) > 10000:
                oldest_keys = list(self.packet_final_verdicts.keys())[:2000]
                for key in oldest_keys:
                    del self.packet_final_verdicts[key]

            self.total_packets += 1

    def get_summary(self) -> Dict:
        """Get current statistics summary - giống y nguyên RealtimeStats.get_summary()"""
        with self._lock:
            uptime = time.time() - self.start_time
            current_ts = time.time()

            # Serialize nodes with packet rate calculation
            nodes_data = {}
            for node_name, node_stats in self.nodes.items():
                nodes_data[node_name] = node_stats.to_dict(current_ts)

            # Serialize edges
            edges_data = []
            for edge_stats in self.edges.values():
                edges_data.append(edge_stats.to_dict())

            # Pipeline statistics (ORDERED for consistent display)
            pipelines_data = []
            for pipeline_name in self.pipeline_order:
                if pipeline_name in self.pipelines:
                    pipeline_stats = self.pipelines[pipeline_name]
                    pipeline_dict = pipeline_stats.to_dict(self.nodes)
                    pipeline_dict['name'] = pipeline_name
                    pipelines_data.append(pipeline_dict)

            # Calculate total verdict statistics from FINAL VERDICTS per packet
            # Count unique packets by their final verdict (not all intermediate verdicts)
            total_verdicts = defaultdict(int)
            for verdict in self.packet_final_verdicts.values():
                total_verdicts[verdict] += 1

            # Top Latency Contributors
            latency_ranking = []
            total_latency = 0
            for node_name, node_stats in self.nodes.items():
                if node_stats.latencies_us:
                    import numpy as np
                    avg_latency = float(np.mean(node_stats.latencies_us))
                    latency_ranking.append({
                        'node': node_name,
                        'avg_latency_us': round(avg_latency, 1),
                        'count': len(node_stats.latencies_us)
                    })
                    total_latency += avg_latency

            # Sort by latency descending and calculate percentage
            latency_ranking.sort(key=lambda x: x['avg_latency_us'], reverse=True)
            for item in latency_ranking[:10]:  # Top 10
                if total_latency > 0:
                    item['percentage'] = round((item['avg_latency_us'] / total_latency) * 100, 1)
                else:
                    item['percentage'] = 0

            return {
                'total_packets': self.total_packets,
                'uptime_seconds': round(uptime, 2),
                'packets_per_second': round(self.total_packets / max(uptime, 1), 2),
                # Pipeline stats for Inbound/Outbound visualization
                'stats': {
                    'Inbound': dict(self.stats_by_direction_layer['Inbound']),
                    'Outbound': dict(self.stats_by_direction_layer['Outbound'])
                },
                # Detailed node and edge statistics
                'nodes': nodes_data,
                'edges': edges_data,
                # Pipeline completion statistics
                'pipelines': pipelines_data,
                # Total verdict statistics
                'total_verdicts': dict(total_verdicts),
                # Top latency contributors for hotspot analysis
                'top_latency': latency_ranking[:10],
                # Mode field to tell frontend this is full mode
                'mode': 'full'
            }

    def reset(self):
        """Reset all statistics"""
        with self._lock:
            self.skb_tracking.clear()
            self.total_packets = 0
            self.start_time = time.time()
            # Reset final verdict tracking
            self.packet_final_verdicts.clear()
            self.stats_by_direction_layer = {
                'Inbound': defaultdict(int),
                'Outbound': defaultdict(int)
            }
            self.nodes.clear()
            self.edges.clear()
            self.skb_paths.clear()
            # Reset pipeline tracking
            self.pipelines = {
                'Inbound': PipelineStats(active_nodes={
                    'NIC', 'Driver (NAPI)', 'GRO', 'TC Ingress',
                    'Netfilter PREROUTING', 'Conntrack', 'NAT PREROUTING', 'Routing Decision'
                }),
                'Outbound': PipelineStats(active_nodes={
                    'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
                    'Routing Lookup', 'NAT POSTROUTING', 'TC Egress', 'Driver TX'
                }),
                'Local Delivery': PipelineStats(active_nodes={
                    'Netfilter INPUT', 'TCP/UDP', 'Socket'
                }),
                'Forward': PipelineStats(active_nodes={
                    'Netfilter FORWARD', 'Netfilter POSTROUTING', 'NIC TX'
                })
            }
