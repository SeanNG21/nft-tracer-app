#!/usr/bin/env python3
"""
Realtime Packet Tracer Backend - FINAL VERSION
Complete working version with all fixes applied
Compatible with both old and new frontend
"""

import os
import sys
import time
import json
import socket
import struct
import threading
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from bcc import BPF
import ctypes as ct

# ============================================
# MAPPINGS AND CONSTANTS
# ============================================

HOOK_MAP = {
    0: "PRE_ROUTING",
    1: "LOCAL_IN",
    2: "FORWARD",
    3: "LOCAL_OUT",
    4: "POST_ROUTING",
    255: "UNKNOWN"
}

HOOK_ORDER = ["PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING"]

LAYER_MAP = {
    "Ingress": [
        "netif_receive_skb", "__netif_receive_skb_core",
        "__netif_receive_skb_one_core", "netif_rx"
    ],
    "L2": [
        "br_handle_frame", "br_forward", "br_nf_pre_routing",
        "br_nf_forward"
    ],
    "IP": [
        "ip_rcv", "ip_rcv_finish", "ip_forward", "ip_forward_finish",
        "ip_local_deliver", "ip_local_deliver_finish",
        "ip_output", "ip_finish_output", "ip_finish_output2",
        "ipv4_mtu", "ip_route_input_slow", "ip_route_output_key_hash"
    ],
    "Firewall": [
        "nf_hook_slow", "nft_do_chain", "nft_immediate_eval",
        "nf_conntrack_in", "nf_nat_packet", "nf_nat_manip_pkt",
        "ipt_do_table", "xt_match_target"
    ],
    "Socket": [
        "tcp_v4_rcv", "tcp_v4_do_rcv", "tcp_rcv_established",
        "tcp_transmit_skb", "tcp_write_xmit",
        "udp_rcv", "__udp4_lib_rcv", "udp_sendmsg",
        "inet_sendmsg", "inet_recvmsg", "__sk_receive_skb"
    ],
    "Egress": [
        "dev_queue_xmit", "__dev_queue_xmit", "dev_hard_start_xmit",
        "sch_direct_xmit", "__dev_xmit_skb"
    ]
}

HOOK_LAYER_MAP = {
    "PRE_ROUTING": ["Ingress", "L2", "IP", "Firewall"],
    "LOCAL_IN": ["IP", "Firewall", "Socket"],
    "FORWARD": ["IP", "Firewall"],
    "LOCAL_OUT": ["Socket", "Firewall", "IP", "Egress"],
    "POST_ROUTING": ["Firewall", "Egress"],
    "UNKNOWN": ["Ingress", "L2", "IP", "Firewall", "Socket", "Egress"]
}

LAYER_ORDER = ["Ingress", "L2", "IP", "Firewall", "Socket", "Egress"]

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

ERROR_MAP = {
    0: "NONE",
    1: "CHECKSUM_FAIL",
    2: "NO_ROUTE",
    3: "INVALID_VERDICT",
    4: "QUEUE_OVERFLOW",
    5: "TTL_EXPIRED"
}

PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    132: "SCTP"
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
    # 'sock_def_readable': 'Socket',  # REMOVED: Generates too many low-value events
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

# ============================================
# DATA STRUCTURES
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
        """Add an event to this node's statistics"""
        self.count += 1
        # Only track unique SKBs if skb_addr is valid (not empty/None)
        if skb_addr and skb_addr != '':
            self.unique_skbs.add(skb_addr)
        if latency_us > 0:
            self.latencies_us.append(latency_us)
        if function:
            self.function_calls[function] += 1
        if verdict:
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

    def to_dict(self, nodes_dict: Dict[str, 'NodeStats']) -> Dict:
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

    def calculate_in_flight_from_nodes(self, nodes_dict: Dict[str, 'NodeStats']) -> int:
        """Calculate total in-flight packets from nodes belonging to this pipeline"""
        total = 0
        for node_name in self.active_nodes:
            if node_name in nodes_dict:
                total += len(nodes_dict[node_name].in_flight_packets)
        return total

@dataclass
class PacketEvent:
    """Single packet event from eBPF"""
    timestamp: float
    skb_addr: str
    cpu_id: int
    pid: int
    event_type: int
    hook: int
    hook_name: str
    pf: int
    protocol: int
    protocol_name: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int
    verdict: int
    verdict_name: str
    error_code: int
    error_name: str
    function: str
    layer: str
    comm: str
    
    chain_addr: Optional[str] = None
    rule_seq: Optional[int] = None
    rule_handle: Optional[int] = None
    queue_num: Optional[int] = None

@dataclass
class LayerStats:
    """Statistics for a single layer"""
    packets_in: int = 0
    packets_out: int = 0
    drops: int = 0
    accepts: int = 0
    errors: int = 0
    total_latency_ns: int = 0
    latency_count: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    verdict_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    function_calls: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    @property
    def avg_latency_ms(self) -> float:
        if self.latency_count == 0:
            return 0.0
        return (self.total_latency_ns / self.latency_count) / 1_000_000
    
    @property
    def drop_rate(self) -> float:
        total = self.packets_in
        if total == 0:
            return 0.0
        return (self.drops / total) * 100
    
    def to_dict(self) -> Dict:
        """Convert to dict - optimized for frontend graph"""
        top_func = None
        top_func_count = 0
        if self.function_calls:
            top_func, top_func_count = max(
                self.function_calls.items(), 
                key=lambda x: x[1]
            )
        
        verdict_pct = {}
        if self.packets_in > 0:
            for verdict, count in self.verdict_breakdown.items():
                verdict_pct[verdict] = round((count / self.packets_in) * 100, 1)
        
        return {
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'drops': self.drops,
            'accepts': self.accepts,
            'errors': self.errors,
            'avg_latency_ms': round(self.avg_latency_ms, 3),
            'drop_rate': round(self.drop_rate, 2),
            'verdict_breakdown': dict(self.verdict_breakdown),
            'verdict_percentages': verdict_pct,
            'error_breakdown': dict(self.error_breakdown),
            'function_calls': dict(sorted(
                self.function_calls.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'top_function': top_func,
            'top_function_calls': top_func_count,
            'first_ts': self.first_ts,
            'last_ts': self.last_ts
        }

@dataclass
class HookStats:
    """Statistics for a single hook"""
    layers: Dict[str, LayerStats] = field(default_factory=dict)
    packets_total: int = 0
    
    def get_layer(self, layer_name: str) -> LayerStats:
        if layer_name not in self.layers:
            self.layers[layer_name] = LayerStats()
        return self.layers[layer_name]
    
    def to_dict(self) -> Dict:
        return {
            'packets_total': self.packets_total,
            'layers': {
                name: stats.to_dict() 
                for name, stats in self.layers.items()
            }
        }

class RealtimeStats:
    """Aggregated realtime statistics"""

    def __init__(self):
        self.hooks: Dict[str, HookStats] = {}
        self.skb_tracking: Dict[str, Dict] = {}
        self.recent_events: deque = deque(maxlen=1000)
        self.total_packets = 0
        self.start_time = time.time()
        self._lock = threading.Lock()

        # NEW: Pipeline stats for Inbound/Outbound visualization
        self.stats_by_direction_layer = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int)
        }

        # ENHANCED: Node-based statistics with detailed metrics
        self.nodes: Dict[str, NodeStats] = {}  # node_name -> NodeStats
        self.edges: Dict[tuple, EdgeStats] = {}  # (from, to) -> EdgeStats
        self.skb_paths: Dict[str, List[str]] = {}  # skb_addr -> [node1, node2, ...]

        # ENHANCED: Pipeline completion tracking with node definitions
        # Define pipelines with their constituent nodes (ORDER MATTERS for display)
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
    
    def get_hook(self, hook_name: str) -> HookStats:
        if hook_name not in self.hooks:
            self.hooks[hook_name] = HookStats()
        return self.hooks[hook_name]

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
    
    def _detect_direction(self, hook_name: str, layer_name: str, function: str, hook: int) -> str:
        """Detect packet direction (Inbound or Outbound) using new pipeline mapping"""
        # First try to use function-based detection
        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return detect_packet_direction_new(function, refined_layer, hook)

        # Fallback to hook-based detection
        if hook_name in ['PRE_ROUTING', 'LOCAL_IN', 'FORWARD']:
            return 'Inbound'
        elif hook_name in ['LOCAL_OUT', 'POST_ROUTING']:
            return 'Outbound'

        # Layer-based fallback (old layer names)
        if layer_name in ['Ingress', 'L2']:
            return 'Inbound'
        elif layer_name == 'Egress':
            return 'Outbound'

        # Function-based fallback
        if function:
            func_lower = function.lower()
            if any(kw in func_lower for kw in ['rcv', 'receive', 'input', 'ingress', 'deliver']):
                return 'Inbound'
            elif any(kw in func_lower for kw in ['sendmsg', 'xmit', 'transmit', 'output', 'egress']):
                return 'Outbound'

        # Default to Inbound
        return 'Inbound'

    def _map_to_pipeline_layer(self, layer_name: str, function: str, hook: int) -> str:
        """Map function to new pipeline layer name using FUNCTION_TO_LAYER"""
        # First priority: Use FUNCTION_TO_LAYER mapping
        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            # Refine by hook if needed (e.g., Netfilter → Netfilter PREROUTING)
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return refined_layer

        # Fallback: Old layer name mappings
        layer_map = {
            'Ingress': 'NIC',
            'L2': 'Driver (NAPI)',
            'IP': 'Routing Decision',
            'Firewall': 'Netfilter',
            'Socket': 'TCP/UDP',
            'Egress': 'Driver TX'
        }

        if layer_name in layer_map:
            return layer_map[layer_name]

        # Fallback: Function-based heuristics
        if function:
            func_lower = function.lower()
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

        return layer_name

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

    def process_event(self, event: PacketEvent):
        """Process a single packet event and update statistics"""
        with self._lock:
            hook_name = event.hook_name
            layer_name = event.layer

            # Allow all valid hooks and layers - don't filter too strictly
            # This ensures we capture all hooks: PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING
            if hook_name == "UNKNOWN" or not layer_name:
                return

            # NEW: Track pipeline stats for Inbound/Outbound using new mapping
            hook = event.hook if event.hook != 255 else 0  # Default to PREROUTING if unknown
            direction = self._detect_direction(hook_name, layer_name, event.function or '', hook)
            pipeline_layer = self._map_to_pipeline_layer(layer_name, event.function or '', hook)
            self.stats_by_direction_layer[direction][pipeline_layer] += 1

            # ENHANCED: Track detailed node statistics
            node = self.get_node(pipeline_layer)

            # Calculate latency in microseconds
            latency_us = 0.0
            if event.skb_addr and event.skb_addr in self.skb_tracking:
                first_ts = self.skb_tracking[event.skb_addr]['first_ts']
                latency_us = (event.timestamp - first_ts) * 1_000_000  # convert to microseconds

            # Add event to node
            node.add_event(
                skb_addr=event.skb_addr or '',
                latency_us=latency_us,
                function=event.function,
                verdict=event.verdict_name,
                error=(event.error_code > 0)
            )

            # Track edges (transitions between nodes) and in-flight packets
            if event.skb_addr:
                if event.skb_addr not in self.skb_paths:
                    self.skb_paths[event.skb_addr] = []

                # If there's a previous node, create an edge and update in-flight tracking
                if self.skb_paths[event.skb_addr]:
                    prev_node = self.skb_paths[event.skb_addr][-1]
                    if prev_node != pipeline_layer:  # Avoid self-loops
                        self.add_edge(prev_node, pipeline_layer)
                        # Remove from previous node's in-flight set
                        prev_node_stats = self.get_node(prev_node)
                        prev_node_stats.in_flight_packets.discard(event.skb_addr)

                # Add packet to current node's in-flight set
                node.in_flight_packets.add(event.skb_addr)

                # Add current node to path
                self.skb_paths[event.skb_addr].append(pipeline_layer)

                # ENHANCED: Track pipeline membership (which pipelines this SKB has entered)
                self._track_pipeline_membership(event.skb_addr, pipeline_layer)

                # Limit path history and cleanup old SKB tracking
                if len(self.skb_paths) > 10000:
                    oldest_keys = list(self.skb_paths.keys())[:1000]
                    for key in oldest_keys:
                        # Cleanup in-flight packets for stale SKBs
                        for node_stats in self.nodes.values():
                            node_stats.in_flight_packets.discard(key)
                        del self.skb_paths[key]
            
            # Accept event even if layer not in strict map - this helps capture more data
            # We'll validate layer presence in HOOK_LAYER_MAP but still process
            expected_layers = HOOK_LAYER_MAP.get(hook_name, [])
            if expected_layers and layer_name not in expected_layers:
                # Layer exists but not expected for this hook - still process but mark as unexpected
                pass  # Continue processing anyway
            
            hook_stats = self.get_hook(hook_name)
            hook_stats.packets_total += 1
            self.total_packets += 1
            
            layer_stats = hook_stats.get_layer(layer_name)
            layer_stats.packets_in += 1
            
            if layer_stats.first_ts is None:
                layer_stats.first_ts = event.timestamp
            layer_stats.last_ts = event.timestamp
            
            if event.verdict_name:
                layer_stats.verdict_breakdown[event.verdict_name] += 1
                
                if event.verdict_name == "DROP":
                    layer_stats.drops += 1
                elif event.verdict_name == "ACCEPT":
                    layer_stats.accepts += 1
                    layer_stats.packets_out += 1
            
            if event.error_code > 0:
                layer_stats.errors += 1
                layer_stats.error_breakdown[event.error_name] += 1
            
            if event.function:
                layer_stats.function_calls[event.function] += 1
            
            if event.skb_addr:
                if event.skb_addr not in self.skb_tracking:
                    self.skb_tracking[event.skb_addr] = {
                        'first_ts': event.timestamp,
                        'hooks': []
                    }
                
                skb_info = self.skb_tracking[event.skb_addr]
                skb_info['hooks'].append({
                    'hook': hook_name,
                    'layer': layer_name,
                    'ts': event.timestamp
                })
                
                latency_ns = int((event.timestamp - skb_info['first_ts']) * 1_000_000_000)
                layer_stats.total_latency_ns += latency_ns
                layer_stats.latency_count += 1
                
                if len(self.skb_tracking) > 10000:
                    oldest_keys = list(self.skb_tracking.keys())[:1000]
                    for key in oldest_keys:
                        del self.skb_tracking[key]
            
            self.recent_events.append(asdict(event))
    
    def get_summary(self) -> Dict:
        """Get current statistics summary - optimized for frontend graph"""
        with self._lock:
            uptime = time.time() - self.start_time
            current_ts = time.time()

            hooks_data = {}
            for hook_name in HOOK_ORDER:
                if hook_name in self.hooks:
                    hooks_data[hook_name] = self.hooks[hook_name].to_dict()

            for hook_name, hook_stats in self.hooks.items():
                if hook_name not in HOOK_ORDER:
                    hooks_data[hook_name] = hook_stats.to_dict()

            # ENHANCED: Serialize nodes and edges with packet rate
            nodes_data = {}
            for node_name, node_stats in self.nodes.items():
                nodes_data[node_name] = node_stats.to_dict(current_ts)

            edges_data = []
            for edge_stats in self.edges.values():
                edges_data.append(edge_stats.to_dict())

            # ENHANCED: Pipeline statistics (ORDERED for consistent display)
            # Use OrderedDict to maintain order from pipeline_order list
            pipelines_data = []
            for pipeline_name in self.pipeline_order:
                if pipeline_name in self.pipelines:
                    pipeline_stats = self.pipelines[pipeline_name]
                    pipeline_dict = pipeline_stats.to_dict(self.nodes)
                    pipeline_dict['name'] = pipeline_name
                    pipelines_data.append(pipeline_dict)

            # Calculate total verdict statistics across all netfilter nodes
            total_verdicts = defaultdict(int)
            for node_name, node_stats in self.nodes.items():
                if 'Netfilter' in node_name and node_stats.verdict_breakdown:
                    for verdict, count in node_stats.verdict_breakdown.items():
                        total_verdicts[verdict] += count

            # ENHANCED: Top Latency Contributors (for latency hotspot panel)
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
                'hooks': hooks_data,
                'recent_events': list(self.recent_events)[-100:],
                # NEW: Pipeline stats for Inbound/Outbound visualization
                'stats': {
                    'Inbound': dict(self.stats_by_direction_layer['Inbound']),
                    'Outbound': dict(self.stats_by_direction_layer['Outbound'])
                },
                # ENHANCED: Detailed node and edge statistics
                'nodes': nodes_data,
                'edges': edges_data,
                # ENHANCED: Pipeline completion statistics
                'pipelines': pipelines_data,
                # ENHANCED: Total verdict statistics
                'total_verdicts': dict(total_verdicts),
                # ENHANCED: Top latency contributors for hotspot analysis
                'top_latency': latency_ranking[:10]
            }
    
    def reset(self):
        """Reset all statistics"""
        with self._lock:
            self.hooks.clear()
            self.skb_tracking.clear()
            self.recent_events.clear()
            self.total_packets = 0
            self.start_time = time.time()
            # NEW: Reset pipeline stats
            self.stats_by_direction_layer = {
                'Inbound': defaultdict(int),
                'Outbound': defaultdict(int)
            }
            # ENHANCED: Reset nodes and edges
            self.nodes.clear()
            self.edges.clear()
            self.skb_paths.clear()
            # ENHANCED: Reset pipeline tracking
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

# ============================================
# HELPER FUNCTIONS
# ============================================

def format_ip(ip_int: int) -> str:
    """Format IP address from integer"""
    if ip_int == 0:
        return "0.0.0.0"
    try:
        return socket.inet_ntoa(struct.pack('<I', ip_int))
    except:
        return "0.0.0.0"

def get_layer_from_function(func_name: str) -> str:
    """Determine layer from function name"""
    for layer, functions in LAYER_MAP.items():
        if func_name in functions:
            return layer
    
    func_lower = func_name.lower()
    if 'netif' in func_lower or 'rx' in func_lower:
        return "Ingress"
    elif 'br_' in func_lower:
        return "L2"
    elif 'ip_' in func_lower or 'ipv4' in func_lower or 'ipv6' in func_lower:
        return "IP"
    elif 'nf_' in func_lower or 'nft_' in func_lower or 'ipt_' in func_lower:
        return "Firewall"
    elif 'tcp_' in func_lower or 'udp_' in func_lower or 'sock' in func_lower:
        return "Socket"
    elif 'xmit' in func_lower or 'dev_queue' in func_lower:
        return "Egress"
    
    return "UNKNOWN"

def resolve_function_name(bpf_obj, func_ip: int) -> str:
    """Resolve function name from instruction pointer"""
    try:
        sym = bpf_obj.ksym(func_ip)
        if sym:
            return sym.decode('utf-8', errors='ignore')
    except:
        pass
    return f"func_{hex(func_ip)}"

# ============================================
# REALTIME TRACER CLASS
# ============================================

class RealtimeTracer:
    """Main realtime tracer with eBPF and Flask-SocketIO"""
    
    def __init__(self, socketio: SocketIO, bpf_code_path: str = None):
        self.socketio = socketio
        self.bpf = None
        self.stats = RealtimeStats()
        self.running = False
        
        if bpf_code_path:
            self.bpf_code_path = bpf_code_path
        else:
            possible_paths = [
                "/mnt/user-data/uploads/full_tracer_bpf.c",
                os.path.join(os.path.dirname(__file__), "ebpf", "full_tracer.bpf.c"),
                os.path.join(os.getcwd(), "full_tracer.bpf.c"),
                os.path.join(os.getcwd(), "full_tracer_bpf.c"),
                os.path.join(os.path.dirname(__file__), "full_tracer.bpf.c"),
                os.path.join(os.path.dirname(__file__), "full_tracer_bpf.c"),
            ]
            
            self.bpf_code_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    self.bpf_code_path = path
                    print(f"[*] Found BPF code at: {path}")
                    break
            
            if not self.bpf_code_path:
                self.bpf_code_path = possible_paths[0]
        
        self.func_name_cache = {}
        
    def load_bpf(self) -> bool:
        """Load and compile BPF program"""
        try:
            if not os.path.exists(self.bpf_code_path):
                print(f"[!] BPF code not found: {self.bpf_code_path}")
                return False
            
            with open(self.bpf_code_path, 'r') as f:
                bpf_code = f.read()
            
            print("[*] Compiling BPF program...")
            self.bpf = BPF(text=bpf_code)
            
            # FIXED: 54 critical networking functions aligned with full trace mode
            functions_to_trace = [
                # === INBOUND PIPELINE ===
                # NIC Layer
                'napi_gro_receive',
                'netif_receive_skb',
                'netif_receive_skb_list_internal',

                # Driver (NAPI)
                'napi_poll',
                'net_rx_action',
                'process_backlog',

                # GRO
                'gro_normal_list',
                'dev_gro_receive',
                'skb_gro_receive',

                # TC Ingress
                'tcf_classify',
                'ingress_redirect',
                'dev_queue_xmit_nit',

                # Netfilter (refined by hook)
                'nf_hook_slow',
                'nf_hook_thresh',
                'nf_reinject',

                # Conntrack
                'nf_conntrack_in',
                'nf_ct_invert_tuple',
                'nf_confirm',

                # NAT
                'nf_nat_ipv4_pre_routing',
                'nf_nat_ipv4_fn',

                # Routing Decision
                'ip_route_input_slow',
                'fib_validate_source',
                'ip_route_output_key_hash',

                # Local Delivery
                'ip_local_deliver',
                'ip_local_deliver_finish',

                # NFT/Queue
                'nf_queue',

                # TCP/UDP (Inbound)
                'tcp_v4_rcv',
                'tcp_v4_do_rcv',
                'tcp_rcv_established',
                'udp_rcv',
                'udp_unicast_rcv_skb',

                # Socket
                # 'sock_def_readable',  # REMOVED: Generates too many low-value events
                'sk_filter_trim_cap',

                # Forward
                'ip_forward',
                'ip_forward_finish',

                # === OUTBOUND PIPELINE ===
                # Application
                'tcp_sendmsg',
                'udp_sendmsg',

                # TCP/UDP Output
                'tcp_write_xmit',
                'tcp_transmit_skb',
                'udp_send_skb',

                # Routing Lookup (outbound)
                'ip_route_output_flow',

                # NAT (outbound)
                'nf_nat_ipv4_out',
                'nf_nat_ipv4_local_fn',

                # TC Egress
                'sch_direct_xmit',

                # Driver TX / NIC TX
                'dev_queue_xmit',
                '__dev_queue_xmit',
                'dev_hard_start_xmit',
            ]
            
            attached_count = 0
            for func_name in functions_to_trace:
                try:
                    self.bpf.attach_kprobe(event=func_name, fn_name="trace_skb_func")
                    attached_count += 1
                except Exception as e:
                    pass
            
            print(f"[✓] Attached to {attached_count} functions")
            print("[✓] NFT hooks attached via kprobe/kretprobe")
            
            return True
            
        except Exception as e:
            print(f"[✗] Failed to load BPF: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_event(self, cpu, data, size):
        """Handle event from eBPF perf buffer"""
        try:
            class TraceEvent(ct.Structure):
                _fields_ = [
                    ("timestamp", ct.c_uint64),
                    ("skb_addr", ct.c_uint64),
                    ("cpu_id", ct.c_uint32),
                    ("pid", ct.c_uint32),
                    ("event_type", ct.c_uint8),
                    ("hook", ct.c_uint8),
                    ("pf", ct.c_uint8),
                    ("protocol", ct.c_uint8),
                    ("src_ip", ct.c_uint32),
                    ("dst_ip", ct.c_uint32),
                    ("src_port", ct.c_uint16),
                    ("dst_port", ct.c_uint16),
                    ("length", ct.c_uint32),
                    ("chain_addr", ct.c_uint64),
                    ("expr_addr", ct.c_uint64),
                    ("chain_depth", ct.c_uint8),
                    ("rule_seq", ct.c_uint16),
                    ("rule_handle", ct.c_uint64),
                    ("verdict_raw", ct.c_int32),
                    ("verdict", ct.c_uint32),
                    ("queue_num", ct.c_uint16),
                    ("has_queue_bypass", ct.c_uint8),
                    ("error_code", ct.c_uint8),
                    ("func_ip", ct.c_uint64),
                    ("function_name", ct.c_char * 64),
                    ("comm", ct.c_char * 16),
                ]
            
            event = ct.cast(data, ct.POINTER(TraceEvent)).contents
            
            ts = time.time()
            
            func_name = event.function_name.decode('utf-8', errors='ignore').strip('\x00')
            if not func_name and event.func_ip != 0:
                if event.func_ip in self.func_name_cache:
                    func_name = self.func_name_cache[event.func_ip]
                else:
                    func_name = resolve_function_name(self.bpf, event.func_ip)
                    self.func_name_cache[event.func_ip] = func_name
            
            layer = get_layer_from_function(func_name)
            
            packet_event = PacketEvent(
                timestamp=ts,
                skb_addr=hex(event.skb_addr) if event.skb_addr else None,
                cpu_id=event.cpu_id,
                pid=event.pid,
                event_type=event.event_type,
                hook=event.hook,
                hook_name=HOOK_MAP.get(event.hook, "UNKNOWN"),
                pf=event.pf,
                protocol=event.protocol,
                protocol_name=PROTO_MAP.get(event.protocol, f"PROTO_{event.protocol}"),
                src_ip=format_ip(event.src_ip),
                dst_ip=format_ip(event.dst_ip),
                src_port=event.src_port,
                dst_port=event.dst_port,
                length=event.length,
                verdict=event.verdict,
                verdict_name=VERDICT_MAP.get(event.verdict, "UNKNOWN"),
                error_code=event.error_code,
                error_name=ERROR_MAP.get(event.error_code, "UNKNOWN"),
                function=func_name,
                layer=layer,
                comm=event.comm.decode('utf-8', errors='ignore'),
                chain_addr=hex(event.chain_addr) if event.chain_addr else None,
                rule_seq=event.rule_seq if event.rule_seq > 0 else None,
                rule_handle=event.rule_handle if event.rule_handle > 0 else None,
                queue_num=event.queue_num if event.queue_num > 0 else None
            )
            
            # Process event and update stats (no longer emit individual events)
            self.stats.process_event(packet_event)
            # Comment out individual event emission - only send aggregated stats every 1s
            # self.socketio.emit('packet_event', asdict(packet_event))
            
        except Exception as e:
            print(f"[!] Error handling event: {e}")
    
    def start(self) -> bool:
        """Start tracing"""
        if not self.load_bpf():
            return False
        
        # CRITICAL FIX: Increase buffer size to prevent sample loss
        # Default: 8 pages = 32KB (too small for high traffic)
        # New: 512 pages = 2MB (can handle burst traffic)
        self.bpf["events"].open_perf_buffer(
            self.handle_event,
            page_cnt=512  # 512 * 4KB = 2MB buffer
        )
        self.running = True

        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        
        self.stats_thread = threading.Thread(target=self._stats_broadcast_loop, daemon=True)
        self.stats_thread.start()
        
        print("[✓] Realtime tracer started")
        return True
    
    def _poll_loop(self):
        """Poll eBPF perf buffer - poll frequently to avoid buffer overflow"""
        while self.running:
            try:
                # CRITICAL FIX: Poll every 10ms instead of 100ms
                # Faster polling = less chance of buffer overflow
                self.bpf.perf_buffer_poll(timeout=10)
            except Exception as e:
                if self.running:
                    print(f"[!] Poll error: {e}")
                break
    
    def _stats_broadcast_loop(self):
        """Broadcast statistics every 1 second for optimal readability"""
        while self.running:
            time.sleep(1.0)  # 1s for optimal readability
            try:
                summary = self.stats.get_summary()
                self.socketio.emit('stats_update', summary)
            except Exception as e:
                print(f"[!] Stats broadcast error: {e}")
    
    def stop(self):
        """Stop tracing"""
        self.running = False
        if self.bpf:
            self.bpf.cleanup()
        print("[✓] Realtime tracer stopped")
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return self.stats.get_summary()
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats.reset()

# ============================================
# FLASK APPLICATION
# ============================================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet-tracer-realtime-2024'
app.config['JSON_SORT_KEYS'] = False
CORS(app)

# CRITICAL FIX: Proper SocketIO configuration
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    logger=False,              # Fix: Disable logger to prevent conflicts
    engineio_logger=False,     # Fix: Disable engineio logger
    ping_timeout=60,           # Fix: Longer timeout
    ping_interval=25           # Fix: Proper ping interval
)

# Global tracer instance
tracer: Optional[RealtimeTracer] = None

# Serve static files
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/')
def index():
    """Serve index page"""
    html_path = os.path.join(os.path.dirname(__file__), 'static', 'index.html')
    if os.path.exists(html_path):
        return send_from_directory('static', 'index.html')
    
    return jsonify({
        'status': 'running',
        'message': 'Realtime Packet Tracer Backend',
        'version': '2.0 Final',
        'endpoints': {
            'start': '/api/start',
            'stop': '/api/stop',
            'stats': '/api/stats',
            'reset': '/api/reset',
            'realtime_enable': '/api/realtime/enable',
            'realtime_disable': '/api/realtime/disable',
            'realtime_stats': '/api/realtime/stats',
            'realtime_reset': '/api/realtime/reset'
        }
    })

# ============================================
# OLD API ROUTES (Backward compatibility)
# ============================================

@app.route('/api/start', methods=['POST'])
def start_trace():
    """Start tracing"""
    global tracer
    
    if tracer and tracer.running:
        return jsonify({'error': 'Tracer already running'}), 400
    
    tracer = RealtimeTracer(socketio)
    
    if tracer.start():
        return jsonify({'status': 'started'})
    else:
        return jsonify({'error': 'Failed to start tracer'}), 500

@app.route('/api/stop', methods=['POST'])
def stop_trace():
    """Stop tracing"""
    global tracer
    
    if not tracer or not tracer.running:
        return jsonify({'error': 'Tracer not running'}), 400
    
    tracer.stop()
    return jsonify({'status': 'stopped'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get current statistics"""
    global tracer
    
    if not tracer:
        return jsonify({
            'total_packets': 0,
            'uptime_seconds': 0,
            'packets_per_second': 0,
            'hooks': {}
        })
    
    return jsonify(tracer.get_stats())

@app.route('/api/reset', methods=['POST'])
def reset_stats():
    """Reset statistics"""
    global tracer
    
    if not tracer:
        return jsonify({'error': 'Tracer not initialized'}), 400
    
    tracer.reset_stats()
    return jsonify({'status': 'reset'})

# ============================================
# NEW API ROUTES (For new frontend)
# ============================================

@app.route('/api/realtime/enable', methods=['POST'])
def enable_realtime():
    """Enable realtime tracing"""
    global tracer
    
    try:
        if tracer and tracer.running:
            return jsonify({'status': 'already_enabled'})
        
        tracer = RealtimeTracer(socketio)
        
        if tracer.start():
            socketio.emit('status', {'enabled': True})
            return jsonify({'status': 'enabled'})
        else:
            return jsonify({'error': 'Failed to start realtime tracer'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime/disable', methods=['POST'])
def disable_realtime():
    """Disable realtime tracing"""
    global tracer
    
    try:
        if not tracer or not tracer.running:
            return jsonify({'status': 'already_disabled'})
        
        tracer.stop()
        socketio.emit('status', {'enabled': False})
        return jsonify({'status': 'disabled'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime/stats', methods=['GET'])
def get_realtime_stats():
    """Get realtime statistics"""
    global tracer
    
    try:
        if not tracer:
            return jsonify({
                'enabled': False,
                'total_packets': 0,
                'uptime_seconds': 0,
                'packets_per_second': 0,
                'hooks': {}
            })
        
        stats = tracer.get_stats()
        stats['enabled'] = tracer.running
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/realtime/reset', methods=['POST'])
def reset_realtime_stats():
    """Reset realtime statistics"""
    global tracer
    
    try:
        if not tracer:
            return jsonify({'error': 'Tracer not initialized'}), 400
        
        tracer.reset_stats()
        return jsonify({'status': 'reset'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# WEBSOCKET EVENTS
# ============================================

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print('[*] Client connected')
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('[*] Client disconnected')

@socketio.on('request_stats')
def handle_stats_request():
    """Client requests current stats"""
    global tracer
    if tracer:
        emit('stats_update', tracer.get_stats())

# ============================================
# REALTIME EXTENSION CLASS (For integration)
# ============================================

class SessionStatsTracker:
    """Track realtime stats for a specific trace session"""

    def __init__(self, session_id: str, mode: str):
        self.session_id = session_id
        self.mode = mode
        self.start_time = time.time()

        # Overall stats
        self.total_packets = 0
        self.total_events = 0

        # Hook-based stats: hook_name -> HookStats
        self.hooks = defaultdict(lambda: {
            'packets_total': 0,
            'packets_in': 0,
            'packets_out': 0,
            'layers': defaultdict(lambda: {
                'packets_in': 0,
                'packets_out': 0,
                'drop_rate': 0.0,
                'verdict_breakdown': defaultdict(int),
                'function_calls': defaultdict(int),
                'top_function': '',
                'top_function_calls': 0,
                'avg_latency_ms': 0.0,
                'total_latency_ms': 0.0,
                'latency_count': 0
            })
        })

        # ENHANCED: Node-based statistics for full mode (enhanced pipeline visualization)
        self.nodes: Dict[str, NodeStats] = {}  # node_name -> NodeStats
        self.skb_tracking: Dict[str, Dict] = {}  # skb_addr -> {'first_ts': float, 'last_node': str}
        self.skb_paths: Dict[str, List[str]] = {}  # skb_addr -> [node1, node2, ...]
        self.stats_by_direction_layer = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int)
        }

        # Multifunction-specific stats
        self.stats_by_layer = defaultdict(int)
        self.stats_by_hook = defaultdict(int)
        self.stats_by_verdict = defaultdict(int)

        # Recent events (keep last 50)
        self.recent_events = deque(maxlen=50)

        # Lock for thread safety
        self.lock = threading.Lock()

    def get_node(self, node_name: str) -> NodeStats:
        """Get or create a node's statistics"""
        if node_name not in self.nodes:
            self.nodes[node_name] = NodeStats()
        return self.nodes[node_name]
    
    def process_event(self, event: Dict):
        """Process a single event"""
        with self.lock:
            self.total_events += 1

            # Debug: Log first few events
            if self.total_events <= 5:
                print(f"[SessionStats {self.session_id}] Event #{self.total_events}: hook={event.get('hook')}, func={event.get('func_name', 'N/A')}, type={event.get('event_type', 'normal')}")

            # Check if multifunction mode
            is_multifunction = event.get('event_type') == 'multifunction'

            # Extract event info
            hook_num = event.get('hook', 255)
            hook_name = HOOK_MAP.get(hook_num, 'UNKNOWN')
            func_name = event.get('func_name', '')
            verdict = event.get('verdict', 255)
            verdict_name = VERDICT_MAP.get(verdict, 'UNKNOWN')
            protocol = event.get('protocol', 0)
            src_ip = event.get('src_ip', '0.0.0.0')
            dst_ip = event.get('dst_ip', '0.0.0.0')

            # Determine layer
            if is_multifunction and 'layer' in event:
                layer_name_raw = event['layer']  # Layer from BPF metadata
                # Map BPF layer names to frontend layer names
                layer_name = self._map_multifunction_layer(layer_name_raw, hook_name)
            else:
                layer_name = self._determine_layer(func_name, hook_name)

            # Multifunction-specific stats
            if is_multifunction:
                if layer_name and layer_name != 'Unknown':
                    self.stats_by_layer[layer_name] += 1

                if hook_num != 255:
                    self.stats_by_hook[hook_name] += 1

                if verdict != 255:
                    self.stats_by_verdict[verdict_name] += 1
            
            # Update hook stats
            hook_stats = self.hooks[hook_name]
            hook_stats['packets_total'] += 1
            
            # Update layer stats
            layer_stats = hook_stats['layers'][layer_name]
            layer_stats['packets_in'] += 1
            
            # Track verdict
            layer_stats['verdict_breakdown'][verdict_name] += 1
            
            # Track function
            if func_name:
                layer_stats['function_calls'][func_name] += 1
                
                # Update top function
                if layer_stats['function_calls'][func_name] > layer_stats['top_function_calls']:
                    layer_stats['top_function'] = func_name
                    layer_stats['top_function_calls'] = layer_stats['function_calls'][func_name]
            
            # Calculate drop rate
            total_in = layer_stats['packets_in']
            drops = layer_stats['verdict_breakdown'].get('DROP', 0)
            layer_stats['drop_rate'] = (drops / total_in * 100) if total_in > 0 else 0.0

            # Add to recent events (skip for multifunction - only aggregated stats)
            if not is_multifunction:
                self.recent_events.append({
                    'type': 'nft' if func_name == 'nft_do_chain' else 'trace',
                    'hook_name': hook_name,
                    'func_name': func_name,
                    'verdict_name': verdict_name,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'timestamp': time.time()
                })

            # ENHANCED: Track pipeline nodes for full mode (for enhanced visualization)
            if self.mode == 'full':
                # Map to pipeline layer
                pipeline_layer = self._map_to_pipeline_layer(layer_name, func_name, hook_num)

                # Detect direction
                direction = self._detect_direction(hook_name, layer_name, func_name, hook_num)

                # Update direction stats
                self.stats_by_direction_layer[direction][pipeline_layer] += 1

                # Get or create node
                node = self.get_node(pipeline_layer)

                # Track SKB and calculate latency
                skb_addr = event.get('skb_addr', '')
                timestamp = event.get('timestamp', time.time())
                latency_us = 0.0

                if skb_addr:
                    if skb_addr not in self.skb_tracking:
                        self.skb_tracking[skb_addr] = {
                            'first_ts': timestamp,
                            'last_node': pipeline_layer
                        }
                    else:
                        first_ts = self.skb_tracking[skb_addr]['first_ts']
                        latency_us = (timestamp - first_ts) * 1_000_000  # microseconds
                        self.skb_tracking[skb_addr]['last_node'] = pipeline_layer

                    # Limit tracking to prevent memory bloat
                    if len(self.skb_tracking) > 10000:
                        # Remove oldest 1000 entries
                        oldest_keys = list(self.skb_tracking.keys())[:1000]
                        for key in oldest_keys:
                            del self.skb_tracking[key]

                # Add event to node
                node.add_event(
                    skb_addr=skb_addr,
                    latency_us=latency_us,
                    function=func_name,
                    verdict=verdict_name,
                    error=(event.get('error_code', 0) > 0)
                )

            # Update total packets (count unique packets, not events)
            self.total_packets = max(self.total_packets, sum(h['packets_total'] for h in self.hooks.values()) // max(len(self.hooks), 1))
    
    def _detect_direction(self, hook_name: str, layer_name: str, function: str, hook: int) -> str:
        """Detect packet direction (Inbound or Outbound)"""
        # First try to use function-based detection
        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return detect_packet_direction_new(function, refined_layer, hook)

        # Fallback to hook-based detection
        if hook_name in ['PRE_ROUTING', 'LOCAL_IN', 'FORWARD']:
            return 'Inbound'
        elif hook_name in ['LOCAL_OUT', 'POST_ROUTING']:
            return 'Outbound'

        # Layer-based fallback
        if layer_name in ['Ingress', 'L2']:
            return 'Inbound'
        elif layer_name == 'Egress':
            return 'Outbound'

        return 'Inbound'  # Default

    def _map_to_pipeline_layer(self, layer_name: str, function: str, hook: int) -> str:
        """Map function to pipeline layer name using FUNCTION_TO_LAYER"""
        # First priority: Use FUNCTION_TO_LAYER mapping
        if function and function in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[function]
            # Refine by hook if needed
            refined_layer = refine_layer_by_hook(function, base_layer, hook)
            return refined_layer

        # Fallback: Old layer name mappings
        layer_map = {
            'Ingress': 'NIC',
            'L2': 'Driver (NAPI)',
            'IP': 'Routing Decision',
            'Firewall': 'Netfilter',
            'Socket': 'TCP/UDP',
            'Egress': 'Driver TX'
        }

        if layer_name in layer_map:
            return layer_map[layer_name]

        # Function-based heuristics
        if function:
            func_lower = function.lower()
            if 'napi' in func_lower:
                return 'Driver (NAPI)'
            elif 'gro' in func_lower:
                return 'GRO'
            elif 'tc' in func_lower:
                return 'TC Ingress' if 'ingress' in func_lower else 'TC Egress'

        return layer_name or 'Unknown'

    def _map_multifunction_layer(self, bpf_layer: str, hook_name: str) -> str:
        """Map BPF layer names to frontend layer names"""
        # Mapping from BPF trace_config.json layers to frontend LAYER_MAP
        layer_mapping = {
            'Device': 'Ingress',
            'GRO': 'Ingress',
            'L2': 'L2',
            'Bridge': 'L2',
            'IPv4': 'IP',
            'IPv6': 'IP',
            'IP': 'IP',
            'Routing': 'IP',
            'Netfilter': 'Firewall',
            'NFT': 'Firewall',
            'Conntrack': 'Firewall',
            'TCP': 'Socket',
            'UDP': 'Socket',
            'ICMP': 'Socket',
            'Socket': 'Socket',
            'Xmit': 'Egress',
            'Qdisc': 'Egress',
            'SoftIRQ': 'Ingress'
        }

        frontend_layer = layer_mapping.get(bpf_layer, bpf_layer)

        # Verify layer is valid for this hook
        valid_layers = HOOK_LAYER_MAP.get(hook_name, [])
        if frontend_layer in valid_layers:
            return frontend_layer

        # If not valid, try to find best match
        if valid_layers:
            # Prefer Firewall for hooks that support it
            if 'Firewall' in valid_layers and bpf_layer in ['Netfilter', 'NFT']:
                return 'Firewall'
            # Otherwise return first valid layer
            return valid_layers[0]

        return frontend_layer

    def _determine_layer(self, func_name: str, hook_name: str) -> str:
        """Determine which layer a function belongs to"""
        if not func_name:
            return "Unknown"

        # Check each layer's functions
        for layer, functions in LAYER_MAP.items():
            for func in functions:
                if func in func_name:
                    # Verify layer is valid for this hook
                    valid_layers = HOOK_LAYER_MAP.get(hook_name, [])
                    if layer in valid_layers:
                        return layer

        # Default to first valid layer for hook
        valid_layers = HOOK_LAYER_MAP.get(hook_name, [])
        return valid_layers[0] if valid_layers else "Unknown"
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        with self.lock:
            uptime = time.time() - self.start_time
            pps = self.total_events / uptime if uptime > 0 else 0
            
            # Convert defaultdicts to regular dicts for JSON
            hooks_dict = {}
            for hook_name, hook_data in self.hooks.items():
                layers_dict = {}
                for layer_name, layer_data in hook_data['layers'].items():
                    layers_dict[layer_name] = {
                        'packets_in': layer_data['packets_in'],
                        'packets_out': layer_data['packets_out'],
                        'drop_rate': layer_data['drop_rate'],
                        'verdict_breakdown': dict(layer_data['verdict_breakdown']),
                        'top_function': layer_data['top_function'],
                        'top_function_calls': layer_data['top_function_calls'],
                        'avg_latency_ms': layer_data['avg_latency_ms']
                    }
                
                hooks_dict[hook_name] = {
                    'packets_total': hook_data['packets_total'],
                    'packets_in': hook_data['packets_in'],
                    'packets_out': hook_data['packets_out'],
                    'layers': layers_dict
                }
            
            stats = {
                'session_id': self.session_id,
                'mode': self.mode,
                'total_packets': self.total_packets,
                'total_events': self.total_events,
                'uptime_seconds': uptime,
                'packets_per_second': pps,
                'hooks': hooks_dict
            }

            # Add multifunction-specific stats (aggregated only, no individual events)
            if self.mode == 'multifunction':
                stats['stats_by_layer'] = dict(self.stats_by_layer)
                stats['stats_by_hook'] = dict(self.stats_by_hook)
                stats['stats_by_verdict'] = dict(self.stats_by_verdict)
            else:
                # Only include recent_events for non-multifunction modes
                stats['recent_events'] = list(self.recent_events)

            # ENHANCED: Add nodes data for full mode (for enhanced pipeline visualization)
            if self.mode == 'full':
                nodes_data = {}
                for node_name, node_stats in self.nodes.items():
                    nodes_data[node_name] = node_stats.to_dict()
                stats['nodes'] = nodes_data

            return stats

class RealtimeExtension:
    """Wrapper class for integrating realtime tracer into main app"""
    
    def __init__(self, app: Flask, socketio: SocketIO):
        self.app = app
        self.socketio = socketio
        self.tracer: Optional[RealtimeTracer] = None
        
        # Session-specific tracking
        self.session_trackers = {}  # session_id -> SessionStatsTracker
        self.session_lock = threading.Lock()
        self._session_stats_thread = None
        self._session_stats_running = False
        
        # Setup WebSocket handlers
        self._setup_session_handlers()
        
        print("[*] RealtimeExtension initialized")
    
    def enable(self) -> bool:
        """Enable realtime tracing"""
        if self.tracer and self.tracer.running:
            return True
        
        self.tracer = RealtimeTracer(self.socketio)
        
        if self.tracer.start():
            self.socketio.emit('status', {'enabled': True})
            return True
        else:
            return False
    
    def disable(self) -> bool:
        """Disable realtime tracing"""
        if not self.tracer or not self.tracer.running:
            return True
        
        self.tracer.stop()
        self.socketio.emit('status', {'enabled': False})
        return True
    
    def is_enabled(self) -> bool:
        """Check if realtime tracing is enabled"""
        return self.tracer is not None and self.tracer.running
    
    def has_session(self, session_id: str) -> bool:
        """Check if a session is being tracked"""
        with self.session_lock:
            return session_id in self.session_trackers
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        if not self.tracer:
            return {
                'enabled': False,
                'total_packets': 0,
                'uptime_seconds': 0,
                'packets_per_second': 0,
                'hooks': {}
            }
        
        stats = self.tracer.get_stats()
        stats['enabled'] = self.tracer.running
        return stats
    
    def reset_stats(self):
        """Reset statistics"""
        if self.tracer:
            self.tracer.reset_stats()
    
    # ============= SESSION-SPECIFIC TRACKING =============
    
    def _setup_session_handlers(self):
        """Setup WebSocket handlers for session tracking"""
        @self.socketio.on('join_session')
        def handle_join_session(data):
            session_id = data.get('session_id')
            if session_id:
                from flask_socketio import join_room
                join_room(f"session_{session_id}")
                print(f"[WebSocket] Client joined session room: session_{session_id}")
                emit('joined_session', {'session_id': session_id})
        
        @self.socketio.on('leave_session')
        def handle_leave_session(data):
            session_id = data.get('session_id')
            if session_id:
                from flask_socketio import leave_room
                leave_room(f"session_{session_id}")
                print(f"[WebSocket] Client left session room: session_{session_id}")
    
    def start_session_tracking(self, session_id: str, mode: str):
        """Start tracking for a specific session"""
        print(f"[DEBUG] start_session_tracking called: session_id={session_id}, mode={mode}")
        with self.session_lock:
            if session_id not in self.session_trackers:
                tracker = SessionStatsTracker(session_id, mode)
                self.session_trackers[session_id] = tracker
                print(f"[Session] Started tracking for session: {session_id} (mode: {mode})")
                print(f"[DEBUG] Active session trackers: {list(self.session_trackers.keys())}")
                
                # Start stats emission thread if not running
                if not self._session_stats_running:
                    self._session_stats_running = True
                    self._session_stats_thread = threading.Thread(
                        target=self._emit_session_stats_loop,
                        daemon=True
                    )
                    self._session_stats_thread.start()
                    print(f"[DEBUG] Stats emission thread started")
            else:
                print(f"[DEBUG] Session {session_id} already exists in trackers")
    
    def stop_session_tracking(self, session_id: str):
        """Stop tracking for a specific session"""
        with self.session_lock:
            if session_id in self.session_trackers:
                del self.session_trackers[session_id]
                print(f"[Session] Stopped tracking for session: {session_id}")
    
    def process_session_event(self, event: Dict, session_id: str):
        """Process an event for a specific session"""
        with self.session_lock:
            if session_id in self.session_trackers:
                self.session_trackers[session_id].process_event(event)
            else:
                # Debug: session not found
                if not hasattr(self, '_session_not_found_logged'):
                    self._session_not_found_logged = set()
                if session_id not in self._session_not_found_logged:
                    print(f"[Warning] Session {session_id} not found in trackers. Available: {list(self.session_trackers.keys())}")
                    self._session_not_found_logged.add(session_id)
    
    def _emit_session_stats_loop(self):
        """Background thread to emit session stats every 1 second for optimal readability"""
        print(f"[DEBUG] _emit_session_stats_loop started (1s interval)")
        iteration = 0
        while self._session_stats_running:
            time.sleep(1.0)  # 1s for optimal readability
            iteration += 1

            with self.session_lock:
                if iteration <= 3:  # Debug first 3 iterations (3 seconds worth at 1s)
                    print(f"[DEBUG] Emit iteration #{iteration}, active sessions: {list(self.session_trackers.keys())}")

                for session_id, tracker in list(self.session_trackers.items()):
                    try:
                        stats = tracker.get_stats()

                        if iteration <= 3:  # Debug first 3 iterations (3s at 1s)
                            print(f"[DEBUG] Emitting stats for {session_id}: total_events={stats['total_events']}, total_packets={stats['total_packets']}")

                        # Emit to session-specific room
                        self.socketio.emit('session_stats_update', {
                            'session_id': session_id,
                            'stats': stats
                        }, room=f"session_{session_id}")
                    except Exception as e:
                        print(f"[Error] Failed to emit stats for session {session_id}: {e}")
                        import traceback
                        traceback.print_exc()


def add_realtime_routes(app: Flask, realtime: RealtimeExtension):
    """Add realtime API routes to Flask app (for backward compatibility)"""
    
    @app.route('/api/realtime/enable', methods=['POST'])
    def enable_realtime_compat():
        try:
            if realtime.enable():
                return jsonify({'status': 'enabled'})
            else:
                return jsonify({'error': 'Failed to start realtime tracer'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/realtime/disable', methods=['POST'])
    def disable_realtime_compat():
        try:
            realtime.disable()
            return jsonify({'status': 'disabled'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/realtime/stats', methods=['GET'])
    def get_realtime_stats_compat():
        try:
            stats = realtime.get_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/realtime/reset', methods=['POST'])
    def reset_realtime_stats_compat():
        try:
            realtime.reset_stats()
            return jsonify({'status': 'reset'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    print("[✓] Realtime API routes registered: /api/realtime/{enable,disable,stats,reset}")

# ============================================
# MAIN
# ============================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Realtime Packet Tracer Backend - Final Version')
    parser.add_argument('--port', '-p', type=int, default=5000,
                       help='Flask port (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Flask host (default: 0.0.0.0)')
    parser.add_argument('--auto-start', action='store_true',
                       help='Auto-start tracing on launch')
    parser.add_argument('--bpf-code', 
                       help='Path to BPF code')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        sys.exit(1)
    
    print(f"""
╔══════════════════════════════════════════════╗
║   Realtime Packet Tracer Backend v2.0        ║
║          FINAL VERSION - All Fixed           ║
╚══════════════════════════════════════════════╝

[*] Starting Flask-SocketIO server...
[*] Host: {args.host}
[*] Port: {args.port}
[*] WebSocket: ws://{args.host}:{args.port}/

[*] API Endpoints:
    OLD ROUTES (backward compatible):
    - POST /api/start
    - POST /api/stop
    - GET  /api/stats
    - POST /api/reset
    
    NEW ROUTES (realtime frontend):
    - POST /api/realtime/enable
    - POST /api/realtime/disable
    - GET  /api/realtime/stats
    - POST /api/realtime/reset

[*] Open browser at http://{args.host}:{args.port}/
[*] Press Ctrl+C to stop
""")
    
    if args.auto_start:
        print("[*] Auto-starting tracer...")
        global tracer
        tracer = RealtimeTracer(socketio, args.bpf_code)
        if tracer.start():
            print("[✓] Tracer auto-started")
        else:
            print("[✗] Failed to auto-start tracer")
    
    try:
        # FIX: Use allow_unsafe_werkzeug to prevent assertion errors
        socketio.run(
            app, 
            host=args.host, 
            port=args.port, 
            debug=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        if tracer:
            tracer.stop()

if __name__ == '__main__':
    main()