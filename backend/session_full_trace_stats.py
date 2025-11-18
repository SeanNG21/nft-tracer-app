#!/usr/bin/env python3
"""
Session Full Trace Stats Backend
Xử lý realtime stats cho từng session trace (độc lập với global realtime)
"""

import time
import threading
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

# Import constants và functions từ realtime_extension để tái sử dụng
from realtime_extension import (
    HOOK_MAP, HOOK_ORDER, LAYER_MAP, HOOK_LAYER_MAP, LAYER_ORDER,
    VERDICT_MAP, ERROR_MAP, PROTO_MAP, FUNCTION_TO_LAYER,
    refine_layer_by_hook, detect_packet_direction_new,
    NodeStats, EdgeStats, PipelineStats, PacketEvent
)

# ============================================
# SESSION STATS TRACKER
# ============================================

class SessionStatsTracker:
    """
    Track realtime statistics for a single trace session
    Similar to RealtimeExtension but session-specific
    """
    def __init__(self, session_id: str, mode: str):
        self.session_id = session_id
        self.mode = mode  # 'full', 'nft', etc.
        self.start_time = time.time()

        # Core stats
        self.total_packets = 0
        self.total_events = 0
        self._lock = threading.Lock()

        # Hook-based stats (for 'nft' mode)
        self.hooks: Dict[str, 'HookStats'] = {}

        # Node-based stats (for 'full' mode)
        self.nodes: Dict[str, NodeStats] = {}
        self.edges: List[EdgeStats] = []
        self.edge_map: Dict[tuple, EdgeStats] = {}  # (from, to) -> EdgeStats

        # Pipeline stats (for 'full' mode)
        self.pipelines: Dict[str, PipelineStats] = {
            'Inbound': PipelineStats(active_nodes=self._get_inbound_nodes()),
            'Outbound': PipelineStats(active_nodes=self._get_outbound_nodes()),
            'Local Delivery': PipelineStats(active_nodes=self._get_local_delivery_nodes()),
            'Forward': PipelineStats(active_nodes=self._get_forward_nodes()),
        }

        # SKB tracking
        self.skb_tracking: Dict[str, Dict] = {}  # skb_addr -> {first_ts, last_ts}
        self.skb_paths: Dict[str, List[str]] = {}  # skb_addr -> [node1, node2, ...]

        # Direction-layer stats
        self.stats_by_direction_layer: Dict[str, Dict[str, int]] = {
            'Inbound': defaultdict(int),
            'Outbound': defaultdict(int)
        }

        # Verdict tracking
        self.total_verdicts: Dict[str, int] = defaultdict(int)

    def _get_inbound_nodes(self) -> set:
        """Get all nodes that belong to Inbound pipeline"""
        return {
            'NIC', 'Driver (NAPI)', 'GRO', 'TC Ingress',
            'Netfilter PREROUTING', 'Conntrack', 'NAT PREROUTING',
            'Routing Decision', 'Local Delivery', 'Netfilter INPUT'
        }

    def _get_outbound_nodes(self) -> set:
        """Get all nodes that belong to Outbound pipeline"""
        return {
            'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
            'Routing Lookup', 'NAT', 'TC Egress', 'Driver TX'
        }

    def _get_local_delivery_nodes(self) -> set:
        """Get nodes for Local Delivery branch"""
        return {'Local Delivery', 'Netfilter INPUT', 'TCP/UDP', 'Socket'}

    def _get_forward_nodes(self) -> set:
        """Get nodes for Forward branch"""
        return {'Forward', 'Netfilter FORWARD', 'Netfilter POSTROUTING'}

    def get_node(self, name: str) -> NodeStats:
        """Get or create a node"""
        if name not in self.nodes:
            self.nodes[name] = NodeStats()
        return self.nodes[name]

    def get_hook(self, name: str) -> 'HookStats':
        """Get or create a hook"""
        if name not in self.hooks:
            self.hooks[name] = HookStats(name)
        return self.hooks[name]

    def add_edge(self, from_node: str, to_node: str):
        """Track edge between nodes"""
        key = (from_node, to_node)
        if key not in self.edge_map:
            edge = EdgeStats(from_node=from_node, to_node=to_node, count=0)
            self.edge_map[key] = edge
            self.edges.append(edge)
        self.edge_map[key].count += 1

    def _detect_direction(self, hook_name: str, layer_name: str, func_name: str, hook: int) -> str:
        """Detect packet direction"""
        return detect_packet_direction_new(func_name, layer_name, hook)

    def _map_to_pipeline_layer(self, layer_name: str, func_name: str, hook: int) -> str:
        """Map layer to pipeline node name"""
        # Try function mapping first
        if func_name and func_name in FUNCTION_TO_LAYER:
            base_layer = FUNCTION_TO_LAYER[func_name]
            return refine_layer_by_hook(func_name, base_layer, hook)

        # Use layer name with refinement
        return refine_layer_by_hook(func_name or '', layer_name, hook)

    def _track_pipeline_membership(self, skb_addr: str, node_name: str):
        """Track which pipelines this SKB has entered"""
        for pipeline_name, pipeline_stats in self.pipelines.items():
            if node_name in pipeline_stats.active_nodes:
                pipeline_stats.unique_skbs.add(skb_addr)

    def process_event(self, event: PacketEvent):
        """Process a single packet event"""
        with self._lock:
            hook_name = event.hook_name
            layer_name = event.layer

            if hook_name == "UNKNOWN" or not layer_name:
                return

            self.total_events += 1

            if self.mode == 'full':
                # Full mode: track nodes and pipelines
                hook = event.hook if event.hook != 255 else 0
                direction = self._detect_direction(hook_name, layer_name, event.function or '', hook)
                pipeline_layer = self._map_to_pipeline_layer(layer_name, event.function or '', hook)
                self.stats_by_direction_layer[direction][pipeline_layer] += 1

                # Get or create node
                node = self.get_node(pipeline_layer)

                # Calculate latency
                latency_us = 0.0
                if event.skb_addr and event.skb_addr in self.skb_tracking:
                    first_ts = self.skb_tracking[event.skb_addr]['first_ts']
                    latency_us = (event.timestamp - first_ts) * 1_000_000

                # Track verdict (with deduplication)
                verdict_to_count = None
                if event.verdict_name and event.verdict_name != 'UNKNOWN':
                    is_netfilter = any(kw in (event.function or '').lower()
                                      for kw in ['nf_', 'nft_', 'netfilter'])
                    if is_netfilter and event.skb_addr:
                        if not hasattr(node, 'counted_verdicts'):
                            node.counted_verdicts = set()

                        verdict_key = (event.skb_addr, event.verdict_name)
                        if verdict_key not in node.counted_verdicts:
                            verdict_to_count = event.verdict_name
                            node.counted_verdicts.add(verdict_key)
                            self.total_verdicts[event.verdict_name] += 1

                            # Cleanup
                            if len(node.counted_verdicts) > 10000:
                                old_entries = list(node.counted_verdicts)[:2000]
                                for entry in old_entries:
                                    node.counted_verdicts.discard(entry)

                # Add event to node
                node.add_event(
                    skb_addr=event.skb_addr or '',
                    latency_us=latency_us,
                    function=event.function,
                    verdict=verdict_to_count,
                    error=(event.error_code > 0)
                )

                # Track edges and in-flight packets
                if event.skb_addr:
                    if event.skb_addr not in self.skb_paths:
                        self.skb_paths[event.skb_addr] = []
                        self.skb_tracking[event.skb_addr] = {
                            'first_ts': event.timestamp,
                            'last_ts': event.timestamp
                        }
                    else:
                        self.skb_tracking[event.skb_addr]['last_ts'] = event.timestamp

                    # Track edge from previous node
                    if self.skb_paths[event.skb_addr]:
                        prev_node = self.skb_paths[event.skb_addr][-1]
                        if prev_node != pipeline_layer:
                            self.add_edge(prev_node, pipeline_layer)
                            prev_node_stats = self.get_node(prev_node)
                            prev_node_stats.in_flight_packets.discard(event.skb_addr)

                    # Add to current node's in-flight
                    node.in_flight_packets.add(event.skb_addr)
                    self.skb_paths[event.skb_addr].append(pipeline_layer)

                    # Track pipeline membership
                    self._track_pipeline_membership(event.skb_addr, pipeline_layer)

                    # Cleanup old paths
                    if len(self.skb_paths) > 10000:
                        oldest_keys = list(self.skb_paths.keys())[:1000]
                        for key in oldest_keys:
                            for node_stats in self.nodes.values():
                                node_stats.in_flight_packets.discard(key)
                            del self.skb_paths[key]
                            if key in self.skb_tracking:
                                del self.skb_tracking[key]

                self.total_packets += 1

            else:
                # NFT mode: track hooks and layers
                hook_stats = self.get_hook(hook_name)
                hook_stats.packets_total += 1
                self.total_packets += 1

                layer_stats = hook_stats.get_layer(layer_name)
                layer_stats.packets_in += 1

                if event.verdict_name and event.verdict_name != 'UNKNOWN':
                    layer_stats.verdict_breakdown[event.verdict_name] += 1
                    if event.verdict_name == 'DROP':
                        layer_stats.packets_dropped += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        with self._lock:
            uptime = time.time() - self.start_time
            packets_per_second = self.total_packets / uptime if uptime > 0 else 0

            stats = {
                'session_id': self.session_id,
                'mode': self.mode,
                'total_packets': self.total_packets,
                'total_events': self.total_events,
                'packets_per_second': packets_per_second,
                'uptime_seconds': uptime,
                'start_time': datetime.fromtimestamp(self.start_time).isoformat()
            }

            if self.mode == 'full':
                # Add node stats
                current_ts = time.time()
                stats['nodes'] = {
                    name: node.to_dict(current_ts)
                    for name, node in self.nodes.items()
                    if node.count > 0
                }

                # Add edge stats
                stats['edges'] = [
                    edge.to_dict()
                    for edge in self.edges
                    if edge.count > 0
                ]

                # Add pipeline stats
                stats['pipelines'] = [
                    {
                        'name': name,
                        **pipeline.to_dict(self.nodes)
                    }
                    for name, pipeline in self.pipelines.items()
                ]

                # Add verdict stats
                if self.total_verdicts:
                    stats['total_verdicts'] = dict(self.total_verdicts)

                # Add top latency contributors
                latency_list = []
                for node_name, node in self.nodes.items():
                    if node.latencies_us:
                        avg_latency = sum(node.latencies_us) / len(node.latencies_us)
                        latency_list.append({
                            'node': node_name,
                            'avg_latency_us': avg_latency,
                            'count': len(node.latencies_us)
                        })

                latency_list.sort(key=lambda x: x['avg_latency_us'], reverse=True)
                stats['top_latency'] = latency_list[:10]

            else:
                # Add hook stats for nft mode
                stats['hooks'] = {
                    name: hook.to_dict()
                    for name, hook in self.hooks.items()
                    if hook.packets_total > 0
                }

            return stats


@dataclass
class HookStats:
    """Statistics for a single netfilter hook (NFT mode)"""
    name: str
    packets_total: int = 0
    layers: Dict[str, 'LayerStats'] = field(default_factory=dict)

    def get_layer(self, layer_name: str) -> 'LayerStats':
        """Get or create layer stats"""
        if layer_name not in self.layers:
            self.layers[layer_name] = LayerStats(layer_name)
        return self.layers[layer_name]

    def to_dict(self) -> Dict:
        return {
            'packets_total': self.packets_total,
            'layers': {
                name: layer.to_dict()
                for name, layer in self.layers.items()
            }
        }


@dataclass
class LayerStats:
    """Statistics for a layer within a hook"""
    name: str
    packets_in: int = 0
    packets_dropped: int = 0
    verdict_breakdown: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def to_dict(self) -> Dict:
        drop_rate = (self.packets_dropped / self.packets_in * 100) if self.packets_in > 0 else 0
        return {
            'packets_in': self.packets_in,
            'drop_rate': drop_rate,
            'verdict_breakdown': dict(self.verdict_breakdown) if self.verdict_breakdown else {}
        }


# ============================================
# SESSION MANAGER FOR WEBSOCKET
# ============================================

class SessionFullTraceStatsManager:
    """
    Manages stats tracking for multiple sessions
    Integrates with Flask-SocketIO
    """
    def __init__(self, socketio):
        self.socketio = socketio
        self.session_trackers: Dict[str, SessionStatsTracker] = {}
        self._lock = threading.Lock()
        self._emitter_thread = None
        self._running = False

        self._setup_handlers()

    def _setup_handlers(self):
        """Setup WebSocket handlers"""
        @self.socketio.on('join_full_trace_session')
        def handle_join(data):
            from flask_socketio import join_room, emit
            session_id = data.get('session_id')
            if session_id:
                join_room(f"full_trace_{session_id}")
                print(f"[SessionFullTrace] Client joined room: full_trace_{session_id}")
                emit('joined_full_trace_session', {'session_id': session_id})

        @self.socketio.on('leave_full_trace_session')
        def handle_leave(data):
            from flask_socketio import leave_room
            session_id = data.get('session_id')
            if session_id:
                leave_room(f"full_trace_{session_id}")
                print(f"[SessionFullTrace] Client left room: full_trace_{session_id}")

    def start_tracking(self, session_id: str, mode: str):
        """Start tracking stats for a session"""
        with self._lock:
            if session_id not in self.session_trackers:
                self.session_trackers[session_id] = SessionStatsTracker(session_id, mode)
                print(f"[SessionFullTrace] Started tracking for session: {session_id} (mode: {mode})")

                # Start emitter thread if not running
                if not self._running:
                    self._running = True
                    self._emitter_thread = threading.Thread(
                        target=self._emit_stats_loop,
                        daemon=True
                    )
                    self._emitter_thread.start()

    def stop_tracking(self, session_id: str):
        """Stop tracking stats for a session"""
        with self._lock:
            if session_id in self.session_trackers:
                del self.session_trackers[session_id]
                print(f"[SessionFullTrace] Stopped tracking for session: {session_id}")

                # Stop emitter thread if no more sessions
                if not self.session_trackers and self._running:
                    self._running = False

    def process_event(self, session_id: str, event_data: Dict):
        """Process an event for a session"""
        with self._lock:
            if session_id in self.session_trackers:
                # Convert event_data to PacketEvent
                event = self._dict_to_packet_event(event_data)
                self.session_trackers[session_id].process_event(event)

    def _dict_to_packet_event(self, data: Dict) -> PacketEvent:
        """Convert dict to PacketEvent"""
        hook = data.get('hook', 255)
        verdict = data.get('verdict', 0)
        error_code = data.get('error_code', 0)
        protocol = data.get('protocol', 0)

        # Determine layer from function
        func_name = data.get('func_name', '')
        layer = 'Unknown'
        for layer_name, funcs in LAYER_MAP.items():
            if func_name in funcs:
                layer = layer_name
                break

        return PacketEvent(
            timestamp=data.get('timestamp', time.time()),
            skb_addr=data.get('skb_addr', ''),
            cpu_id=data.get('cpu_id', 0),
            pid=data.get('pid', 0),
            event_type=data.get('event_type', 0),
            hook=hook,
            hook_name=HOOK_MAP.get(hook, 'UNKNOWN'),
            pf=data.get('pf', 2),
            protocol=protocol,
            protocol_name=PROTO_MAP.get(protocol, f'PROTO_{protocol}'),
            src_ip=data.get('src_ip', ''),
            dst_ip=data.get('dst_ip', ''),
            src_port=data.get('src_port', 0),
            dst_port=data.get('dst_port', 0),
            length=data.get('length', 0),
            verdict=verdict,
            verdict_name=VERDICT_MAP.get(verdict, 'UNKNOWN'),
            error_code=error_code,
            error_name=ERROR_MAP.get(error_code, 'NONE'),
            function=func_name,
            layer=layer,
            comm=data.get('comm', '')
        )

    def _emit_stats_loop(self):
        """Emit stats periodically to WebSocket clients"""
        iteration = 0
        while self._running:
            try:
                time.sleep(1)  # Emit every 1 second
                iteration += 1

                with self._lock:
                    for session_id, tracker in list(self.session_trackers.items()):
                        try:
                            stats = tracker.get_stats()

                            if iteration <= 3:
                                print(f"[SessionFullTrace] Emitting stats for {session_id}: "
                                      f"packets={stats['total_packets']}, events={stats['total_events']}")

                            # Emit to session-specific room
                            self.socketio.emit('full_trace_stats_update', {
                                'session_id': session_id,
                                'stats': stats
                            }, room=f"full_trace_{session_id}")

                        except Exception as e:
                            print(f"[Error] Failed to emit stats for {session_id}: {e}")

            except Exception as e:
                print(f"[Error] Stats emitter loop error: {e}")

        print("[SessionFullTrace] Stats emitter thread stopped")


# ============================================
# FLASK ROUTES
# ============================================

def add_session_full_trace_routes(app, manager: SessionFullTraceStatsManager):
    """Add Flask routes for session full trace stats"""
    from flask import jsonify

    @app.route('/api/session-full-trace-stats/<session_id>', methods=['GET'])
    def get_session_stats(session_id):
        """Get current stats for a session"""
        with manager._lock:
            if session_id in manager.session_trackers:
                stats = manager.session_trackers[session_id].get_stats()
                return jsonify(stats)
            else:
                return jsonify({'error': 'Session not found'}), 404

    @app.route('/api/session-full-trace-stats/health', methods=['GET'])
    def health():
        """Health check"""
        with manager._lock:
            return jsonify({
                'status': 'ok',
                'active_sessions': len(manager.session_trackers),
                'session_ids': list(manager.session_trackers.keys())
            })
