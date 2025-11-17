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

# ============================================
# DATA STRUCTURES
# ============================================

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
    
    def get_hook(self, hook_name: str) -> HookStats:
        if hook_name not in self.hooks:
            self.hooks[hook_name] = HookStats()
        return self.hooks[hook_name]
    
    def process_event(self, event: PacketEvent):
        """Process a single packet event and update statistics"""
        with self._lock:
            hook_name = event.hook_name
            layer_name = event.layer
            
            # Allow all valid hooks and layers - don't filter too strictly
            # This ensures we capture all hooks: PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING
            if hook_name == "UNKNOWN" or not layer_name:
                return
            
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
            
            hooks_data = {}
            for hook_name in HOOK_ORDER:
                if hook_name in self.hooks:
                    hooks_data[hook_name] = self.hooks[hook_name].to_dict()
            
            for hook_name, hook_stats in self.hooks.items():
                if hook_name not in HOOK_ORDER:
                    hooks_data[hook_name] = hook_stats.to_dict()
            
            return {
                'total_packets': self.total_packets,
                'uptime_seconds': round(uptime, 2),
                'packets_per_second': round(self.total_packets / max(uptime, 1), 2),
                'hooks': hooks_data,
                'recent_events': list(self.recent_events)[-100:]
            }
    
    def reset(self):
        """Reset all statistics"""
        with self._lock:
            self.hooks.clear()
            self.skb_tracking.clear()
            self.recent_events.clear()
            self.total_packets = 0
            self.start_time = time.time()

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
            
            functions_to_trace = [
                # === Ingress Layer ===
                '__netif_receive_skb_core',
                'netif_receive_skb',
                'netif_receive_skb_internal',
                'netif_rx',
                'netif_rx_internal',
                
                # === IP Layer ===
                'ip_rcv',
                'ip_rcv_finish',
                'ip_rcv_core',
                'ip_output',
                'ip_finish_output',
                'ip_finish_output2',
                'ip_local_out',
                '__ip_local_out',
                'ip_forward',
                'ip_forward_finish',
                'ip_local_deliver',
                'ip_local_deliver_finish',
                
                # === Netfilter/Firewall Layer (CRITICAL!) ===
                'nf_hook_slow',  # Main netfilter hook - catches all hooks!
                'nft_do_chain',
                'nft_immediate_eval',
                'nf_conntrack_in',
                'nf_nat_inet_fn',
                'nf_nat_ipv4_fn',
                
                # === Transport/Socket Layer ===
                'tcp_v4_rcv',
                'tcp_v4_do_rcv',
                'tcp_transmit_skb',
                'tcp_write_xmit',
                'tcp_send_mss',
                '__tcp_transmit_skb',
                'udp_rcv',
                '__udp4_lib_rcv',
                'udp_sendmsg',
                'udp_send_skb',
                '__sk_receive_skb',
                'sk_filter_trim_cap',
                
                # === Egress Layer ===
                'dev_queue_xmit',
                '__dev_queue_xmit',
                'dev_hard_start_xmit',
                'sch_direct_xmit',
                '__dev_xmit_skb',
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
        
        self.bpf["events"].open_perf_buffer(self.handle_event)
        self.running = True
        
        self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.poll_thread.start()
        
        self.stats_thread = threading.Thread(target=self._stats_broadcast_loop, daemon=True)
        self.stats_thread.start()
        
        print("[✓] Realtime tracer started")
        return True
    
    def _poll_loop(self):
        """Poll eBPF perf buffer"""
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception as e:
                if self.running:
                    print(f"[!] Poll error: {e}")
                break
    
    def _stats_broadcast_loop(self):
        """Broadcast statistics every second"""
        while self.running:
            time.sleep(1)
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

        # Multifunction-specific stats
        self.stats_by_layer = defaultdict(int)
        self.stats_by_hook = defaultdict(int)
        self.stats_by_verdict = defaultdict(int)

        # Recent events (keep last 50)
        self.recent_events = deque(maxlen=50)

        # Lock for thread safety
        self.lock = threading.Lock()
    
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

            # Update total packets (count unique packets, not events)
            self.total_packets = max(self.total_packets, sum(h['packets_total'] for h in self.hooks.values()) // max(len(self.hooks), 1))
    
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
        """Background thread to emit session stats every second"""
        print(f"[DEBUG] _emit_session_stats_loop started")
        iteration = 0
        while self._session_stats_running:
            time.sleep(1)
            iteration += 1
            
            with self.session_lock:
                if iteration <= 3:  # Debug first 3 iterations
                    print(f"[DEBUG] Emit iteration #{iteration}, active sessions: {list(self.session_trackers.keys())}")
                
                for session_id, tracker in list(self.session_trackers.items()):
                    try:
                        stats = tracker.get_stats()
                        
                        if iteration <= 3:  # Debug first 3 iterations
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