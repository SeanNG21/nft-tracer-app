#!/usr/bin/env python3
"""
Unified Packet Tracing Backend - FULL MODE + REALTIME VISUALIZATION
Trace đường đi packet qua kernel + verdict từ nftables + Realtime WebSocket
COMPLETE VERSION - Tích hợp với realtime_extension.py
"""

import os
import sys
import json
import time
import threading
import socket
import platform
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import psutil

from btf_skb_discoverer import BTFSKBDiscoverer

try:
    from nft_ruleset_parser import get_ruleset_parser
    NFT_PARSER_AVAILABLE = True
except ImportError as e:
    NFT_PARSER_AVAILABLE = False
    print(f"WARNING: NFT ruleset parser not available: {e}")

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    print("WARNING: BCC not available - Install: pip3 install bcc")

app = Flask(__name__)
CORS(app)

# ============================================================================
# REALTIME INTEGRATION - SETUP
# ============================================================================
try:
    from flask_socketio import SocketIO
    from realtime_extension import RealtimeExtension, add_realtime_routes
    
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', 
                       logger=False, engineio_logger=False)
    realtime = RealtimeExtension(app, socketio)
    add_realtime_routes(app, realtime)
    
    REALTIME_AVAILABLE = True
    print("[✓] Realtime visualization module loaded")
except ImportError as e:
    REALTIME_AVAILABLE = False
    socketio = None
    realtime = None
    print(f"[!] Realtime not available: {e}")
    print("[!] Install: pip3 install flask-socketio python-socketio")

# ============================================================================
# CONFIGURATION
# ============================================================================
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
NFT_TRACER_PATH = os.path.join(os.path.dirname(__file__), "nft_tracer.bpf.c")
FULL_TRACER_PATH = os.path.join(os.path.dirname(__file__), "full_tracer.bpf.c")
FUNCTIONS_CACHE = os.path.join(os.path.dirname(__file__), "skb_functions.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# CRITICAL_FUNCTIONS: LUÔN được trace trong FULL mode
CRITICAL_FUNCTIONS = [
    # Network device layer
    'netif_receive_skb', '__netif_receive_skb_core', 'netif_receive_skb_internal',
    # IP layer
    'ip_rcv', 'ip_rcv_core', 'ip_rcv_finish', 
    'ip_local_deliver', 'ip_local_deliver_finish',
    'ip_forward', 'ip_forward_finish',
    # Transport layer
    'tcp_v4_rcv', 'tcp_v4_do_rcv', 'udp_rcv', 'udp_unicast_rcv_skb',
    # Netfilter hooks
    'nf_hook_slow', 'nf_conntrack_in',
    # Output path
    'ip_output', 'ip_finish_output', 'ip_local_out', '__ip_local_out',
]

# BLACKLIST_FUNCTIONS: Không trace (internal/utility)
BLACKLIST_PATTERNS = [
    'nf_getsockopt', 'nf_setsockopt', 'nf_hook_entries_', 'nf_hook_direct_',
    'nf_register_', 'nf_unregister_', 'nf_log_', 'nf_queue_', '__nf_hook_',
    'nf_ct_', 'nf_nat_', 'nf_tables_',
]

def is_blacklisted(func_name: str) -> bool:
    """Check if function name matches blacklist patterns"""
    for pattern in BLACKLIST_PATTERNS:
        if pattern in func_name:
            return True
    return False

# ============================================================================
# KALLSYMS HELPER - Function name lookup from IP
# ============================================================================
class KallsymsLookup:
    """Fast kallsyms IP -> function name lookup"""
    
    def __init__(self):
        self.symbols: Dict[int, str] = {}
        self.sorted_addrs: List[int] = []
        self._load_kallsyms()
    
    def _load_kallsyms(self):
        """Load /proc/kallsyms into memory"""
        print("[*] Loading kallsyms...")
        count = 0
        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        addr_str, sym_type, name = parts[0], parts[1], parts[2]
                        if sym_type in ['T', 't']:
                            try:
                                addr = int(addr_str, 16)
                                if addr > 0:
                                    self.symbols[addr] = name
                                    count += 1
                            except ValueError:
                                continue
            
            self.sorted_addrs = sorted(self.symbols.keys())
            print(f"[✓] Loaded {count} kernel symbols")
        except Exception as e:
            print(f"[!] Failed to load kallsyms: {e}")
    
    def lookup(self, func_ip: int) -> Optional[str]:
        """Lookup function name from instruction pointer"""
        if not self.sorted_addrs or func_ip == 0:
            return None
        
        left, right = 0, len(self.sorted_addrs) - 1
        result_addr = None
        
        while left <= right:
            mid = (left + right) // 2
            addr = self.sorted_addrs[mid]
            
            if addr == func_ip:
                result_addr = addr
                break
            elif addr < func_ip:
                result_addr = addr
                left = mid + 1
            else:
                right = mid - 1
        
        if result_addr is not None:
            return self.symbols.get(result_addr)
        
        return None

kallsyms = KallsymsLookup()

# ============================================================================
# DATA STRUCTURES
# ============================================================================
@dataclass
class NFTEvent:
    """NFT trace event"""
    timestamp: int
    cpu_id: int
    pid: int
    skb_addr: int
    chain_addr: int
    expr_addr: int
    regs_addr: int
    hook: int
    chain_depth: int
    trace_type: int
    pf: int
    verdict: int
    verdict_raw: int
    queue_num: int
    rule_seq: int
    has_queue_bypass: int
    protocol: int
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    rule_handle: int
    comm: str
    
    @staticmethod
    def from_bpf_event(event):
        return NFTEvent(
            timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
            skb_addr=event.skb_addr, chain_addr=event.chain_addr,
            expr_addr=event.expr_addr, regs_addr=event.regs_addr,
            hook=event.hook, chain_depth=event.chain_depth,
            trace_type=event.trace_type, pf=event.pf,
            verdict=event.verdict, verdict_raw=event.verdict_raw,
            queue_num=event.queue_num, rule_seq=event.rule_seq,
            has_queue_bypass=event.has_queue_bypass, protocol=event.protocol,
            src_ip=event.src_ip, dst_ip=event.dst_ip,
            src_port=event.src_port, dst_port=event.dst_port,
            rule_handle=event.rule_handle,
            comm=event.comm.decode('utf-8', errors='ignore')
        )

@dataclass
class UniversalEvent:
    """Universal trace event"""
    timestamp: int
    cpu_id: int
    pid: int
    skb_addr: int
    func_name: str
    protocol: int
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    length: int
    comm: str

@dataclass
class PacketTrace:
    """Complete packet trace - Đường đi + Verdict"""
    skb_addr: int
    first_seen: int
    last_seen: int
    events: List[Dict]
    
    # Packet info
    protocol: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    # NFT verdict info
    final_verdict: Optional[int] = None
    final_verdict_str: Optional[str] = None
    hook: Optional[int] = None
    total_rules_evaluated: int = 0
    verdict_changes: int = 0
    
    # Path info
    functions_called: List[str] = None
    unique_functions: int = 0
    
    mode: str = "full"
    
    def __post_init__(self):
        if self.functions_called is None:
            self.functions_called = []
    
    def add_universal_event(self, event: UniversalEvent):
        """Add function call event"""
        event_dict = {
            'timestamp': event.timestamp, 'trace_type': 'function_call',
            'function': event.func_name, 'cpu_id': event.cpu_id,
            'comm': event.comm, 'length': event.length
        }
        self.events.append(event_dict)
        self.last_seen = event.timestamp
        
        if event.func_name not in self.functions_called:
            self.functions_called.append(event.func_name)
            self.unique_functions = len(self.functions_called)
        
        if event.protocol > 0 and self.protocol is None:
            self.protocol = event.protocol
            self.src_ip = self._format_ip(event.src_ip)
            self.dst_ip = self._format_ip(event.dst_ip)
            self.src_port = event.src_port if event.src_port > 0 else None
            self.dst_port = event.dst_port if event.dst_port > 0 else None
    
    def add_nft_event(self, event: NFTEvent):
        """Add NFT rule evaluation event with deduplication support"""

        # FIX: Deduplicate events - check if same expr_addr within time window
        # This prevents logging the same expression evaluation multiple times
        #
        # DEDUP_WINDOW: 5 microseconds (5000 nanoseconds)
        # Rationale: Same expression evaluated within 5us is likely a duplicate
        # - Observed duplicate with 1079ns delta (exceeds 1us threshold)
        # - 5us is safe margin while still detecting real duplicates
        # - Normal different expressions have >10us separation
        DEDUP_WINDOW_NS = 5000  # 5 microseconds

        if event.expr_addr > 0:
            dedup_key = (event.skb_addr, event.expr_addr)

            if hasattr(self, '_last_expr_eval'):
                last_key, last_ts = self._last_expr_eval
                if (last_key == dedup_key and
                    abs(event.timestamp - last_ts) < DEDUP_WINDOW_NS):
                    # Same expression evaluated within window → duplicate!
                    # Skip to avoid duplicate logging
                    return

            self._last_expr_eval = (dedup_key, event.timestamp)

        event_dict = {
            'timestamp': event.timestamp,
            'trace_type': self._trace_type_str(event.trace_type),
            'verdict': self._verdict_str(event.verdict),
            'verdict_code': event.verdict,
            'verdict_raw': event.verdict_raw,  # FIX: Include raw verdict for debugging
            'rule_seq': event.rule_seq,
            'rule_handle': event.rule_handle,  # FIX: Always include, even if 0
            'expr_addr': hex(event.expr_addr) if event.expr_addr > 0 else None,  # FIX: Add expr_addr
            'chain_addr': hex(event.chain_addr) if event.chain_addr > 0 else None,  # FIX: Add chain_addr
            'chain_depth': event.chain_depth, 'cpu_id': event.cpu_id,
            'comm': event.comm, 'hook': event.hook, 'pf': event.pf
        }

        # Enrich with rule definition if available
        if NFT_PARSER_AVAILABLE and event.rule_handle > 0:
            try:
                parser = get_ruleset_parser()
                rule = parser.get_rule_by_handle(event.rule_handle)
                if rule:
                    event_dict['rule_text'] = rule.rule_text
                    event_dict['rule_table'] = rule.table
                    event_dict['rule_chain'] = rule.chain
                    event_dict['rule_family'] = rule.family
                else:
                    # Rule not found in ruleset - this is normal if rules changed
                    # after tracing started
                    if not hasattr(self, '_warned_handles'):
                        self._warned_handles = set()
                    if event.rule_handle not in self._warned_handles:
                        print(f"[DEBUG] Rule handle {event.rule_handle} not found in ruleset")
                        self._warned_handles.add(event.rule_handle)
            except Exception as e:
                # Log error for debugging
                print(f"[!] Error enriching rule handle {event.rule_handle}: {e}")
                import traceback
                traceback.print_exc()
        
        if len(self.events) > 0:
            for prev_event in reversed(self.events):
                if prev_event.get('trace_type') in ['chain_exit', 'rule_eval', 'hook_exit']:
                    if prev_event.get('verdict_code') != event.verdict:
                        self.verdict_changes += 1
                    break
        
        self.events.append(event_dict)
        self.last_seen = event.timestamp
        
        if event.protocol > 0 and self.protocol is None:
            self.protocol = event.protocol
            self.src_ip = self._format_ip(event.src_ip)
            self.dst_ip = self._format_ip(event.dst_ip)
            self.src_port = event.src_port if event.src_port > 0 else None
            self.dst_port = event.dst_port if event.dst_port > 0 else None
        
        if event.hook != 255 and self.hook is None:
            self.hook = event.hook
        
        if event.trace_type == 0:
            self.final_verdict = event.verdict
            self.final_verdict_str = self._verdict_str(event.verdict)
        
        if event.trace_type == 1:
            self.total_rules_evaluated += 1
    
    @staticmethod
    def _verdict_str(verdict: int) -> str:
        verdicts = {
            0: "DROP", 1: "ACCEPT", 2: "STOLEN", 3: "QUEUE",
            4: "REPEAT", 5: "STOP", 10: "CONTINUE", 11: "RETURN",
            12: "JUMP", 13: "GOTO", 14: "BREAK", 255: "UNKNOWN"
        }
        return verdicts.get(verdict, f"UNKNOWN_{verdict}")
    
    @staticmethod
    def _trace_type_str(trace_type: int) -> str:
        types = {0: "chain_exit", 1: "rule_eval", 2: "hook_exit"}
        return types.get(trace_type, f"unknown_{trace_type}")
    
    @staticmethod
    def _format_ip(ip: int) -> Optional[str]:
        if ip == 0:
            return None
        return socket.inet_ntoa(ip.to_bytes(4, byteorder='little'))
    
    def to_summary(self) -> Dict:
        """Export summary với full information"""
        sorted_events = sorted(self.events, key=lambda x: x['timestamp'])
        important_events = []
        function_events = []
        nft_events = []
        
        for event in sorted_events:
            trace_type = event.get('trace_type')
            if trace_type in ['chain_exit', 'rule_eval', 'hook_exit']:
                nft_events.append(event)
            elif trace_type == 'function_call':
                function_events.append(event)
        
        if len(function_events) > 0:
            important_events.extend(function_events[:3])
            if len(function_events) > 5:
                important_events.extend(function_events[-2:])
            elif len(function_events) > 3:
                important_events.extend(function_events[3:])
        
        for event in nft_events:
            if event.get('trace_type') == 'chain_exit':
                if event.get('chain_depth', 0) == 0:
                    important_events.append(event)
            else:
                important_events.append(event)
        
        important_events = sorted(important_events, key=lambda x: x['timestamp'])
        
        return {
            'skb_addr': hex(self.skb_addr) if self.skb_addr > 0 else f"synthetic_{self.skb_addr}",
            'first_seen': self.first_seen, 'last_seen': self.last_seen,
            'duration_ns': self.last_seen - self.first_seen,
            'protocol': self.protocol, 'protocol_name': self._protocol_name(self.protocol),
            'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
            'src_port': self.src_port, 'dst_port': self.dst_port,
            'functions_path': self.functions_called,
            'unique_functions': self.unique_functions,
            'total_functions_called': len(function_events),
            'hook': self.hook, 'hook_name': self._hook_name(self.hook),
            'final_verdict': self.final_verdict_str,
            'total_rules_evaluated': self.total_rules_evaluated,
            'verdict_changes': self.verdict_changes,
            'important_events': important_events,
            'all_events_count': len(sorted_events),
        }
    
    @staticmethod
    def _protocol_name(proto):
        if proto is None:
            return None
        protos = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protos.get(proto, f'PROTO_{proto}')
    
    @staticmethod
    def _hook_name(hook):
        if hook is None:
            return None
        hooks = {0: 'PREROUTING', 1: 'INPUT', 2: 'FORWARD', 3: 'OUTPUT', 4: 'POSTROUTING'}
        return hooks.get(hook, f'HOOK_{hook}')

# ============================================================================
# UNIVERSAL BPF PROGRAM
# ============================================================================
UNIVERSAL_BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct trace_event_t {
    u64 timestamp;
    u64 skb_addr;
    u32 cpu_id;
    u32 pid;
    u32 func_id;
    u64 func_ip;
    char func_name[64];
    u8 protocol;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 len;
    char comm[16];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(skb_tracking, u64, u64, 10240);

static inline void extract_packet_info(struct sk_buff *skb, struct trace_event_t *evt) {
    if (!skb) return;
    evt->skb_addr = (u64)skb;
    unsigned char *head;
    u16 network_header, transport_header;
    u32 len;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);
    bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
    evt->len = len;
    if (network_header == 0xFFFF || network_header > 4096) return;
    struct iphdr *ip = (struct iphdr *)(head + network_header);
    u8 protocol;
    u32 saddr, daddr;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip->protocol);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &ip->saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &ip->daddr);
    evt->protocol = protocol;
    evt->saddr = saddr;
    evt->daddr = daddr;
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        if (transport_header != 0xFFFF && transport_header < 4096) {
            u16 *ports = (u16 *)(head + transport_header);
            u16 sport, dport;
            bpf_probe_read_kernel(&sport, sizeof(sport), &ports[0]);
            bpf_probe_read_kernel(&dport, sizeof(dport), &ports[1]);
            evt->sport = bpf_ntohs(sport);
            evt->dport = bpf_ntohs(dport);
        }
    }
}

int trace_skb_func(struct pt_regs *ctx, struct sk_buff *skb) {
    struct trace_event_t evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.func_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.func_ip = PT_REGS_IP(ctx);
    extract_packet_info(skb, &evt);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    if (evt.skb_addr != 0) {
        u64 count = 0;
        u64 *val = skb_tracking.lookup(&evt.skb_addr);
        if (val) count = *val;
        count++;
        skb_tracking.update(&evt.skb_addr, &count);
    }
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

# ============================================================================
# TRACE SESSION
# ============================================================================
class TraceSession:
    """Manages trace session - supports nft, universal, full modes"""
    
    def __init__(self, session_id: str, mode: str = "nft", pcap_filter: str = "", 
                 max_functions: int = 30):
        self.session_id = session_id
        self.mode = mode
        self.pcap_filter = pcap_filter
        self.max_functions = max_functions
        self.start_time = datetime.now()
        self.end_time = None
        self.running = False
        self.bpf_nft = None
        self.bpf_universal = None
        self.bpf_full = None
        self.thread = None
        
        self.packet_traces: Dict[int, PacketTrace] = {}
        self.completed_traces: List[PacketTrace] = []
        self.lock = threading.Lock()
        
        self.total_events = 0
        self.events_per_second = 0
        self.last_stats_time = time.time()
        self.last_event_count = 0
        
        self.hostname = socket.gethostname()
        self.kernel_version = platform.release()
        self.cpu_count = psutil.cpu_count()
        
        self.synthetic_id_counter = -1
        self.skb_zero_count = 0
        
        self.functions = []
        self.func_id_to_name = {}
        self.events_by_func = defaultdict(int)
        
        self.trace_timeout_ns = 5 * 1_000_000_000
        
        print(f"[DEBUG] Session {session_id} created in {mode.upper()} mode")
    
    def start(self) -> bool:
        if not BCC_AVAILABLE:
            return False
        
        try:
            if self.mode == 'nft':
                return self._start_nft_only()
            elif self.mode == 'universal':
                return self._start_universal_only()
            elif self.mode == 'full':
                return self._start_full_mode()
            else:
                print(f"[ERROR] Unknown mode: {self.mode}")
                return False
                
        except Exception as e:
            print(f"[ERROR] Starting session: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _start_nft_only(self) -> bool:
        with open(NFT_TRACER_PATH, 'r') as f:
            bpf_code = f.read()
        self.bpf_nft = BPF(text=bpf_code)
        self.bpf_nft.attach_kprobe(event="nft_do_chain", fn_name="kprobe__nft_do_chain")
        self.bpf_nft.attach_kretprobe(event="nft_do_chain", fn_name="kretprobe__nft_do_chain")
        self.bpf_nft.attach_kprobe(event="nft_immediate_eval", fn_name="kprobe__nft_immediate_eval")
        self.bpf_nft.attach_kretprobe(event="nf_hook_slow", fn_name="kretprobe__nf_hook_slow")
        self.bpf_nft["events"].open_perf_buffer(self._handle_nft_event)
        self.running = True
        self.thread = threading.Thread(target=self._poll_nft_events)
        self.thread.daemon = True
        self.thread.start()
        print(f"[✓] NFT mode started")
        return True
    
    def _start_universal_only(self) -> bool:
        return self._start_universal_tracer()
    
    def _start_full_mode(self) -> bool:
        print("[*] Starting FULL mode (Integrated: Functions + NFT verdicts)...")
        
        functions_to_trace = []
        critical_filtered = [f for f in CRITICAL_FUNCTIONS if not is_blacklisted(f)]
        print(f"[*] Priority: {len(critical_filtered)} critical path functions")
        functions_to_trace.extend(critical_filtered)
        
        remaining_slots = self.max_functions - len(critical_filtered)
        if remaining_slots > 0 and os.path.exists(FUNCTIONS_CACHE):
            print(f"[*] Adding {remaining_slots} additional discovered functions...")
            with open(FUNCTIONS_CACHE, 'r') as f:
                data = json.load(f)
                all_funcs = data.get('functions', [])
                sorted_funcs = sorted(all_funcs, key=lambda x: (x['priority'], x['name']))
                
                for func in sorted_funcs:
                    func_name = func['name']
                    if func_name in functions_to_trace:
                        continue
                    if is_blacklisted(func_name):
                        continue
                    functions_to_trace.append(func_name)
                    if len(functions_to_trace) >= self.max_functions:
                        break
        
        self.functions = functions_to_trace
        print(f"[*] Total functions to trace: {len(self.functions)}")
        
        with open(FULL_TRACER_PATH, 'r') as f:
            bpf_code = f.read()
        
        self.bpf_full = BPF(text=bpf_code)
        
        print("[*] Attaching NFT hooks...")
        try:
            self.bpf_full.attach_kprobe(event="nft_do_chain", fn_name="kprobe__nft_do_chain")
            self.bpf_full.attach_kretprobe(event="nft_do_chain", fn_name="kretprobe__nft_do_chain")
            self.bpf_full.attach_kprobe(event="nft_immediate_eval", fn_name="kprobe__nft_immediate_eval")
            self.bpf_full.attach_kretprobe(event="nf_hook_slow", fn_name="kretprobe__nf_hook_slow")
            print("[✓] NFT hooks attached")
        except Exception as e:
            print(f"[!] Warning: NFT hooks failed - {e}")
        
        print("[*] Attaching packet path functions...")
        attached_critical = 0
        attached_additional = 0
        
        for func_name in self.functions:
            try:
                self.bpf_full.attach_kprobe(event=func_name, fn_name="trace_skb_func")
                if func_name in critical_filtered:
                    attached_critical += 1
                else:
                    attached_additional += 1
            except:
                pass
        
        print(f"[✓] Attached {attached_critical}/{len(critical_filtered)} critical functions")
        print(f"[✓] Attached {attached_additional} additional functions")
        
        self.bpf_full["events"].open_perf_buffer(self._handle_full_event)
        
        self.running = True
        self.thread = threading.Thread(target=self._poll_full_events)
        self.thread.daemon = True
        self.thread.start()
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_traces)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        print("[✓] FULL MODE READY!")
        return True
    
    def _start_universal_tracer(self) -> bool:
        if os.path.exists(FUNCTIONS_CACHE):
            with open(FUNCTIONS_CACHE, 'r') as f:
                data = json.load(f)
            all_funcs = data.get('functions', [])
            sorted_funcs = sorted(all_funcs, key=lambda x: (x['priority'], x['name']))
            self.functions = [f['name'] for f in sorted_funcs if not is_blacklisted(f['name'])][:self.max_functions]
        else:
            discoverer = BTFSKBDiscoverer()
            discovered = discoverer.discover_from_btf()
            discoverer.export_json(FUNCTIONS_CACHE)
            self.functions = [f.name for f in discovered if not is_blacklisted(f.name)][:self.max_functions]
        
        print(f"[*] Loading {len(self.functions)} functions")
        self.bpf_universal = BPF(text=UNIVERSAL_BPF_PROGRAM)
        
        attached = 0
        for i, func_name in enumerate(self.functions):
            try:
                self.bpf_universal.attach_kprobe(event=func_name, fn_name="trace_skb_func")
                self.func_id_to_name[i] = func_name
                attached += 1
            except:
                pass
        
        print(f"[✓] Attached {attached}/{len(self.functions)} functions")
        
        if self.mode == 'universal':
            self.bpf_universal["events"].open_perf_buffer(self._handle_universal_event)
            self.running = True
            self.thread = threading.Thread(target=self._poll_universal_events)
            self.thread.daemon = True
            self.thread.start()
            self.cleanup_thread = threading.Thread(target=self._cleanup_old_traces)
            self.cleanup_thread.daemon = True
            self.cleanup_thread.start()
            print(f"[✓] Universal mode started")
        
        return True
    
    def stop(self) -> str:
        self.running = False
        self.end_time = datetime.now()
        
        if hasattr(self, 'thread') and self.thread:
            self.thread.join(timeout=2.0)
        
        with self.lock:
            for skb_addr, trace in self.packet_traces.items():
                self.completed_traces.append(trace)
            self.packet_traces.clear()
        
        output_path = self._export_json()
        
        if self.bpf_nft:
            try:
                self.bpf_nft.cleanup()
            except:
                pass
        
        if self.bpf_universal:
            try:
                self.bpf_universal.cleanup()
            except:
                pass
        
        if hasattr(self, 'bpf_full') and self.bpf_full:
            try:
                self.bpf_full.cleanup()
            except:
                pass
        
        return output_path
    
    def _poll_nft_events(self):
        while self.running:
            try:
                self.bpf_nft.perf_buffer_poll(timeout=100)
            except Exception as e:
                if self.running:
                    print(f"[ERROR] NFT polling: {e}")
                break
    
    def _poll_universal_events(self):
        while self.running:
            try:
                self.bpf_universal.perf_buffer_poll(timeout=100)
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Universal polling: {e}")
                break
    
    def _poll_full_events(self):
        while self.running:
            try:
                self.bpf_full.perf_buffer_poll(timeout=100)
            except Exception as e:
                if self.running:
                    print(f"[ERROR] FULL mode polling: {e}")
                break
    
    def _cleanup_old_traces(self):
        while self.running:
            time.sleep(2)
            now = time.time_ns()
            to_complete = []
            
            with self.lock:
                for skb_addr, trace in list(self.packet_traces.items()):
                    if now - trace.last_seen > self.trace_timeout_ns:
                        to_complete.append(skb_addr)
                
                for skb_addr in to_complete:
                    trace = self.packet_traces.pop(skb_addr)
                    self.completed_traces.append(trace)
    
    def _handle_nft_event(self, cpu, data, size):
        event = self.bpf_nft["events"].event(data)
        nft_event = NFTEvent.from_bpf_event(event)
        
        with self.lock:
            self.total_events += 1
            self._update_stats()
            
            skb_addr = self._get_skb_addr(nft_event.skb_addr, nft_event.chain_addr)
            
            if skb_addr not in self.packet_traces:
                self.packet_traces[skb_addr] = PacketTrace(
                    skb_addr=skb_addr, first_seen=nft_event.timestamp,
                    last_seen=nft_event.timestamp, events=[], mode="nft"
                )
            
            trace = self.packet_traces[skb_addr]
            trace.add_nft_event(nft_event)
            
            if nft_event.trace_type == 0:
                if nft_event.verdict in [0, 1]:
                    self.completed_traces.append(trace)
                    del self.packet_traces[skb_addr]
    
    def _handle_full_event(self, cpu, data, size):
        """Handle FULL mode event + REALTIME INTEGRATION"""
        import ctypes as ct
        
        class FullEvent(ct.Structure):
            _fields_ = [
                ("timestamp", ct.c_ulonglong), ("skb_addr", ct.c_ulonglong),
                ("cpu_id", ct.c_uint), ("pid", ct.c_uint),
                ("event_type", ct.c_ubyte), ("hook", ct.c_ubyte),
                ("pf", ct.c_ubyte), ("protocol", ct.c_ubyte),
                ("src_ip", ct.c_uint), ("dst_ip", ct.c_uint),
                ("src_port", ct.c_ushort), ("dst_port", ct.c_ushort),
                ("length", ct.c_uint), ("chain_addr", ct.c_ulonglong),
                ("expr_addr", ct.c_ulonglong), ("chain_depth", ct.c_ubyte),
                ("rule_seq", ct.c_ushort), ("rule_handle", ct.c_ulonglong),
                ("verdict_raw", ct.c_int), ("verdict", ct.c_uint),
                ("queue_num", ct.c_ushort), ("has_queue_bypass", ct.c_ubyte),
                ("func_ip", ct.c_ulonglong), ("function_name", ct.c_char * 64),
                ("comm", ct.c_char * 16),
            ]
        
        event = ct.cast(data, ct.POINTER(FullEvent)).contents
        
        with self.lock:
            self.total_events += 1
            self._update_stats()
            
            skb_addr = event.skb_addr if event.skb_addr != 0 else event.chain_addr
            if skb_addr == 0:
                return
            
            if skb_addr not in self.packet_traces:
                self.packet_traces[skb_addr] = PacketTrace(
                    skb_addr=skb_addr, first_seen=event.timestamp,
                    last_seen=event.timestamp, events=[], mode="full"
                )
            
            trace = self.packet_traces[skb_addr]
            
            if event.event_type == 0:  # Function call
                func_name = kallsyms.lookup(event.func_ip)
                if not func_name:
                    func_name = event.function_name.decode('utf-8', errors='ignore').strip()
                if not func_name:
                    func_name = f"unknown_{hex(event.func_ip)}"
                
                self.events_by_func[func_name] += 1
                
                universal_event = UniversalEvent(
                    timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
                    skb_addr=event.skb_addr, func_name=func_name,
                    protocol=event.protocol, src_ip=event.src_ip, dst_ip=event.dst_ip,
                    src_port=event.src_port, dst_port=event.dst_port,
                    length=event.length, comm=event.comm.decode('utf-8', errors='ignore')
                )
                trace.add_universal_event(universal_event)

                # === REALTIME: Send function event (ALWAYS for session tracking) ===
                if REALTIME_AVAILABLE and realtime:
                    try:
                        realtime.process_session_event({
                            'hook': event.hook,
                            'func_name': func_name,
                            'verdict': event.verdict,
                            'protocol': event.protocol,
                            'src_ip': trace._format_ip(event.src_ip),
                            'dst_ip': trace._format_ip(event.dst_ip),
                            'timestamp': time.time()
                        }, self.session_id)
                    except Exception as e:
                        # Silent fail - don't break session if realtime fails
                        pass
            
            elif event.event_type in [1, 2, 3]:  # NFT events
                nft_event = NFTEvent(
                    timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
                    skb_addr=event.skb_addr, chain_addr=event.chain_addr,
                    expr_addr=event.expr_addr, regs_addr=0,
                    hook=event.hook, chain_depth=event.chain_depth,
                    trace_type=event.event_type - 1, pf=event.pf,
                    verdict=event.verdict, verdict_raw=event.verdict_raw,
                    queue_num=event.queue_num, rule_seq=event.rule_seq,
                    has_queue_bypass=event.has_queue_bypass, protocol=event.protocol,
                    src_ip=event.src_ip, dst_ip=event.dst_ip,
                    src_port=event.src_port, dst_port=event.dst_port,
                    rule_handle=event.rule_handle,
                    comm=event.comm.decode('utf-8', errors='ignore')
                )
                trace.add_nft_event(nft_event)

                # === REALTIME: Send NFT verdict event (ALWAYS for session tracking) ===
                if REALTIME_AVAILABLE and realtime:
                    try:
                        realtime.process_session_event({
                            'hook': event.hook,
                            'func_name': 'nft_do_chain',
                            'verdict': event.verdict,
                            'protocol': event.protocol,
                            'src_ip': trace._format_ip(event.src_ip),
                            'dst_ip': trace._format_ip(event.dst_ip),
                            'timestamp': time.time()
                        }, self.session_id)
                    except Exception as e:
                        # Silent fail - don't break session if realtime fails
                        pass
                
                if event.event_type == 1 and event.verdict in [0, 1]:
                    if skb_addr in self.packet_traces:
                        self.completed_traces.append(trace)
                        del self.packet_traces[skb_addr]
    
    def _handle_universal_event(self, cpu, data, size):
        event = self.bpf_universal["events"].event(data)
        func_name = kallsyms.lookup(event.func_ip)
        if not func_name:
            func_name = f"unknown_{hex(event.func_ip)}"
        
        universal_event = UniversalEvent(
            timestamp=event.timestamp, cpu_id=event.cpu_id, pid=event.pid,
            skb_addr=event.skb_addr, func_name=func_name,
            protocol=event.protocol, src_ip=event.saddr, dst_ip=event.daddr,
            src_port=event.sport, dst_port=event.dport,
            length=event.len, comm=event.comm.decode('utf-8', errors='ignore')
        )
        
        with self.lock:
            self.total_events += 1
            self.events_by_func[func_name] += 1
            self._update_stats()
            
            skb_addr = event.skb_addr
            if skb_addr == 0:
                return
            
            if skb_addr not in self.packet_traces:
                self.packet_traces[skb_addr] = PacketTrace(
                    skb_addr=skb_addr, first_seen=event.timestamp,
                    last_seen=event.timestamp, events=[], mode="universal"
                )
            
            trace = self.packet_traces[skb_addr]
            trace.add_universal_event(universal_event)
    
    def _get_skb_addr(self, skb_addr: int, chain_addr: int) -> int:
        if skb_addr == 0:
            self.skb_zero_count += 1
            if chain_addr != 0:
                return chain_addr
            else:
                addr = self.synthetic_id_counter
                self.synthetic_id_counter -= 1
                return addr
        return skb_addr
    
    def _update_stats(self):
        now = time.time()
        if now - self.last_stats_time >= 1.0:
            self.events_per_second = self.total_events - self.last_event_count
            self.last_event_count = self.total_events
            self.last_stats_time = now
    
    def _export_json(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"trace_{self.mode}_{self.session_id}_{timestamp}.json"
        output_path = os.path.join(OUTPUT_DIR, filename)
        
        summary = {
            'session': {
                'id': self.session_id, 'mode': self.mode,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'duration_seconds': (self.end_time - self.start_time).total_seconds() if self.end_time else 0,
                'hostname': self.hostname, 'kernel_version': self.kernel_version,
            },
            'statistics': {
                'total_events': self.total_events,
                'total_packets': len(self.completed_traces),
            },
            'traces': [trace.to_summary() for trace in self.completed_traces]
        }
        
        if self.mode in ['universal', 'full']:
            summary['statistics'].update({
                'functions_traced': len(self.functions),
                'functions_hit': len(self.events_by_func),
                'top_functions': dict(sorted(self.events_by_func.items(), 
                                            key=lambda x: x[1], reverse=True)[:20])
            })
            summary['functions_list'] = self.functions
        
        if self.mode in ['nft', 'full']:
            drops = sum(1 for t in self.completed_traces if t.final_verdict == 0)
            accepts = sum(1 for t in self.completed_traces if t.final_verdict == 1)
            summary['statistics'].update({
                'packets_dropped': drops,
                'packets_accepted': accepts,
            })
        
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[✓] Exported {len(self.completed_traces)} traces to {output_path}")
        return output_path
    
    def get_stats(self) -> Dict:
        with self.lock:
            return {
                'session_id': self.session_id, 'mode': self.mode,
                'running': self.running, 'total_events': self.total_events,
                'events_per_second': self.events_per_second,
                'active_packets': len(self.packet_traces),
                'completed_packets': len(self.completed_traces),
                'functions_traced': len(self.functions) if self.mode in ['universal', 'full'] else 0,
                'functions_hit': len(self.events_by_func) if self.mode in ['universal', 'full'] else 0,
                'start_time': self.start_time.isoformat(),
                'uptime_seconds': (datetime.now() - self.start_time).total_seconds()
            }

# ============================================================================
# SESSION MANAGER & FLASK API
# ============================================================================
class SessionManager:
    def __init__(self, realtime_ext=None):
        self.sessions: Dict[str, TraceSession] = {}
        self.lock = threading.Lock()
        self.realtime = realtime_ext
    
    def create_session(self, session_id: str, mode: str = "nft", 
                      pcap_filter: str = "", max_functions: int = 30) -> bool:
        with self.lock:
            if session_id in self.sessions:
                return False
            
            session = TraceSession(session_id, mode, pcap_filter, max_functions)
            if session.start():
                self.sessions[session_id] = session
                
                # Start realtime tracking for this session
                if self.realtime:
                    try:
                        self.realtime.start_session_tracking(session_id, mode)
                    except Exception as e:
                        print(f"[Warning] Failed to start realtime tracking: {e}")
                
                return True
            return False
    
    def stop_session(self, session_id: str) -> Optional[str]:
        with self.lock:
            if session_id not in self.sessions:
                return None
            session = self.sessions[session_id]
            output_path = session.stop()
            del self.sessions[session_id]
            
            # Stop realtime tracking for this session
            if self.realtime:
                try:
                    self.realtime.stop_session_tracking(session_id)
                except Exception as e:
                    print(f"[Warning] Failed to stop realtime tracking: {e}")
            
            return output_path
    
    def get_session_stats(self, session_id: str) -> Optional[Dict]:
        with self.lock:
            if session_id not in self.sessions:
                return None
            return self.sessions[session_id].get_stats()
    
    def list_sessions(self) -> List[Dict]:
        with self.lock:
            return [session.get_stats() for session in self.sessions.values()]

session_manager = SessionManager(realtime_ext=realtime if REALTIME_AVAILABLE else None)

# ============================================================================
# FLASK API ROUTES
# ============================================================================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok', 'bcc_available': BCC_AVAILABLE,
        'realtime_available': REALTIME_AVAILABLE,
        'timestamp': datetime.now().isoformat(),
        'kernel': platform.release(), 'hostname': socket.gethostname()
    })

@app.route('/api/discover', methods=['POST'])
def discover_functions():
    try:
        data = request.json or {}
        discoverer = BTFSKBDiscoverer()
        functions = discoverer.discover_from_btf()
        functions = discoverer.filter_by_priority(data.get('max_priority', 2))
        discoverer.export_json(FUNCTIONS_CACHE)
        return jsonify({
            'status': 'success', 'total_discovered': len(functions),
            'functions': [f.name for f in functions[:50]]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/functions', methods=['GET'])
def get_functions():
    if not os.path.exists(FUNCTIONS_CACHE):
        return jsonify({'error': 'Functions not discovered'}), 404
    with open(FUNCTIONS_CACHE, 'r') as f:
        return jsonify(json.load(f))

@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    return jsonify({'sessions': session_manager.list_sessions()})

@app.route('/api/sessions', methods=['POST'])
def create_session():
    data = request.json
    session_id = data.get('session_id', f"trace_{int(time.time() * 1000)}")
    mode = data.get('mode', 'nft')
    
    if mode not in ['nft', 'universal', 'full']:
        return jsonify({'error': 'Invalid mode. Use: nft, universal, or full'}), 400
    
    success = session_manager.create_session(
        session_id, mode, data.get('pcap_filter', ''), data.get('max_functions', 30)
    )
    
    if success:
        return jsonify({'status': 'started', 'session_id': session_id, 'mode': mode}), 201
    return jsonify({'error': 'Failed to start'}), 400

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def stop_session(session_id):
    output_path = session_manager.stop_session(session_id)
    if output_path:
        return jsonify({'status': 'stopped', 'output_file': os.path.basename(output_path)})
    return jsonify({'error': 'Session not found'}), 404

@app.route('/api/sessions/<session_id>/stats', methods=['GET'])
def get_session_stats(session_id):
    stats = session_manager.get_session_stats(session_id)
    if stats:
        return jsonify(stats)
    return jsonify({'error': 'Session not found'}), 404

@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = os.path.join(OUTPUT_DIR, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/files', methods=['GET'])
def list_files():
    files = []
    for filename in os.listdir(OUTPUT_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(OUTPUT_DIR, filename)
            stat = os.stat(filepath)
            files.append({
                'filename': filename, 'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
    files.sort(key=lambda x: x['created'], reverse=True)
    return jsonify({'files': files})

@app.route('/api/modes', methods=['GET'])
def get_modes():
    return jsonify({
        'modes': [
            {'id': 'nft', 'name': 'NFT Tracer', 
             'description': 'Trace nftables rules và verdicts'},
            {'id': 'universal', 'name': 'Universal Tracer', 
             'description': 'Trace đường đi packet qua kernel functions'},
            {'id': 'full', 'name': 'Full Tracer (Recommended)', 
             'description': 'Trace ĐẦY ĐỦ: đường đi + verdict cuối cùng',
             'recommended': True}
        ]
    })

# ============================================================================
# TRACE ANALYZER API - Phân tích chi tiết file trace
# ============================================================================
class TraceAnalyzer:
    """Helper class để load và phân tích trace files"""

    @staticmethod
    def load_trace_file(filename: str) -> Optional[Dict]:
        """Load trace JSON file"""
        file_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Enrich with rule definitions if parser available
            if NFT_PARSER_AVAILABLE:
                TraceAnalyzer.enrich_with_rule_definitions(data)

            return data
        except Exception as e:
            print(f"Error loading trace file {filename}: {e}")
            return None

    @staticmethod
    def enrich_with_rule_definitions(trace_data: Dict):
        """Enrich events in trace data with NFT rule definitions"""
        if not NFT_PARSER_AVAILABLE:
            return

        try:
            parser = get_ruleset_parser()
            traces = trace_data.get('traces', [])
            enriched_count = 0

            for packet in traces:
                events = packet.get('important_events', [])
                for event in events:
                    # Only enrich rule_eval events that don't already have rule_text
                    if (event.get('trace_type') == 'rule_eval' and
                        'rule_text' not in event and
                        event.get('rule_handle', 0) > 0):

                        rule_handle = event['rule_handle']
                        rule = parser.get_rule_by_handle(rule_handle)

                        if rule:
                            event['rule_text'] = rule.rule_text
                            event['rule_table'] = rule.table
                            event['rule_chain'] = rule.chain
                            event['rule_family'] = rule.family
                            enriched_count += 1

            if enriched_count > 0:
                print(f"[✓] Enriched {enriched_count} events with rule definitions")

        except Exception as e:
            print(f"[!] Error enriching trace data: {e}")
            import traceback
            traceback.print_exc()

    @staticmethod
    def filter_packets(traces: List[Dict], filters: Dict) -> List[Dict]:
        """Filter packets based on query parameters"""
        filtered = traces

        # Filter by IP addresses
        if 'src_ip' in filters and filters['src_ip']:
            filtered = [t for t in filtered if t.get('src_ip') == filters['src_ip']]
        if 'dst_ip' in filters and filters['dst_ip']:
            filtered = [t for t in filtered if t.get('dst_ip') == filters['dst_ip']]

        # Filter by ports
        if 'src_port' in filters and filters['src_port']:
            try:
                port = int(filters['src_port'])
                filtered = [t for t in filtered if t.get('src_port') == port]
            except ValueError:
                pass
        if 'dst_port' in filters and filters['dst_port']:
            try:
                port = int(filters['dst_port'])
                filtered = [t for t in filtered if t.get('dst_port') == port]
            except ValueError:
                pass

        # Filter by protocol
        if 'protocol' in filters and filters['protocol']:
            proto = filters['protocol'].upper()
            filtered = [t for t in filtered if t.get('protocol_name') == proto]

        # Filter by skb address
        if 'skb' in filters and filters['skb']:
            filtered = [t for t in filtered if filters['skb'].lower() in str(t.get('skb_addr', '')).lower()]

        # Filter by hook
        if 'hook' in filters and filters['hook']:
            hook = filters['hook'].upper()
            filtered = [t for t in filtered if t.get('hook_name') == hook]

        # Filter by final verdict
        if 'verdict' in filters and filters['verdict']:
            verdict = filters['verdict'].upper()
            filtered = [t for t in filtered if t.get('final_verdict') == verdict]

        # Filter by any verdict (including intermediate verdicts in events)
        if 'any_verdict' in filters and filters['any_verdict']:
            verdict = filters['any_verdict'].upper()
            def has_verdict(trace):
                # Check final verdict
                if trace.get('final_verdict') == verdict:
                    return True
                # Check important_events for intermediate verdicts
                events = trace.get('important_events', [])
                for event in events:
                    # Check verdict in different event types
                    event_verdict = event.get('verdict_str') or event.get('verdict')
                    if event_verdict:
                        if isinstance(event_verdict, str) and event_verdict.upper() == verdict:
                            return True
                        elif isinstance(event_verdict, int):
                            # Map verdict codes to names
                            verdict_map = {0: 'DROP', 1: 'ACCEPT', 2: 'STOLEN',
                                          3: 'QUEUE', 4: 'REPEAT', 5: 'STOP',
                                          -1: 'JUMP', -2: 'GOTO', -3: 'RETURN'}
                            if verdict_map.get(event_verdict, '').upper() == verdict:
                                return True
                return False
            filtered = [t for t in filtered if has_verdict(t)]

        # Filter packets that had verdict changes
        if 'had_verdict_change' in filters and filters['had_verdict_change']:
            if filters['had_verdict_change'].lower() in ['true', '1', 'yes']:
                filtered = [t for t in filtered if t.get('verdict_changes', 0) > 0]

        # Filter by function name
        if 'function' in filters and filters['function']:
            func = filters['function'].lower()
            filtered = [t for t in filtered
                       if any(func in f.lower() for f in t.get('functions_path', []))]

        # Keyword search across all fields
        if 'keyword' in filters and filters['keyword']:
            keyword = filters['keyword'].lower()
            filtered = [t for t in filtered
                       if keyword in json.dumps(t).lower()]

        return filtered

    @staticmethod
    def get_packet_detail(trace_data: Dict, packet_index: int) -> Optional[Dict]:
        """Get full detail of a specific packet including all events"""
        traces = trace_data.get('traces', [])
        if packet_index < 0 or packet_index >= len(traces):
            return None

        packet = traces[packet_index]

        # Load full events from storage if needed
        # For now, important_events are already in the summary
        # If you need ALL events, you would need to store them separately

        # Analyze packet flow and verdict chain
        analysis = TraceAnalyzer._analyze_packet_flow(packet)

        return {
            **packet,
            'packet_index': packet_index,
            'analysis': analysis
        }

    @staticmethod
    def _analyze_packet_flow(packet: Dict) -> Dict:
        """Analyze packet flow and provide insights"""
        analysis = {
            'verdict_chain': [],
            'jump_goto_chain': [],
            'drop_reason': None,
            'flow_summary': []
        }

        # Analyze verdict changes
        events = packet.get('important_events', [])
        for event in events:
            trace_type = event.get('trace_type')

            if trace_type in ['chain_exit', 'hook_exit']:
                verdict_info = {
                    'timestamp': event.get('timestamp'),
                    'type': trace_type,
                    'verdict': event.get('verdict_str'),
                    'hook': event.get('hook_name'),
                    'chain': event.get('chain_name'),
                    'table': event.get('table_name')
                }
                analysis['verdict_chain'].append(verdict_info)

                # Check for JUMP/GOTO
                if event.get('verdict_str') in ['JUMP', 'GOTO']:
                    analysis['jump_goto_chain'].append({
                        'source_chain': event.get('chain_name'),
                        'target_chain': event.get('target_chain'),
                        'verdict_type': event.get('verdict_str')
                    })

            elif trace_type == 'rule_eval':
                # Track rule evaluation
                pass

        # Determine drop reason
        final_verdict = packet.get('final_verdict')
        if final_verdict == 'DROP':
            last_verdict = analysis['verdict_chain'][-1] if analysis['verdict_chain'] else None
            if last_verdict:
                analysis['drop_reason'] = {
                    'hook': last_verdict.get('hook'),
                    'chain': last_verdict.get('chain'),
                    'table': last_verdict.get('table'),
                    'reason': f"Packet dropped at {last_verdict.get('hook')} in chain {last_verdict.get('chain')}"
                }

        # Create flow summary
        functions = packet.get('functions_path', [])
        if functions:
            # Group functions by layer
            layers = {
                'Network Device': ['netif_receive_skb', '__netif_receive_skb_core'],
                'IP Layer': ['ip_rcv', 'ip_rcv_finish', 'ip_local_deliver', 'ip_forward', 'ip_output'],
                'Transport': ['tcp_v4_rcv', 'udp_rcv'],
                'Netfilter': ['nf_hook_slow', 'nf_conntrack_in'],
            }

            for layer, layer_funcs in layers.items():
                matched = [f for f in functions if any(lf in f for lf in layer_funcs)]
                if matched:
                    analysis['flow_summary'].append({
                        'layer': layer,
                        'functions': matched
                    })

        return analysis

@app.route('/api/traces/<filename>', methods=['GET'])
def get_trace_file(filename):
    """Load complete trace file"""
    trace_data = TraceAnalyzer.load_trace_file(filename)
    if trace_data is None:
        return jsonify({'error': 'Trace file not found'}), 404

    return jsonify(trace_data)

@app.route('/api/traces/<filename>/packets', methods=['GET'])
def get_trace_packets(filename):
    """Get filtered list of packets from trace file"""
    trace_data = TraceAnalyzer.load_trace_file(filename)
    if trace_data is None:
        return jsonify({'error': 'Trace file not found'}), 404

    # Get filter parameters from query string
    filters = {
        'src_ip': request.args.get('src_ip'),
        'dst_ip': request.args.get('dst_ip'),
        'src_port': request.args.get('src_port'),
        'dst_port': request.args.get('dst_port'),
        'protocol': request.args.get('protocol'),
        'skb': request.args.get('skb'),
        'hook': request.args.get('hook'),
        'verdict': request.args.get('verdict'),
        'any_verdict': request.args.get('any_verdict'),
        'had_verdict_change': request.args.get('had_verdict_change'),
        'function': request.args.get('function'),
        'keyword': request.args.get('keyword')
    }

    # Remove None values
    filters = {k: v for k, v in filters.items() if v}

    traces = trace_data.get('traces', [])

    # Add original index to each trace before filtering
    for i, trace in enumerate(traces):
        trace['original_index'] = i

    filtered_traces = TraceAnalyzer.filter_packets(traces, filters)

    # Add pagination support
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 100))
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'session': trace_data.get('session'),
        'statistics': trace_data.get('statistics'),
        'filters_applied': filters,
        'total_packets': len(filtered_traces),
        'page': page,
        'per_page': per_page,
        'packets': filtered_traces[start:end]
    })

@app.route('/api/traces/<filename>/packets/<int:packet_index>', methods=['GET'])
def get_packet_detail(filename, packet_index):
    """Get detailed information about a specific packet"""
    trace_data = TraceAnalyzer.load_trace_file(filename)
    if trace_data is None:
        return jsonify({'error': 'Trace file not found'}), 404

    packet_detail = TraceAnalyzer.get_packet_detail(trace_data, packet_index)
    if packet_detail is None:
        return jsonify({'error': 'Packet not found'}), 404

    return jsonify(packet_detail)

# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    print("=" * 70)
    print("KERNEL PACKET TRACER - FULL MODE + REALTIME VISUALIZATION")
    print("=" * 70)
    print(f"BCC: {'✓' if BCC_AVAILABLE else '✗'}")
    print(f"Realtime: {'✓' if REALTIME_AVAILABLE else '✗'}")
    print(f"Kernel: {platform.release()}")
    print(f"Hostname: {socket.gethostname()}")
    print("=" * 70)
    print("MODES:")
    print("  • nft      - NFT rules only")
    print("  • universal - Kernel functions only")
    print("  • full     - ĐƯỜNG ĐI + VERDICT (recommended!)")
    print("=" * 70)
    
    if REALTIME_AVAILABLE:
        print("REALTIME VISUALIZATION:")
        print("  • WebSocket: ws://localhost:5000/realtime")
        print("  • Enable: POST /api/realtime/enable")
        print("  • Disable: POST /api/realtime/disable")
        print("  • Stats: GET /api/realtime/stats")
        print("=" * 70)
    
    print("\nAPI Endpoints:")
    print("  GET  /api/health")
    print("  POST /api/discover")
    print("  GET  /api/functions")
    print("  GET  /api/sessions")
    print("  POST /api/sessions")
    print("  DELETE /api/sessions/<id>")
    print("  GET  /api/sessions/<id>/stats")
    print("=" * 70)
    
    # Start server with SocketIO support if available
    if REALTIME_AVAILABLE and socketio:
        print("\n[✓] Starting with SocketIO support (Realtime enabled)")
        print("[*] Server running on http://0.0.0.0:5000")
        print("[*] WebSocket endpoint: ws://0.0.0.0:5000/socket.io/")
        print("[*] CORS: enabled for all origins")
        print("-" * 70)
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
    else:
        print("\n[✓] Starting standard Flask server (No realtime)")
        print("[*] Server running on http://0.0.0.0:5000")
        app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)