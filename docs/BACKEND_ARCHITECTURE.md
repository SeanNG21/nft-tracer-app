# SƠ ĐỒ KIẾN TRÚC BACKEND - NFT TRACER APP

## 📋 MỤC LỤC
1. [Sơ đồ Kiến trúc Tổng thể](#1-sơ-đồ-kiến-trúc-tổng-thể)
2. [Các Thành phần Chính](#2-các-thành-phần-chính)
3. [Mối Quan hệ giữa Các Thành phần](#3-mối-quan-hệ-giữa-các-thành-phần)
4. [Luồng Dữ liệu Tổng quát](#4-luồng-dữ-liệu-tổng-quát)
5. [Thuật toán và Mô hình](#5-thuật-toán-và-mô-hình)
6. [Các Chức năng Chính](#6-các-chức-năng-chính)

---

## 1. SƠ ĐỒ KIẾN TRÚC TỔNG THỂ

### 1.1. Kiến trúc 4 Lớp (Layered Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   REST API       │  │   WebSocket      │  │   Static Files   │  │
│  │   (Flask)        │  │   (Socket.IO)    │  │                  │  │
│  │                  │  │                  │  │                  │  │
│  │ • 25+ Endpoints  │  │ • Real-time      │  │ • JSON Export    │  │
│  │ • JWT Auth       │  │ • Event Stream   │  │ • Trace Files    │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                               │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Session Manager (SessionManager)                 │  │
│  │  • Create/Stop Sessions   • Thread-safe operations           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                   │                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  TraceSession    │  │  NFTablesManager │  │  RealtimeExt     │  │
│  │                  │  │                  │  │                  │  │
│  │ • NFT Mode       │  │ • Rule CRUD      │  │ • Event Agg.     │  │
│  │ • FULL Mode      │  │ • Ruleset Parse  │  │ • WebSocket Pub  │  │
│  │ • Event Handler  │  │ • Chain Query    │  │ • Stats Tracking │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  PacketTrace     │  │  TraceAnalyzer   │  │  SKBDiscoverer   │  │
│  │                  │  │                  │  │                  │  │
│  │ • Aggregation    │  │ • Filtering      │  │ • BTF Discovery  │  │
│  │ • Deduplication  │  │ • Analysis       │  │ • kallsyms Scan  │  │
│  │ • Classification │  │ • Detail View    │  │ • Layer Classify │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA LAYER                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   SQLite DB      │  │   JSON Files     │  │   In-Memory      │  │
│  │                  │  │                  │  │                  │  │
│  │ • User Table     │  │ • Trace Export   │  │ • Active Traces  │  │
│  │ • SQLAlchemy     │  │ • Session Data   │  │ • BPF Maps       │  │
│  │ • Auth Data      │  │ • Statistics     │  │ • Event Buffers  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         KERNEL LAYER                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      eBPF Programs (BCC)                      │  │
│  │  ┌────────────────────────┐  ┌────────────────────────────┐  │  │
│  │  │   nft_tracer.bpf.c     │  │   full_tracer.bpf.c        │  │  │
│  │  │                        │  │                            │  │  │
│  │  │ • nft_do_chain         │  │ • 50+ Fixed Functions      │  │  │
│  │  │ • nft_immediate_eval   │  │ • All Network Layers       │  │  │
│  │  │ • nf_hook_slow         │  │ • + NFT Integration        │  │  │
│  │  └────────────────────────┘  └────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                   │                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Linux Kernel Network Stack                      │  │
│  │                                                               │  │
│  │  NIC → Driver → GRO → TC → Netfilter → Routing → TCP/UDP    │  │
│  │         ↓         ↓     ↓        ↓         ↓         ↓       │  │
│  │       kprobe   kprobe kprobe  kprobe    kprobe    kprobe     │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2. Technology Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                      BACKEND TECH STACK                          │
├─────────────────────────────────────────────────────────────────┤
│ Language:      Python 3.8+, C (eBPF)                            │
│ Web Framework: Flask 2.0+                                        │
│ Real-time:     Flask-SocketIO, Python-SocketIO                  │
│ Database:      SQLite + SQLAlchemy ORM                          │
│ Auth:          Flask-JWT-Extended, Werkzeug                     │
│ Kernel Trace:  BCC (BPF Compiler Collection)                    │
│ System:        nftables, libnftnl, conntrack-tools              │
│ Process:       psutil, threading, subprocess                    │
│ Data Format:   JSON, struct                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. CÁC THÀNH PHẦN CHÍNH

### 2.1. Flask Application Core (`app.py`)

**Chức năng:** Main server application, routing, session orchestration

**Thành phần con:**
- **KallsymsLookup**: Symbol resolution từ `/proc/kallsyms`
- **NFTEvent / UniversalEvent**: Event data structures
- **PacketTrace**: Packet aggregation and analysis
- **TraceSession**: Individual tracing session management
- **SessionManager**: Multi-session coordination

**Key Attributes:**
```python
# Global Constants
FUNCTION_TO_LAYER: Dict[str, str]     # 50+ functions mapped to network layers
PIPELINE_STRUCTURE: Dict[str, List]   # Inbound/Outbound pipeline stages
EXCLUDED_PORTS: Set[int]              # Self-tracing prevention
CRITICAL_FUNCTIONS: List[str]         # High-priority trace targets
```

### 2.2. Database Models (`models.py`)

**User Model:**
```python
class User(db.Model):
    id: Integer (PK)
    username: String(80) [unique, indexed]
    email: String(120) [unique, indexed]
    password_hash: String(255)
    is_active: Boolean
    first_login: Boolean
    created_at: DateTime
    last_login: DateTime
```

### 2.3. Authentication System (`auth.py`)

**Components:**
- `init_default_user()`: Tạo root user mặc định
- `authenticate_user()`: Credential validation
- `create_tokens()`: JWT access (24h) + refresh (30d) tokens
- `token_required`: Decorator cho protected routes
- `change_password()`: Password management

### 2.4. eBPF Programs

#### nft_tracer.bpf.c (NFT Mode)
```c
struct nft_event {
    u64 timestamp, skb_addr, chain_addr, expr_addr;
    u32 cpu_id, pid, verdict;
    u16 src_port, dst_port, rule_seq;
    u32 src_ip, dst_ip;
    u8 hook, protocol, trace_type;
    // ... 16 fields total
};

BPF_PERF_OUTPUT(events);
BPF_HASH(skb_map, u64, struct skb_info, 10240);

Probes:
- kprobe__nft_do_chain
- kretprobe__nft_do_chain
- kprobe__nft_immediate_eval
- kretprobe__nf_hook_slow
```

#### full_tracer.bpf.c (FULL Mode)
```c
struct trace_event {
    // All nft_event fields +
    u64 func_ip;
    char function_name[64];
    u8 event_type;  // 0=func, 1=nft_chain, 2=nft_rule, 3=nf_verdict
};

Probes:
- kprobe__nf_hook_slow (for hook tracking)
- kretprobe__nf_hook_slow
- kprobe__nft_do_chain
- kretprobe__nft_do_chain
- kprobe__nft_immediate_eval
- trace_skb_func (attached to 50+ functions)
```

### 2.5. NFTables Manager (`nftables_manager.py`)

**Static Methods:**
- `get_ruleset()`: Query full nftables config via JSON
- `get_tables()`, `get_chains()`: Hierarchy navigation
- `add_rule()`, `delete_rule()`, `update_rule()`: Rule CRUD
- `parse_ruleset_to_tree()`: Convert flat JSON to nested tree
- `parse_rule_expr()`: Expression to human-readable text

### 2.6. SKB Function Discoverer (`enhanced_skb_discoverer.py`)

**Discovery Methods:**
1. **BTF-based**: Parse `/sys/kernel/btf/vmlinux` via bpftool
2. **kallsyms-based**: Heuristic scan of `/proc/kallsyms`

**Classification:**
- **Layers**: Device, GRO, Netfilter, IPv4/6, TCP, UDP, Routing, etc.
- **Priority**: 0=Critical, 1=Important, 2=Optional, 3=Unknown
- **Categories**: nft, conntrack, tcp, udp, ip, routing, etc.

---

## 3. MỐI QUAN HỆ GIỮA CÁC THÀNH PHẦN

### 3.1. Component Interaction Diagram

```
┌──────────────┐
│   Frontend   │
│   (React)    │
└──────┬───────┘
       │ HTTP REST + WebSocket
       ▼
┌──────────────────────────────────────────────┐
│            Flask Application                 │
│  ┌────────────┐         ┌────────────┐      │
│  │    Auth    │◄────────┤ Middleware │      │
│  │   Module   │         │  (JWT)     │      │
│  └────────────┘         └────────────┘      │
│         │                                    │
│         ▼                                    │
│  ┌────────────────────────────────────┐     │
│  │       SessionManager               │     │
│  │  ┌──────────────────────────────┐  │     │
│  │  │   TraceSession (NFT/FULL)    │  │     │
│  │  │   ┌──────────┐  ┌──────────┐ │  │     │
│  │  │   │ BPF_NFT  │  │ BPF_FULL │ │  │     │
│  │  │   └────┬─────┘  └────┬─────┘ │  │     │
│  │  │        │             │        │  │     │
│  │  └────────┼─────────────┼────────┘  │     │
│  └───────────┼─────────────┼───────────┘     │
│              │             │                  │
└──────────────┼─────────────┼──────────────────┘
               │             │
               ▼             ▼
        ┌──────────────────────────┐
        │    Kernel Space (eBPF)   │
        │  ┌────────────────────┐  │
        │  │  kprobe hooks      │  │
        │  │  • nft_do_chain    │  │
        │  │  • tcp_v4_rcv      │  │
        │  │  • ip_rcv          │  │
        │  │  • dev_queue_xmit  │  │
        │  │  ... (50+ funcs)   │  │
        │  └────────────────────┘  │
        │           │               │
        │           ▼               │
        │  ┌────────────────────┐  │
        │  │  BPF Perf Buffer   │  │
        │  └────────────────────┘  │
        └───────────┬──────────────┘
                    │
                    ▼
        ┌───────────────────────────┐
        │   PacketTrace Objects     │
        │   • Aggregation           │
        │   • Deduplication         │
        │   • Classification        │
        └───────────┬───────────────┘
                    │
                    ▼
        ┌───────────────────────────┐
        │   Export to JSON          │
        │   • Session metadata      │
        │   • Statistics            │
        │   • Trace array           │
        └───────────────────────────┘
```

### 3.2. Data Flow Between Components

```
User Request → JWT Validation → Session Manager → Trace Session
                                                         │
                    ┌────────────────────────────────────┘
                    ▼
            eBPF Program Loading
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   Attach kprobes         Attach kretprobes
        │                       │
        └───────────┬───────────┘
                    ▼
          Event Collection (perf buffer)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   NFT Events            Function Events
        │                       │
        └───────────┬───────────┘
                    ▼
          _handle_*_event() callbacks
                    │
        ┌───────────┴───────────────┐
        ▼                           ▼
   SKB Address            5-Tuple Extraction
   Resolution                      │
        │                          │
        └────────┬─────────────────┘
                 ▼
         Packet Key Generation
                 │
                 ▼
      ┌──────────────────────┐
      │ PacketTrace Lookup   │
      │ (or create new)      │
      └──────────┬───────────┘
                 ▼
      ┌──────────────────────┐
      │  add_nft_event() or  │
      │  add_universal_event()│
      └──────────┬───────────┘
                 ▼
      ┌──────────────────────┐
      │  Event Deduplication │
      │  • 5µs NFT window    │
      │  • 1ms func window   │
      └──────────┬───────────┘
                 ▼
      ┌──────────────────────┐
      │  Layer Classification│
      │  • FUNCTION_TO_LAYER │
      │  • refine_layer_by_  │
      │    hook()            │
      └──────────┬───────────┘
                 ▼
      ┌──────────────────────┐
      │  Direction Detection │
      │  • Inbound/Outbound  │
      └──────────┬───────────┘
                 ▼
         Update Trace Stats
         (verdict, layers, etc.)
                 │
         ┌───────┴────────┐
         ▼                ▼
   Still Active     Timed Out / DROP
         │                │
    Keep in Map     Move to Completed
                          │
                          ▼
                   Export to JSON
```

---

## 4. LUỒNG DỮ LIỆU TỔNG QUÁT

### 4.1. Authentication Flow

```
┌──────────┐
│  Client  │
└────┬─────┘
     │ POST /api/auth/login
     │ {username, password}
     ▼
┌──────────────────┐
│ authenticate_    │
│ user()           │
│ • Query DB       │
│ • check_password │
│ • Update login   │
└────┬─────────────┘
     │ User object
     ▼
┌──────────────────┐
│ create_tokens()  │
│ • access_token   │
│   (24h)          │
│ • refresh_token  │
│   (30d)          │
└────┬─────────────┘
     │ JWT tokens
     ▼
┌──────────┐
│  Client  │
│  Stores  │
│  Tokens  │
└──────────┘

Subsequent Requests:
Authorization: Bearer <access_token>
       ↓
@token_required decorator
       ↓
verify_jwt_in_request()
       ↓
get_jwt_identity() → user_id
       ↓
User.query.get(user_id)
       ↓
Inject user into route handler
```

### 4.2. Trace Session Lifecycle

```
1. CREATE SESSION
   POST /api/sessions
   {mode: "full", session_id: "trace_123"}
        ↓
   SessionManager.create_session()
        ↓
   TraceSession.__init__(mode="full")
        ↓
   TraceSession.start()
        ↓
   _start_full_mode()
        ↓
   ┌─────────────────────────────────┐
   │ • Load eBPF program from file   │
   │ • BPF(text=bpf_code)            │
   │ • Attach 50+ kprobes            │
   │ • Open perf buffer              │
   │ • Start polling thread          │
   └─────────────────────────────────┘

2. ACTIVE TRACING
   Polling thread (_poll_full_events):
   While running:
       bpf.perf_buffer_poll(timeout=10)
            ↓
       _handle_full_event(cpu, data, size)
            ↓
       Parse struct trace_event
            ↓
       Lock acquired
            ↓
       ┌─ event_type = 0 (function call)
       │   → kallsyms.lookup(func_ip)
       │   → create UniversalEvent
       │   → trace.add_universal_event()
       │
       └─ event_type = 1/2/3 (NFT events)
           → create NFTEvent
           → trace.add_nft_event()
            ↓
       Lock released

   Cleanup thread (_cleanup_old_traces):
   While running:
       Every 2 seconds:
           if (now - trace.last_seen > 1_000_000_000 ns):
               Move packet_traces → completed_traces

3. STOP SESSION
   DELETE /api/sessions/{id}
        ↓
   SessionManager.stop_session(id)
        ↓
   session.stop()
        ↓
   ┌──────────────────────────────┐
   │ • Set running = False        │
   │ • Join threads (timeout 2s)  │
   │ • Move active → completed    │
   │ • _export_json()             │
   │ • bpf.cleanup()              │
   └──────────────────────────────┘
        ↓
   Return JSON file path
```

### 4.3. Packet Trace Aggregation

```
Event arrives (e.g., tcp_v4_rcv called)
     ↓
Extract packet info:
  skb_addr, src_ip, dst_ip, src_port, dst_port, protocol
     ↓
_make_packet_key():
  if 5-tuple available:
      key = f"{skb_addr:x}:{protocol}:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
  else:
      key = f"{skb_addr:x}"
     ↓
Lookup in packet_traces dict:
  trace = packet_traces.get(key)
     ↓
If not found:
  Create new PacketTrace(
      skb_addr=skb_addr,
      first_seen=timestamp,
      last_seen=timestamp,
      events=[],
      mode="full"
  )
  packet_traces[key] = trace
     ↓
trace.add_universal_event(event):
  │
  ├─ Deduplication check:
  │   dedup_key = (func_name, layer)
  │   if timestamp - last_seen[dedup_key] < 1000 ns:
  │       return  // Skip duplicate
  │
  ├─ Layer classification:
  │   base_layer = FUNCTION_TO_LAYER[func_name]
  │   layer = refine_layer_by_hook(func_name, base_layer, hook)
  │
  ├─ Direction detection:
  │   direction = detect_packet_direction(func_name, layer)
  │
  ├─ Append to events[]
  ├─ Update functions_called[]
  ├─ Update pipeline_stages[]
  ├─ Update layer_counts{}
  └─ Update last_seen timestamp

Verdict tracking (for NFT events):
  trace.add_nft_event(event):
      if trace_type == 'chain_exit':
          Compare with previous verdict → verdict_changes++
      if trace_type == 'hook_exit':
          final_verdict = event.verdict
      if trace_type == 'rule_eval':
          total_rules_evaluated++

Completion criteria:
  • verdict == DROP/STOLEN → immediate completion
  • timeout (1s no activity) → auto-complete
  • session stop → flush all to completed
```

### 4.4. Data Export Flow

```
Session stopped
     ↓
_export_json():
     ↓
Filter valuable traces:
  for trace in completed_traces:
      if trace.is_valuable_trace():
          ✓ Include
      else:
          ✗ Skip
     ↓
Build summary dict:
  {
    session: {id, mode, start_time, end_time, ...},
    statistics: {
        total_events,
        total_packets,
        valuable_packets,
        filtered_packets,
        functions_traced,
        top_functions,
        pipeline_stats,
        ...
    },
    traces: [
        trace.to_summary() for each valuable trace
    ]
  }
     ↓
Write to JSON file:
  data/output/trace_{mode}_{session_id}_{timestamp}.json
     ↓
Return file path to caller
```

---

## 5. THUẬT TOÁN VÀ MÔ HÌNH

### 5.1. SKB Address Resolution

**Problem:** `skb_addr` có thể = 0 trong một số context (chain evaluation)

**Algorithm:**
```python
def _get_skb_addr(skb_addr: int, chain_addr: int) -> int:
    """
    Resolve actual packet identifier from eBPF event

    Priority:
    1. Use skb_addr if valid (> 0)
    2. Fallback to chain_addr if skb_addr = 0
    3. Generate synthetic ID if both = 0
    """
    if skb_addr == 0:
        skb_zero_count++
        if chain_addr != 0:
            return chain_addr  # FALLBACK 1
        else:
            addr = synthetic_id_counter  # FALLBACK 2
            synthetic_id_counter -= 1    # Negative IDs
            return addr
    return skb_addr  # PRIMARY
```

**Pseudocode:**
```
FUNCTION resolve_skb_address(event):
    IF event.skb_addr > 0 THEN
        RETURN event.skb_addr
    ELSE IF event.chain_addr > 0 THEN
        INCREMENT skb_zero_counter
        RETURN event.chain_addr
    ELSE
        INCREMENT skb_zero_counter
        synthetic_id ← next_synthetic_id()
        RETURN synthetic_id
    END IF
END FUNCTION
```

---

### 5.2. Packet Identification (5-Tuple Composite Key)

**Problem:** Kernel reuses SKB memory addresses → different packets may have same skb_addr

**Solution:** Composite key combining SKB + 5-tuple

**Algorithm:**
```python
def _make_packet_key(skb_addr, src_ip, dst_ip, src_port, dst_port, protocol):
    """
    Create unique packet identifier

    Format: {skb_addr}:{protocol}:{src_ip}:{src_port}:{dst_ip}:{dst_port}

    Prevents false merging of different packets when kernel reuses SKB addresses
    """
    # If packet info unavailable, use only SKB addr
    if src_ip == 0 and dst_ip == 0 and src_port == 0 and dst_port == 0:
        return f"{skb_addr:x}"

    # Convert IPs to dotted notation
    src_ip_str = inet_ntoa(pack('<I', src_ip))
    dst_ip_str = inet_ntoa(pack('<I', dst_ip))

    # Composite key
    return f"{skb_addr:x}:{protocol}:{src_ip_str}:{src_port}:{dst_ip_str}:{dst_port}"
```

**Pseudocode:**
```
FUNCTION make_packet_key(skb, src_ip, dst_ip, src_port, dst_port, proto):
    IF src_ip = 0 AND dst_ip = 0 AND src_port = 0 AND dst_port = 0 THEN
        // Early packet path, 5-tuple not yet extracted
        key ← HEX(skb)
    ELSE
        // Full identification available
        key ← CONCAT(
            HEX(skb), ":",
            proto, ":",
            IP_TO_STRING(src_ip), ":",
            src_port, ":",
            IP_TO_STRING(dst_ip), ":",
            dst_port
        )
    END IF
    RETURN key
END FUNCTION

Example keys:
  "ffff88810abc1234"                                    // Early path
  "ffff88810abc1234:6:192.168.1.10:52341:8.8.8.8:443"  // Full identification
```

---

### 5.3. Event Deduplication

**Problem:** Kernel may fire same kprobe multiple times for single logical event

**Algorithm:**
```python
# For NFT Events (expression evaluation)
DEDUP_WINDOW_NS = 5000  # 5 microseconds

def add_nft_event(event: NFTEvent):
    if event.expr_addr > 0:
        dedup_key = (event.skb_addr, event.expr_addr)

        if hasattr(self, '_last_expr_eval'):
            last_key, last_ts = self._last_expr_eval
            if last_key == dedup_key and abs(event.timestamp - last_ts) < DEDUP_WINDOW_NS:
                return  # DUPLICATE - SKIP

        self._last_expr_eval = (dedup_key, event.timestamp)

    # Process event...
```

```python
# For Function Call Events
DEDUP_WINDOW_NS = 1000  # 1 millisecond

def add_universal_event(event: UniversalEvent):
    dedup_key = (event.func_name, layer)
    last_ts = self._func_last_seen.get(dedup_key, 0)

    if event.timestamp - last_ts < DEDUP_WINDOW_NS:
        return  # DUPLICATE - SKIP

    self._func_last_seen[dedup_key] = event.timestamp

    # Process event...
```

**Pseudocode:**
```
FUNCTION deduplicate_nft_event(trace, event):
    WINDOW ← 5000 nanoseconds

    IF event.expr_addr > 0 THEN
        key ← (event.skb_addr, event.expr_addr)

        IF trace.has_last_eval AND
           trace.last_eval.key = key AND
           ABS(event.timestamp - trace.last_eval.timestamp) < WINDOW THEN
            RETURN FALSE  // Duplicate
        END IF

        trace.last_eval ← {key, event.timestamp}
    END IF

    RETURN TRUE  // Unique
END FUNCTION

FUNCTION deduplicate_function_event(trace, event, layer):
    WINDOW ← 1000 nanoseconds

    key ← (event.func_name, layer)
    last_seen ← trace.func_last_seen[key] OR 0

    IF event.timestamp - last_seen < WINDOW THEN
        RETURN FALSE  // Duplicate
    END IF

    trace.func_last_seen[key] ← event.timestamp
    RETURN TRUE  // Unique
END FUNCTION
```

---

### 5.4. Layer Classification

**Algorithm:**
```python
FUNCTION_TO_LAYER = {
    # Network Interface Layer
    'napi_gro_receive': 'NIC',
    'netif_receive_skb': 'NIC',

    # Driver Layer
    'net_rx_action': 'Driver (NAPI)',

    # GRO Layer
    'gro_normal_list': 'GRO',

    # Traffic Control
    'tcf_classify': 'TC Ingress',

    # Netfilter Hooks
    'nf_hook_slow': 'Netfilter',

    # Connection Tracking
    'nf_conntrack_in': 'Conntrack',

    # NAT
    'nf_nat_ipv4_fn': 'NAT',

    # Routing
    'ip_route_input_slow': 'Routing Decision',

    # Local Delivery
    'ip_local_deliver': 'Local Delivery',

    # Transport Layer
    'tcp_v4_rcv': 'TCP/UDP',
    'udp_rcv': 'TCP/UDP',

    # ... 50+ functions total
}

def classify_event(func_name: str, hook: int) -> tuple[str, str]:
    """
    Classify network event by layer and direction

    Returns: (layer, direction)
    """
    # Step 1: Base layer lookup
    base_layer = FUNCTION_TO_LAYER.get(func_name, 'Unknown')

    # Step 2: Refine by netfilter hook
    layer = refine_layer_by_hook(func_name, base_layer, hook)

    # Step 3: Detect direction
    direction = detect_packet_direction(func_name, layer)

    return (layer, direction)
```

**Hook Refinement:**
```python
def refine_layer_by_hook(func_name: str, base_layer: str, hook: int) -> str:
    """
    Refine layer classification using Netfilter hook point

    Hook values:
    0 = PREROUTING
    1 = INPUT
    2 = FORWARD
    3 = OUTPUT
    4 = POSTROUTING
    """
    if base_layer == 'Netfilter' or 'nf_hook' in func_name:
        hook_map = {
            0: 'Netfilter PREROUTING',
            1: 'Netfilter INPUT',
            2: 'Netfilter FORWARD',
            3: 'Netfilter OUTPUT',
            4: 'Netfilter POSTROUTING',
        }
        return hook_map.get(hook, base_layer)

    if 'NAT' in base_layer:
        if hook == 0:
            return 'NAT PREROUTING'
        elif hook in [3, 4]:
            return 'NAT POSTROUTING'

    return base_layer
```

**Pseudocode:**
```
FUNCTION classify_layer(func_name, hook):
    // Base classification
    base_layer ← LOOKUP(FUNCTION_TO_LAYER, func_name)
    IF base_layer = NULL THEN
        base_layer ← "Unknown"
    END IF

    // Refine by hook point
    IF base_layer CONTAINS "Netfilter" OR func_name CONTAINS "nf_hook" THEN
        CASE hook OF
            0: refined_layer ← "Netfilter PREROUTING"
            1: refined_layer ← "Netfilter INPUT"
            2: refined_layer ← "Netfilter FORWARD"
            3: refined_layer ← "Netfilter OUTPUT"
            4: refined_layer ← "Netfilter POSTROUTING"
            DEFAULT: refined_layer ← base_layer
        END CASE
    ELSE IF base_layer CONTAINS "NAT" THEN
        IF hook = 0 THEN
            refined_layer ← "NAT PREROUTING"
        ELSE IF hook IN [3, 4] THEN
            refined_layer ← "NAT POSTROUTING"
        ELSE
            refined_layer ← base_layer
        END IF
    ELSE
        refined_layer ← base_layer
    END IF

    RETURN refined_layer
END FUNCTION
```

---

### 5.5. Direction Detection

**Algorithm:**
```python
def detect_packet_direction(func_name: str, layer: str) -> str:
    """
    Determine if packet is inbound or outbound

    Uses:
    1. Layer-based heuristics
    2. Function name keywords
    3. Default rules
    """
    # Definitive inbound layers
    inbound_layers = [
        'NIC', 'Driver (NAPI)', 'GRO', 'TC Ingress',
        'Netfilter PREROUTING', 'Netfilter INPUT',
        'Conntrack', 'NAT PREROUTING', 'Routing Decision',
        'Local Delivery', 'Socket'
    ]

    # Definitive outbound layers
    outbound_layers = [
        'Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
        'Routing Lookup', 'NAT POSTROUTING', 'TC Egress',
        'Driver TX'
    ]

    if layer in inbound_layers:
        return 'Inbound'
    if layer in outbound_layers:
        return 'Outbound'

    # Keyword-based detection
    inbound_keywords = ['rcv', 'receive', 'input', 'ingress', 'deliver']
    outbound_keywords = ['sendmsg', 'xmit', 'transmit', 'output', 'egress']

    func_lower = func_name.lower()
    for kw in inbound_keywords:
        if kw in func_lower:
            return 'Inbound'
    for kw in outbound_keywords:
        if kw in func_lower:
            return 'Outbound'

    # Default
    return 'Inbound'
```

**Pseudocode:**
```
FUNCTION detect_direction(func_name, layer):
    INBOUND ← ['NIC', 'Driver (NAPI)', 'GRO', 'TC Ingress',
               'Netfilter PREROUTING', 'Netfilter INPUT', ...]
    OUTBOUND ← ['Application', 'TCP/UDP Output', 'Netfilter OUTPUT',
                'Routing Lookup', 'NAT POSTROUTING', ...]

    // Layer-based
    IF layer IN INBOUND THEN
        RETURN "Inbound"
    ELSE IF layer IN OUTBOUND THEN
        RETURN "Outbound"
    END IF

    // Keyword-based
    fname ← TO_LOWER(func_name)
    IF fname CONTAINS "rcv" OR fname CONTAINS "receive" OR
       fname CONTAINS "input" OR fname CONTAINS "ingress" THEN
        RETURN "Inbound"
    ELSE IF fname CONTAINS "sendmsg" OR fname CONTAINS "xmit" OR
            fname CONTAINS "transmit" OR fname CONTAINS "output" THEN
        RETURN "Outbound"
    END IF

    // Default
    RETURN "Inbound"
END FUNCTION
```

---

### 5.6. Verdict Decoding

**eBPF Verdict Encoding:**
```c
// Negative return values = flow control
// Positive return values = terminal verdicts

static inline u32 decode_verdict(s32 raw_ret, u32 raw_u32) {
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;  // CONTINUE
            case -2: return 11;  // RETURN
            case -3: return 12;  // JUMP
            case -4: return 13;  // GOTO
            case -5: return 14;  // BREAK
            default: return 0;   // DROP
        }
    }

    // Terminal verdicts
    u32 verdict = raw_u32 & 0xFF;
    if (verdict > 5) return 255;  // UNKNOWN
    return verdict;
}
```

**Python Verdict Decoding:**
```python
@staticmethod
def _verdict_str(verdict: int) -> str:
    verdicts = {
        0: "DROP",
        1: "ACCEPT",
        2: "STOLEN",
        3: "QUEUE",
        4: "REPEAT",
        5: "STOP",
        10: "CONTINUE",
        11: "RETURN",
        12: "JUMP",
        13: "GOTO",
        14: "BREAK",
        255: "UNKNOWN"
    }
    return verdicts.get(verdict, f"UNKNOWN_{verdict}")
```

**Pseudocode:**
```
FUNCTION decode_verdict(raw_return, raw_u32):
    IF raw_return < 0 THEN
        // Flow control verdicts
        CASE raw_return OF
            -1: RETURN "CONTINUE" (10)
            -2: RETURN "RETURN"   (11)
            -3: RETURN "JUMP"     (12)
            -4: RETURN "GOTO"     (13)
            -5: RETURN "BREAK"    (14)
            DEFAULT: RETURN "DROP" (0)
        END CASE
    ELSE
        // Terminal verdicts
        verdict ← raw_u32 AND 0xFF
        IF verdict > 5 THEN
            RETURN "UNKNOWN" (255)
        ELSE
            CASE verdict OF
                0: RETURN "DROP"
                1: RETURN "ACCEPT"
                2: RETURN "STOLEN"
                3: RETURN "QUEUE"
                4: RETURN "REPEAT"
                5: RETURN "STOP"
            END CASE
        END IF
    END IF
END FUNCTION
```

---

### 5.7. Kernel Symbol Lookup (Binary Search)

**Problem:** Convert instruction pointer (func_ip) to function name

**Data Source:** `/proc/kallsyms` (sorted by address)

**Algorithm:**
```python
class KallsymsLookup:
    def __init__(self):
        self.symbols: Dict[int, str] = {}
        self.sorted_addrs: List[int] = []
        self._load_kallsyms()

    def _load_kallsyms(self):
        """Load all function symbols (type 'T'/'t') into sorted array"""
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                addr_str, sym_type, name = line.strip().split()[:3]
                if sym_type in ['T', 't']:  # Function symbols
                    addr = int(addr_str, 16)
                    if addr > 0:
                        self.symbols[addr] = name

        self.sorted_addrs = sorted(self.symbols.keys())

    def lookup(self, func_ip: int) -> Optional[str]:
        """
        Find function name for given instruction pointer

        Uses binary search to find largest address <= func_ip
        (instruction may be offset from function start)
        """
        if not self.sorted_addrs or func_ip == 0:
            return None

        left, right = 0, len(self.sorted_addrs) - 1
        result_addr = None

        # Binary search for largest addr <= func_ip
        while left <= right:
            mid = (left + right) // 2
            addr = self.sorted_addrs[mid]

            if addr == func_ip:
                result_addr = addr
                break
            elif addr < func_ip:
                result_addr = addr  # Candidate
                left = mid + 1      # Search right
            else:
                right = mid - 1     # Search left

        if result_addr is not None:
            return self.symbols[result_addr]

        return None
```

**Pseudocode:**
```
FUNCTION kallsyms_lookup(func_ip):
    // Binary search for largest address <= func_ip

    IF func_ip = 0 OR sorted_addrs IS EMPTY THEN
        RETURN NULL
    END IF

    left ← 0
    right ← LENGTH(sorted_addrs) - 1
    result_addr ← NULL

    WHILE left <= right DO
        mid ← (left + right) / 2
        addr ← sorted_addrs[mid]

        IF addr = func_ip THEN
            result_addr ← addr
            BREAK
        ELSE IF addr < func_ip THEN
            result_addr ← addr  // Best candidate so far
            left ← mid + 1      // Search higher addresses
        ELSE
            right ← mid - 1     // Search lower addresses
        END IF
    END WHILE

    IF result_addr IS NOT NULL THEN
        RETURN symbols[result_addr]
    ELSE
        RETURN NULL
    END IF
END FUNCTION

Example:
  kallsyms entries:
    0xffffffff81234000  tcp_v4_rcv
    0xffffffff81234100  tcp_v4_do_rcv
    0xffffffff81234200  tcp_rcv_established

  lookup(0xffffffff81234050):
    → finds 0xffffffff81234000
    → returns "tcp_v4_rcv"
```

---

### 5.8. Rule Handle Extraction

**Problem:** nftables doesn't directly expose rule handle in kprobe context

**Solution:** Memory probing at known offsets

**Algorithm (eBPF):**
```c
static inline u64 extract_rule_handle(void *expr) {
    if (!expr)
        return 0;

    // Known offsets where rule handle might be stored
    s32 offsets[] = {-16, -24, -32, -40, -48, -56, -64, -72, -80, -96};

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        u64 potential_handle = 0;

        // Try to read memory at offset
        if (bpf_probe_read_kernel(&potential_handle, sizeof(potential_handle),
                                   (char *)expr + offsets[i]) == 0) {

            // Validate: handle should be reasonable value
            if (potential_handle > 0 && potential_handle < 0x100000) {
                return potential_handle;
            }
        }
    }

    return 0;  // Not found
}
```

**Pseudocode:**
```
FUNCTION extract_rule_handle(expr_ptr):
    IF expr_ptr IS NULL THEN
        RETURN 0
    END IF

    OFFSETS ← [-16, -24, -32, -40, -48, -56, -64, -72, -80, -96]

    FOR EACH offset IN OFFSETS DO
        TRY
            value ← READ_KERNEL_MEMORY(expr_ptr + offset, 8 bytes)

            // Heuristic validation
            IF value > 0 AND value < 0x100000 THEN
                RETURN value  // Found plausible handle
            END IF
        CATCH
            CONTINUE
        END TRY
    END FOR

    RETURN 0  // Not found
END FUNCTION
```

---

### 5.9. Packet Trace Quality Filter

**Algorithm:**
```python
def is_valuable_trace(self) -> bool:
    """
    Determine if packet trace is worth keeping

    Filters out:
    - Self-tracing (ports 3000, 5000, 5001)
    - Incomplete/corrupted packets
    - Very short-lived events
    """
    # Exclude self-tracing
    if self.src_port in EXCLUDED_PORTS or self.dst_port in EXCLUDED_PORTS:
        return False

    # Quality checks
    has_complete_info = (
        self.protocol is not None and
        self.src_ip is not None and
        self.dst_ip is not None
    )

    has_multiple_events = len(self.events) >= 2

    has_nft_activity = self.total_rules_evaluated > 0

    has_verdict_changes = self.verdict_changes > 0

    duration_ns = self.last_seen - self.first_seen
    has_significant_duration = duration_ns >= 10000  # 10 microseconds

    # Include if ANY quality indicator met
    return (
        has_complete_info or
        has_multiple_events or
        has_nft_activity or
        has_verdict_changes or
        has_significant_duration
    )
```

**Pseudocode:**
```
FUNCTION is_valuable_trace(trace):
    // Criterion 1: Not self-tracing
    IF trace.src_port IN EXCLUDED_PORTS OR
       trace.dst_port IN EXCLUDED_PORTS THEN
        RETURN FALSE
    END IF

    // Criterion 2: Quality indicators
    complete_info ← (trace.protocol ≠ NULL AND
                     trace.src_ip ≠ NULL AND
                     trace.dst_ip ≠ NULL)

    multiple_events ← (LENGTH(trace.events) >= 2)

    nft_activity ← (trace.total_rules_evaluated > 0)

    verdict_changes ← (trace.verdict_changes > 0)

    duration ← trace.last_seen - trace.first_seen
    significant_duration ← (duration >= 10000)  // 10µs

    // Include if ANY criterion met
    RETURN (complete_info OR
            multiple_events OR
            nft_activity OR
            verdict_changes OR
            significant_duration)
END FUNCTION
```

**Filtering Statistics:**
```
Example session:
  Total packets traced: 1532
  Valuable packets: 847
  Filtered packets: 685
  Filter reduction: 44.71%

Breakdown of filtered packets:
  - Self-tracing (ports 3000, 5000, 5001): 412 (60.1%)
  - Incomplete packet info: 189 (27.6%)
  - Single event only: 84 (12.3%)
```

---

## 6. CÁC CHỨC NĂNG CHÍNH

### 6.1. Authentication & Authorization

**Endpoints:**
```
POST   /api/auth/login          Login and get JWT tokens
GET    /api/auth/me             Get current user info
POST   /api/auth/refresh        Refresh access token
POST   /api/auth/logout         Logout (client-side)
POST   /api/auth/change-password  Change password
```

**Features:**
- JWT access token (24h expiry)
- JWT refresh token (30d expiry)
- Password hashing (Werkzeug)
- First-login detection
- SQLAlchemy ORM for data access

**Default Credentials:**
```
Username: root
Password: root
Email: root@localhost
```

---

### 6.2. Trace Session Management

**Endpoints:**
```
GET    /api/sessions            List all active sessions
POST   /api/sessions            Create new trace session
DELETE /api/sessions/{id}       Stop trace session
GET    /api/sessions/{id}/stats Get session statistics
```

**Session Modes:**

#### NFT Mode (Lightweight)
- **Probes:** 4 kprobes/kretprobes
  - `nft_do_chain` (entry/exit)
  - `nft_immediate_eval`
  - `nf_hook_slow` (return)
- **Data Collected:**
  - Rule evaluations
  - Verdicts (ACCEPT/DROP/JUMP/etc.)
  - Chain traversal
  - Hook points
- **Use Case:** Pure nftables analysis

#### FULL Mode (Comprehensive)
- **Probes:** 50+ kprobes across entire network stack
- **Coverage:**
  - NIC layer (napi_gro_receive, netif_receive_skb)
  - Driver (net_rx_action, napi_poll)
  - GRO (gro_normal_list, dev_gro_receive)
  - TC (tcf_classify)
  - Netfilter (nf_hook_slow, nf_reinject)
  - Conntrack (nf_conntrack_in, nf_confirm)
  - NAT (nf_nat_ipv4_fn)
  - Routing (ip_route_input_slow, fib_validate_source)
  - TCP/UDP (tcp_v4_rcv, udp_rcv)
  - Local delivery (ip_local_deliver)
  - Forwarding (ip_forward)
  - Output (ip_output, dev_queue_xmit)
- **Data Collected:** All of NFT mode + function call traces
- **Use Case:** Deep packet journey analysis

**Session Statistics:**
```json
{
  "session_id": "trace_1732012345678",
  "mode": "full",
  "running": true,
  "total_events": 15234,
  "events_per_second": 127,
  "active_packets": 23,
  "completed_packets": 847,
  "functions_traced": 52,
  "functions_hit": 41,
  "start_time": "2025-11-19T10:30:45.123Z",
  "uptime_seconds": 185.4,
  "stats": {
    "Inbound": {
      "NIC": 1523,
      "GRO": 1489,
      "Netfilter PREROUTING": 1487,
      "Routing Decision": 1452,
      "Netfilter INPUT": 1201,
      "TCP/UDP": 982
    },
    "Outbound": {
      "Application": 423,
      "TCP/UDP Output": 421,
      "Netfilter OUTPUT": 419,
      "Routing Lookup": 418,
      "Driver TX": 415
    }
  }
}
```

---

### 6.3. Trace File Analysis

**Endpoints:**
```
GET /api/files                       List all trace files
GET /api/traces/{filename}           Get full trace file
GET /api/traces/{filename}/packets   Get packets with filtering
GET /api/traces/{filename}/packets/{index}  Get packet detail
GET /api/download/{filename}         Download trace file
```

**Filtering Capabilities:**
```javascript
// Query parameters
{
  src_ip: "192.168.1.10",
  dst_ip: "8.8.8.8",
  src_port: 52341,
  dst_port: 443,
  protocol: "TCP",
  skb: "ffff8881",
  hook: "INPUT",
  verdict: "DROP",
  any_verdict: "DROP",        // Match any verdict in trace
  had_verdict_change: true,
  function: "tcp_v4_rcv",
  keyword: "conntrack",
  page: 1,
  per_page: 100
}
```

**Packet Detail Analysis:**
```json
{
  "packet_index": 42,
  "skb_addr": "0xffff88810abc1234",
  "protocol": 6,
  "protocol_name": "TCP",
  "src_ip": "192.168.1.10",
  "dst_ip": "8.8.8.8",
  "src_port": 52341,
  "dst_port": 443,
  "direction": "Outbound",
  "branch": "OUTPUT",
  "first_seen": 1732012345678901234,
  "last_seen": 1732012345679123456,
  "duration_ns": 222222,
  "final_verdict": "ACCEPT",
  "total_rules_evaluated": 5,
  "verdict_changes": 2,
  "unique_functions": 18,
  "functions_path": [
    "tcp_sendmsg",
    "tcp_write_xmit",
    "tcp_transmit_skb",
    "ip_local_out",
    "nf_hook_slow",
    "nft_do_chain",
    "ip_output",
    "ip_finish_output",
    "dev_queue_xmit",
    "..."
  ],
  "events": [...],
  "nft_events": [...],
  "analysis": {
    "verdict_chain": [
      {
        "timestamp": 1732012345678950000,
        "type": "rule_eval",
        "verdict": "CONTINUE",
        "hook": 3,
        "rule_handle": 42
      },
      {
        "timestamp": 1732012345679100000,
        "type": "chain_exit",
        "verdict": "ACCEPT",
        "hook": 3
      }
    ],
    "jump_goto_chain": [],
    "drop_reason": null,
    "flow_summary": [
      {
        "layer": "Transport",
        "functions": ["tcp_sendmsg", "tcp_write_xmit", "tcp_transmit_skb"]
      },
      {
        "layer": "IP Layer",
        "functions": ["ip_local_out", "ip_output", "ip_finish_output"]
      },
      {
        "layer": "Netfilter",
        "functions": ["nf_hook_slow", "nft_do_chain"]
      },
      {
        "layer": "Network Device",
        "functions": ["dev_queue_xmit", "dev_hard_start_xmit"]
      }
    ]
  }
}
```

---

### 6.4. NFTables Integration

**Endpoints:**
```
GET  /api/nft/health              Check nft availability
GET  /api/nft/rules               Get full ruleset tree
GET  /api/nft/tables              List all tables
GET  /api/nft/chains/{family}/{table}  Get chains
POST /api/nft/rule/add            Add new rule
POST /api/nft/rule/delete         Delete rule by handle
POST /api/nft/rule/update         Update existing rule
```

**Rule Management Example:**
```json
// Add rule
POST /api/nft/rule/add
{
  "family": "ip",
  "table": "filter",
  "chain": "input",
  "rule_text": "tcp dport 22 counter accept"
}

// Delete rule
POST /api/nft/rule/delete
{
  "family": "ip",
  "table": "filter",
  "chain": "input",
  "handle": 42
}

// Update rule
POST /api/nft/rule/update
{
  "family": "ip",
  "table": "filter",
  "chain": "input",
  "handle": 42,
  "new_rule_text": "tcp dport 2222 counter accept"
}
```

**Ruleset Tree Structure:**
```json
{
  "success": true,
  "tree": {
    "ip": {
      "filter": {
        "handle": 1,
        "chains": {
          "input": {
            "handle": 1,
            "type": "filter",
            "hook": "input",
            "prio": 0,
            "policy": "accept",
            "rules": [
              {
                "handle": 2,
                "rule_text": "tcp dport 22 counter packets 1523 bytes 98432 accept",
                "comment": "SSH access"
              },
              {
                "handle": 3,
                "rule_text": "tcp dport 80 counter packets 45231 bytes 5234567 accept"
              }
            ]
          },
          "forward": {...},
          "output": {...}
        }
      }
    },
    "ip6": {...}
  }
}
```

---

### 6.5. Real-time Visualization (WebSocket)

**Endpoints:**
```
WS  /socket.io/                   WebSocket connection
POST /api/realtime/enable         Enable real-time streaming
POST /api/realtime/disable        Disable real-time streaming
GET  /api/realtime/stats          Get real-time statistics
```

**Event Stream Format:**
```javascript
// Client connects
socket.on('connect', () => {
  console.log('Connected to real-time stream');
});

// Subscribe to session
socket.emit('subscribe', {session_id: 'trace_123'});

// Receive events
socket.on('packet_event', (data) => {
  console.log(data);
  /*
  {
    session_id: 'trace_123',
    hook: 1,                    // INPUT
    func_name: 'tcp_v4_rcv',
    verdict: 1,                 // ACCEPT
    protocol: 6,                // TCP
    src_ip: '192.168.1.10',
    dst_ip: '8.8.8.8',
    timestamp: 1732012345.678
  }
  */
});

// Receive aggregated stats
socket.on('session_stats', (data) => {
  console.log(data);
  /*
  {
    session_id: 'trace_123',
    events_per_second: 127,
    total_packets: 847,
    by_hook: {
      PREROUTING: 423,
      INPUT: 312,
      OUTPUT: 112
    },
    by_verdict: {
      ACCEPT: 801,
      DROP: 46
    }
  }
  */
});
```

---

### 6.6. Function Discovery

**Endpoints:**
```
POST /api/discover               Discover SKB functions
GET  /api/functions              Get discovered functions
GET  /api/functions/fixed        Get fixed function set
```

**Discovery Process:**
```python
discoverer = BTFSKBDiscoverer()

# Method 1: BTF (BPF Type Format)
functions_btf = discoverer.discover_from_btf()
# → Parses /sys/kernel/btf/vmlinux
# → Finds all functions with 'struct sk_buff *' parameter
# → ~200-500 functions depending on kernel

# Method 2: kallsyms heuristic
functions_kallsyms = discoverer.discover_from_kallsyms()
# → Scans /proc/kallsyms
# → Matches keywords: '_skb_', '_rcv', '_xmit', 'tcp_', 'udp_', etc.
# → ~100-300 additional functions

# Classification
discoverer.classify_all_functions()
# → Assign layers (Device, GRO, Netfilter, TCP, etc.)
# → Assign priorities (0=Critical, 1=Important, 2=Optional)
# → Assign categories (nft, tcp, udp, routing, etc.)
```

**Fixed Function Set (FULL Mode):**
```json
{
  "total_functions": 52,
  "function_map": {
    "Driver RX": {
      "functions": ["napi_gro_receive", "netif_receive_skb", ...],
      "hooks": ["PREROUTING"],
      "description": "Network device driver receive path"
    },
    "Netfilter Core": {
      "functions": ["nf_hook_slow", "nf_reinject", ...],
      "hooks": ["ALL"],
      "description": "Core netfilter hook processing"
    },
    "TCP Transport": {
      "functions": ["tcp_v4_rcv", "tcp_sendmsg", ...],
      "hooks": ["INPUT", "OUTPUT"],
      "description": "TCP protocol processing"
    }
  },
  "functions_list": [
    "napi_gro_receive",
    "netif_receive_skb",
    "nf_hook_slow",
    "..."
  ]
}
```

---

### 6.7. Health Check & System Info

**Endpoint:**
```
GET /api/health
```

**Response:**
```json
{
  "status": "ok",
  "bcc_available": true,
  "realtime_available": true,
  "timestamp": "2025-11-19T10:30:45.123Z",
  "kernel": "5.15.0-56-generic",
  "hostname": "nft-tracer-dev"
}
```

---

## 7. TỔNG KẾT

### 7.1. Điểm Mạnh của Kiến trúc

1. **Modularity:** Separation of concerns (auth, tracing, nftables, realtime)
2. **Scalability:** Thread-safe session management, concurrent tracing
3. **Performance:**
   - eBPF kernel-space filtering
   - Efficient deduplication
   - Binary search symbol lookup
4. **Flexibility:**
   - NFT vs FULL modes
   - Configurable function sets
   - Multiple filter options
5. **Real-time Capability:** WebSocket streaming for live monitoring
6. **Data Quality:** Intelligent filtering removes 40-60% noise

### 7.2. Các Thành phần Quan trọng Nhất

| Component | Lines of Code | Criticality | Purpose |
|-----------|---------------|-------------|---------|
| app.py | 2080 | ⭐⭐⭐⭐⭐ | Main orchestrator |
| TraceSession | ~500 | ⭐⭐⭐⭐⭐ | Core tracing logic |
| PacketTrace | ~320 | ⭐⭐⭐⭐⭐ | Data aggregation |
| full_tracer.bpf.c | ~800 | ⭐⭐⭐⭐⭐ | Kernel data collection |
| nft_tracer.bpf.c | ~600 | ⭐⭐⭐⭐ | NFT-specific tracing |
| auth.py | 174 | ⭐⭐⭐⭐ | Security layer |
| nftables_manager.py | 324 | ⭐⭐⭐ | Firewall integration |
| enhanced_skb_discoverer.py | 443 | ⭐⭐⭐ | Function discovery |

### 7.3. Technology Highlights

```
┌────────────────────────────────────────────────────────────┐
│                    KEY TECHNOLOGIES                         │
├────────────────────────────────────────────────────────────┤
│ eBPF/BCC:        Kernel tracing without recompilation     │
│ Flask:           Lightweight REST API framework            │
│ SQLAlchemy:      ORM with SQL injection protection        │
│ JWT:             Stateless authentication                  │
│ Socket.IO:       Bi-directional real-time communication   │
│ Binary Search:   O(log n) symbol resolution               │
│ Perf Buffers:    Efficient kernel→userspace data transfer │
│ Threading:       Concurrent session management             │
└────────────────────────────────────────────────────────────┘
```

---

## 8. DEPLOYMENT CONFIGURATION

### 8.1. Environment Variables

```bash
# Backend Configuration
BACKEND_PORT=5000
FRONTEND_PORT=3000
SOCKETIO_PORT=5001

# Security
JWT_SECRET_KEY=your-secret-key-change-in-production  # ⚠️ CHANGE IN PROD

# Database
SQLALCHEMY_DATABASE_URI=sqlite:///nft_tracer.db

# eBPF
BCC_KERNEL_SOURCE=/lib/modules/$(uname -r)/build
```

### 8.2. System Requirements

```yaml
OS: Linux kernel >= 4.18 (for eBPF)
Python: >= 3.8
Packages:
  - bcc-tools
  - python3-bcc
  - nftables
  - libnftnl-dev
Privileges: root (for eBPF and nftables access)
```

### 8.3. Performance Tuning

```python
# BPF perf buffer size (in pages)
page_cnt=512  # 2MB buffer (512 pages × 4KB)

# Trace timeout
trace_timeout_ns = 1_000_000_000  # 1 second

# Deduplication windows
NFT_DEDUP_WINDOW = 5000    # 5 microseconds
FUNC_DEDUP_WINDOW = 1000   # 1 millisecond

# Session cleanup interval
cleanup_interval = 2  # seconds

# BPF hash map sizes
BPF_HASH(skb_map, ..., 10240)     # 10K entries
BPF_HASH(hook_map, ..., 10240)    # 10K entries
```

---

**Tài liệu này được tạo tự động từ phân tích source code backend.**

*Ngày tạo: 2025-11-19*
*Phiên bản: 1.0*
*Người phân tích: Claude Code (Anthropic)*
