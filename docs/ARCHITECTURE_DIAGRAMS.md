# SƠ ĐỒ KIẾN TRÚC TRỰC QUAN - NFT TRACER

## 1. TỔNG QUAN HỆ THỐNG

```
                              NFT TRACER APP

┌───────────────────────────────────────────────────────────────────────────┐
│                                                                           │
│                          ┌─────────────────┐                             │
│                          │   Web Browser   │                             │
│                          │   (Frontend)    │                             │
│                          └────────┬────────┘                             │
│                                   │                                       │
│                    ┌──────────────┴──────────────┐                       │
│                    │                             │                       │
│              HTTP REST API               WebSocket (Socket.IO)           │
│                    │                             │                       │
│                    ▼                             ▼                       │
│         ┌──────────────────────────────────────────────────┐            │
│         │         Flask Backend (Python)                   │            │
│         │  ┌────────────┐  ┌──────────────────────────┐   │            │
│         │  │   Auth     │  │   Session Manager        │   │            │
│         │  │  (JWT)     │  │  ┌────────────────────┐  │   │            │
│         │  └────────────┘  │  │  TraceSession      │  │   │            │
│         │                  │  │  • NFT Mode        │  │   │            │
│         │  ┌────────────┐  │  │  • FULL Mode       │  │   │            │
│         │  │  NFTables  │  │  └────────┬───────────┘  │   │            │
│         │  │  Manager   │  │           │              │   │            │
│         │  └────────────┘  └───────────┼──────────────┘   │            │
│         │                              │                  │            │
│         │  ┌────────────┐  ┌───────────▼──────────────┐   │            │
│         │  │  SQLite DB │  │   BCC (BPF Compiler)     │   │            │
│         │  │  • Users   │  │   • Load eBPF programs   │   │            │
│         │  └────────────┘  │   • Attach kprobes       │   │            │
│         │                  │   • Poll perf buffers    │   │            │
│         │  ┌────────────┐  └───────────┬──────────────┘   │            │
│         │  │JSON Export │              │                  │            │
│         │  │ • Traces   │              │                  │            │
│         │  └────────────┘              │                  │            │
│         └──────────────────────────────┼──────────────────┘            │
│                                        │                                │
│                                        │ eBPF Interface                 │
│                                        ▼                                │
│         ┌───────────────────────────────────────────────┐              │
│         │       Linux Kernel (Kernel Space)             │              │
│         │  ┌──────────────────────────────────────────┐ │              │
│         │  │      eBPF Programs (C)                   │ │              │
│         │  │  ┌────────────────┐  ┌────────────────┐  │ │              │
│         │  │  │ nft_tracer.bpf │  │ full_tracer.bpf│  │ │              │
│         │  │  │                │  │                │  │ │              │
│         │  │  │ • nft_do_chain │  │ • 50+ funcs    │  │ │              │
│         │  │  │ • nf_hook_slow │  │ • All layers   │  │ │              │
│         │  │  └────────┬───────┘  └───────┬────────┘  │ │              │
│         │  │           │                  │           │ │              │
│         │  │           └──────────┬───────┘           │ │              │
│         │  │                      │                   │ │              │
│         │  │           ┌──────────▼──────────┐        │ │              │
│         │  │           │  BPF Perf Buffers   │        │ │              │
│         │  │           └─────────────────────┘        │ │              │
│         │  └──────────────────────────────────────────┘ │              │
│         │                      │                        │              │
│         │                      │ kprobes                │              │
│         │                      ▼                        │              │
│         │  ┌──────────────────────────────────────────┐ │              │
│         │  │    Linux Network Stack                   │ │              │
│         │  │                                           │ │              │
│         │  │  NIC → Driver → GRO → TC → Netfilter     │ │              │
│         │  │    → Routing → TCP/UDP → Socket          │ │              │
│         │  └──────────────────────────────────────────┘ │              │
│         └───────────────────────────────────────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. PACKET JOURNEY - FULL MODE TRACING

```
┌────────────────────────────────────────────────────────────────────────┐
│                    INBOUND PACKET JOURNEY                              │
└────────────────────────────────────────────────────────────────────────┘

 Network Cable/Wireless
       │
       ▼
┌──────────────────┐ ◄────── napi_gro_receive, netif_receive_skb
│   1. NIC Layer   │         (kprobes attached)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── net_rx_action, process_backlog
│ 2. Driver (NAPI) │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── gro_normal_list, dev_gro_receive
│   3. GRO Layer   │         (Generic Receive Offload)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── tcf_classify, dev_queue_xmit_nit
│ 4. TC Ingress    │         (Traffic Control)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── nf_hook_slow (hook=0)
│ 5. NF PREROUTING │         HOOK POINT: PREROUTING
│    (Netfilter)   │         • nft_do_chain (kprobe)
│                  │         • Connection tracking
│    ┌──────────┐  │         • NAT PREROUTING
│    │nft_do_   │  │
│    │chain     │  │
│    └──────────┘  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── ip_route_input_slow, fib_validate_source
│ 6. Routing       │         Decision: LOCAL or FORWARD?
│    Decision      │
└────────┬─────────┘
         │
         ├─────────────────────────────────┐
         │                                 │
         │ LOCAL DELIVERY                  │ FORWARD
         ▼                                 ▼
┌──────────────────┐              ┌──────────────────┐
│ 7a. Local        │              │ 7b. IP Forward   │
│     Delivery     │              │                  │
│                  │              └────────┬─────────┘
│ ip_local_deliver │                       │
└────────┬─────────┘                       ▼
         │                          ┌──────────────────┐
         ▼                          │ NF FORWARD       │
┌──────────────────┐                │   (Netfilter)    │
│ 8. NF INPUT      │                └────────┬─────────┘
│    (Netfilter)   │                         │
│                  │                         ▼
│  nf_hook_slow    │                  ┌──────────────────┐
│  (hook=1)        │                  │ NF POSTROUTING   │
└────────┬─────────┘                  └────────┬─────────┘
         │                                     │
         ▼                                     ▼
┌──────────────────┐                    ┌──────────────────┐
│ 9. TCP/UDP       │                    │ TX Path          │
│    Processing    │                    │ (dev_queue_xmit) │
│                  │                    └──────────────────┘
│ tcp_v4_rcv       │
│ udp_rcv          │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 10. Socket Layer │
│                  │
│ Application      │
└──────────────────┘


┌────────────────────────────────────────────────────────────────────────┐
│                    OUTBOUND PACKET JOURNEY                             │
└────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐
│   Application    │
│   (sendmsg)      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── tcp_sendmsg, udp_sendmsg
│ 1. TCP/UDP       │
│    Output        │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── nf_hook_slow (hook=3)
│ 2. NF OUTPUT     │         HOOK POINT: OUTPUT
│    (Netfilter)   │         • nft_do_chain
│                  │         • Connection tracking
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── ip_route_output_key_hash
│ 3. Routing       │         Find output interface
│    Lookup        │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── nf_nat_ipv4_out
│ 4. NAT           │
│    POSTROUTING   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── nf_hook_slow (hook=4)
│ 5. NF            │         HOOK POINT: POSTROUTING
│    POSTROUTING   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── sch_direct_xmit
│ 6. TC Egress     │
│    (QDisc)       │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐ ◄────── dev_queue_xmit, dev_hard_start_xmit
│ 7. Driver TX     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   8. NIC TX      │
└────────┬─────────┘
         │
         ▼
   Network Cable/Wireless
```

---

## 3. eBPF EVENT COLLECTION ARCHITECTURE

```
┌───────────────────────────────────────────────────────────────────────┐
│                       KERNEL SPACE                                     │
│                                                                        │
│  Network Function Executes (e.g., tcp_v4_rcv)                        │
│         │                                                              │
│         ▼                                                              │
│  ┌─────────────────────────────────────────────┐                     │
│  │  kprobe fires (trace_skb_func)              │                     │
│  │  • Read function IP                         │                     │
│  │  • Extract SKB fields:                      │                     │
│  │    - skb_addr (struct sk_buff *)            │                     │
│  │    - protocol, src_ip, dst_ip               │                     │
│  │    - src_port, dst_port                     │                     │
│  │  • Read current process name (comm)         │                     │
│  │  • Get timestamp (bpf_ktime_get_ns)         │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  Build trace_event struct                   │                     │
│  │  {                                           │                     │
│  │    timestamp: 1732012345678901234,          │                     │
│  │    skb_addr: 0xffff88810abc1234,            │                     │
│  │    func_ip: 0xffffffff81234567,             │                     │
│  │    event_type: 0,  // FUNCTION_CALL         │                     │
│  │    protocol: 6,    // TCP                   │                     │
│  │    src_ip: 0xC0A8010A,  // 192.168.1.10    │                     │
│  │    dst_ip: 0x08080808,  // 8.8.8.8         │                     │
│  │    src_port: 52341,                         │                     │
│  │    dst_port: 443,                           │                     │
│  │    comm: "curl"                             │                     │
│  │  }                                           │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  bpf_perf_event_output(events)              │                     │
│  │  → Write to perf ring buffer                │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
└────────────────────┼──────────────────────────────────────────────────┘
                     │
                     │ Perf Buffer (shared memory)
                     │
┌────────────────────▼──────────────────────────────────────────────────┐
│                       USER SPACE                                       │
│                                                                        │
│  ┌─────────────────────────────────────────────┐                     │
│  │  Polling Thread (_poll_full_events)         │                     │
│  │  while running:                              │                     │
│  │    bpf.perf_buffer_poll(timeout=10)         │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  Callback: _handle_full_event(cpu, data)    │                     │
│  │  1. Parse struct from buffer                 │                     │
│  │  2. Lock acquisition                         │                     │
│  │  3. Resolve function name:                   │                     │
│  │     kallsyms.lookup(func_ip)                │                     │
│  │     → "tcp_v4_rcv"                           │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  Create packet key (5-tuple)                │                     │
│  │  key = make_packet_key(                     │                     │
│  │    skb_addr, src_ip, dst_ip,                │                     │
│  │    src_port, dst_port, protocol             │                     │
│  │  )                                           │                     │
│  │  → "ffff88810abc1234:6:192.168.1.10:52341:  │                     │
│  │     8.8.8.8:443"                             │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  Lookup or Create PacketTrace                │                     │
│  │  if key not in packet_traces:                │                     │
│  │    trace = PacketTrace(                      │                     │
│  │      skb_addr=skb_addr,                      │                     │
│  │      first_seen=timestamp,                   │                     │
│  │      events=[],                              │                     │
│  │      mode="full"                             │                     │
│  │    )                                         │                     │
│  │    packet_traces[key] = trace                │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  trace.add_universal_event(event)            │                     │
│  │  • Deduplication check                       │                     │
│  │  • Layer classification                      │                     │
│  │  • Direction detection                       │                     │
│  │  • Append to events[]                        │                     │
│  │  • Update statistics                         │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  WebSocket broadcast (if enabled)            │                     │
│  │  socketio.emit('packet_event', {             │                     │
│  │    session_id, func_name, verdict, ...      │                     │
│  │  })                                          │                     │
│  └─────────────────┬───────────────────────────┘                     │
│                    │                                                  │
│                    ▼                                                  │
│  ┌─────────────────────────────────────────────┐                     │
│  │  Lock release                                │                     │
│  └─────────────────────────────────────────────┘                     │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. SESSION STATE MACHINE

```
┌──────────────┐
│   CREATED    │  SessionManager.create_session()
└──────┬───────┘
       │
       │ session.start()
       │
       ▼
┌──────────────────────────────────────┐
│           STARTING                   │
│  • Load eBPF program                 │
│  • Attach kprobes                    │
│  • Open perf buffer                  │
│  • Start polling thread              │
└──────┬───────────────────────────────┘
       │
       │ Success
       │
       ▼
┌──────────────────────────────────────┐
│           RUNNING                    │
│  ┌────────────────────────────────┐  │
│  │ Polling Thread                 │  │
│  │ • Poll perf buffer             │  │
│  │ • Handle events                │  │
│  │ • Update traces                │  │
│  └────────────────────────────────┘  │
│  ┌────────────────────────────────┐  │
│  │ Cleanup Thread                 │  │
│  │ • Check trace timeouts (1s)    │  │
│  │ • Move completed traces        │  │
│  └────────────────────────────────┘  │
│  ┌────────────────────────────────┐  │
│  │ State                          │  │
│  │ • packet_traces: {...}         │  │
│  │ • completed_traces: [...]      │  │
│  │ • total_events: 15234          │  │
│  │ • functions_hit: {...}         │  │
│  └────────────────────────────────┘  │
└──────┬───────────────────────────────┘
       │
       │ session.stop()
       │
       ▼
┌──────────────────────────────────────┐
│           STOPPING                   │
│  • Set running = False               │
│  • Join threads (timeout 2s)         │
│  • Flush active → completed          │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│           EXPORTING                  │
│  • Filter valuable traces            │
│  • Build summary JSON                │
│  • Write to file                     │
│  • Cleanup BPF objects               │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────┐
│   STOPPED    │  Return JSON file path
└──────────────┘


State Transitions:
  CREATED → STARTING: start() called
  STARTING → RUNNING: eBPF setup successful
  STARTING → FAILED: eBPF setup failed
  RUNNING → STOPPING: stop() called
  STOPPING → EXPORTING: threads joined
  EXPORTING → STOPPED: JSON exported
```

---

## 5. AUTHENTICATION FLOW

```
┌──────────────┐
│    Client    │
└──────┬───────┘
       │
       │ POST /api/auth/login
       │ {username: "root", password: "root"}
       │
       ▼
┌──────────────────────────────────────┐
│   Flask Route: /api/auth/login       │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│   authenticate_user(username, pwd)   │
│   1. Query DB: User.query.filter_by  │
│   2. Check is_active                 │
│   3. Verify password hash            │
│   4. Update last_login               │
└──────┬───────────────────────────────┘
       │
       │ User object
       │
       ▼
┌──────────────────────────────────────┐
│   create_tokens(user.id)             │
│   • create_access_token (24h)        │
│   • create_refresh_token (30d)       │
└──────┬───────────────────────────────┘
       │
       │ {access_token, refresh_token}
       │
       ▼
┌──────────────┐
│    Client    │ Stores tokens
│              │ in localStorage/cookies
└──────┬───────┘
       │
       │
       │ Subsequent API calls
       │ Authorization: Bearer <access_token>
       │
       ▼
┌──────────────────────────────────────┐
│   @token_required decorator          │
│   1. Extract token from header       │
│   2. verify_jwt_in_request()         │
│   3. get_jwt_identity() → user_id    │
│   4. Query User.query.get(user_id)   │
│   5. Inject user into route handler  │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│   Protected Route Handler            │
│   def my_route(user=None):           │
│     # user object available          │
└──────────────────────────────────────┘


Token Expiry Handling:
┌──────────────┐
│ Access Token │
│  Expired     │
└──────┬───────┘
       │
       │ POST /api/auth/refresh
       │ Authorization: Bearer <refresh_token>
       │
       ▼
┌──────────────────────────────────────┐
│   @jwt_required(refresh=True)        │
│   • Validate refresh token           │
│   • Create new access token          │
│   • Return new tokens                │
└──────┬───────────────────────────────┘
       │
       ▼
┌──────────────┐
│ New Tokens   │
└──────────────┘
```

---

## 6. DATA MODEL RELATIONSHIPS

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATABASE SCHEMA                              │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│       User           │
├──────────────────────┤
│ id (PK)              │───┐
│ username [unique]    │   │
│ email [unique]       │   │ 1:N (implicit via JWT)
│ password_hash        │   │
│ is_active            │   │
│ first_login          │   │
│ created_at           │   │
│ last_login           │   │
└──────────────────────┘   │
                           │
                           │ Creates
                           │
                           ▼
                  ┌──────────────────┐
                  │   TraceSession   │ (In-memory, not persisted)
                  ├──────────────────┤
                  │ session_id       │
                  │ mode             │
                  │ start_time       │
                  │ running          │
                  │ bpf_nft          │───► BPF program instance
                  │ bpf_full         │
                  └────────┬─────────┘
                           │
                           │ Contains
                           │
                           ▼
                  ┌──────────────────┐
                  │  PacketTrace     │ (In-memory dict)
                  ├──────────────────┤
                  │ skb_addr         │ (key component)
                  │ first_seen       │
                  │ last_seen        │
                  │ events[]         │───┐
                  │ protocol         │   │
                  │ src_ip, dst_ip   │   │
                  │ src_port, dst_port│  │
                  │ final_verdict    │   │
                  │ functions_called │   │
                  └──────────────────┘   │
                                         │
                                         │ Contains
                                         │
                           ┌─────────────┴─────────────┐
                           │                           │
                           ▼                           ▼
                  ┌──────────────────┐      ┌──────────────────┐
                  │   NFTEvent       │      │ UniversalEvent   │
                  ├──────────────────┤      ├──────────────────┤
                  │ timestamp        │      │ timestamp        │
                  │ skb_addr         │      │ skb_addr         │
                  │ chain_addr       │      │ func_name        │
                  │ expr_addr        │      │ protocol         │
                  │ verdict          │      │ src_ip, dst_ip   │
                  │ hook             │      │ src_port, dst_port│
                  │ rule_handle      │      │ length           │
                  │ trace_type       │      │ comm             │
                  └──────────────────┘      └──────────────────┘


┌─────────────────────────────────────────────────────────────────────┐
│                         FILE STORAGE                                 │
└─────────────────────────────────────────────────────────────────────┘

backend/data/output/
  ├── trace_nft_trace_123_20251119_103045.json
  ├── trace_full_trace_456_20251119_104512.json
  └── trace_full_trace_789_20251119_110234.json

Each JSON file structure:
{
  "session": {
    "id": "trace_123",
    "mode": "full",
    "start_time": "2025-11-19T10:30:45Z",
    "end_time": "2025-11-19T10:35:12Z"
  },
  "statistics": {
    "total_events": 15234,
    "total_packets": 1532,
    "valuable_packets": 847,
    "functions_traced": 52,
    "top_functions": {...}
  },
  "traces": [
    {
      "skb_addr": "0xffff88810abc1234",
      "protocol_name": "TCP",
      "src_ip": "192.168.1.10",
      "dst_ip": "8.8.8.8",
      "events": [...],
      "nft_events": [...]
    },
    ...
  ]
}
```

---

## 7. CONCURRENCY MODEL

```
┌─────────────────────────────────────────────────────────────────────┐
│                     THREADING ARCHITECTURE                           │
└─────────────────────────────────────────────────────────────────────┘

Main Thread (Flask)
  │
  ├─► Request Handler Threads (Flask built-in)
  │   ├─► GET /api/sessions
  │   ├─► POST /api/sessions  ───────┐
  │   ├─► DELETE /api/sessions/{id}  │
  │   └─► GET /api/sessions/{id}/stats│
  │                                   │
  │                                   │ Creates
  │                                   ▼
  └─► Session Manager ──────► TraceSession
                                   │
                                   ├─► Polling Thread
                                   │   │
                                   │   └─► Infinite Loop:
                                   │       while running:
                                   │         bpf.perf_buffer_poll(10ms)
                                   │         ├─► _handle_nft_event()
                                   │         │   │
                                   │         │   └─► with self.lock:
                                   │         │         ├─► Update packet_traces{}
                                   │         │         └─► Update statistics
                                   │         │
                                   │         └─► _handle_full_event()
                                   │             │
                                   │             └─► with self.lock:
                                   │                   ├─► Update packet_traces{}
                                   │                   └─► Update statistics
                                   │
                                   └─► Cleanup Thread
                                       │
                                       └─► Infinite Loop:
                                           while running:
                                             sleep(2s)
                                             with self.lock:
                                               Move timed-out traces:
                                               packet_traces → completed_traces


Lock Hierarchy:
  SessionManager.lock
    │
    └─► TraceSession.lock
          │
          ├─► Protects: packet_traces{}, completed_traces[]
          ├─► Held during: event handling, cleanup, stats query
          └─► Lock duration: < 1ms typically

Deadlock Prevention:
  • Single lock per session (no nested locks)
  • Consistent lock acquisition order
  • Short critical sections
  • No blocking operations inside lock


Thread Communication:
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Polling    │  lock   │   Shared     │  lock   │   Cleanup    │
│   Thread     │────────►│   Data       │◄────────│   Thread     │
│              │         │              │         │              │
│ Writes:      │         │ • packet_    │         │ Reads:       │
│ • events     │         │   traces{}   │         │ • last_seen  │
│ • stats      │         │ • completed_ │         │              │
│              │         │   traces[]   │         │ Writes:      │
└──────────────┘         │ • total_     │         │ • move traces│
                         │   events     │         └──────────────┘
                         └──────────────┘
                                │
                                │ lock (read-only)
                                ▼
                         ┌──────────────┐
                         │   API        │
                         │   Handler    │
                         │              │
                         │ Reads:       │
                         │ • stats      │
                         │ • traces     │
                         └──────────────┘
```

---

## 8. PERFORMANCE CHARACTERISTICS

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PERFORMANCE METRICS                               │
└─────────────────────────────────────────────────────────────────────┘

eBPF Overhead:
  Per-event overhead:  < 1 microsecond (kprobe + data extraction)
  Context switch:      None (in-kernel processing)
  Packet impact:       Negligible (no packet delay)

Perf Buffer:
  Size:                512 pages × 4KB = 2 MB
  Poll interval:       10 milliseconds
  Throughput:          > 100,000 events/second
  Loss rate:           < 0.1% at normal load

User-space Processing:
  Event handling:      100-500 microseconds
  Lock contention:     < 10 microseconds (typical)
  Memory per packet:   ~2 KB (PacketTrace object)
  Deduplication:       O(1) hash lookup

Symbol Resolution:
  Algorithm:           Binary search
  Complexity:          O(log n), n ≈ 50,000 symbols
  Time:                < 10 microseconds
  Cache:               kallsyms loaded once at startup

Trace Export:
  File size:           ~1-10 MB per session (100-1000 packets)
  Export time:         < 100 milliseconds
  Compression:         Not used (human-readable JSON)

Scalability:
  Max sessions:        Limited by memory (typically 5-10 concurrent)
  Max packets/session: Limited by memory (typically 10,000-100,000)
  Max events/second:   100,000+ (kernel-limited)
  Max trace duration:  No limit (but memory grows linearly)


┌─────────────────────────────────────────────────────────────────────┐
│                    RESOURCE CONSUMPTION                              │
└─────────────────────────────────────────────────────────────────────┘

Memory Usage (per session):
  Base overhead:       ~50 MB (BCC/eBPF)
  Per packet trace:    ~2 KB
  Per event:           ~200 bytes
  Example (1000 pkts, 10 events/pkt):
    50 MB + (1000 × 2 KB) + (10000 × 200 bytes) ≈ 54 MB

CPU Usage:
  Idle:                < 1%
  Active tracing:      5-15% (1 core)
  Peak (high traffic): 20-30% (1 core)
  eBPF overhead:       < 2%

Disk I/O:
  During tracing:      Minimal (only metadata)
  Export:              Sequential write (fast)
  Typical file:        1-10 MB


┌─────────────────────────────────────────────────────────────────────┐
│                    OPTIMIZATION TECHNIQUES                           │
└─────────────────────────────────────────────────────────────────────┘

1. Deduplication:
   • Reduces events by 40-60%
   • Time windows: 5µs (NFT), 1ms (functions)

2. Quality Filtering:
   • Removes 40-70% low-value traces
   • Export size reduction: 50-80%

3. Composite Keys:
   • 5-tuple + SKB address
   • Prevents false packet merging
   • O(1) lookup in dict

4. Binary Search:
   • Symbol resolution: O(log n)
   • 50,000 symbols → ~16 comparisons

5. Perf Buffers:
   • Zero-copy from kernel
   • Batch processing
   • Efficient memory usage

6. Lock-free Read Paths:
   • Most data structures read-optimized
   • Locks only for writes
   • Short critical sections
```

---

**Tài liệu này cung cấp cái nhìn trực quan về kiến trúc hệ thống.**

*Ngày tạo: 2025-11-19*
*Phiên bản: 1.0*
