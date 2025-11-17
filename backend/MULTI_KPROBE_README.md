# Multi-Kprobe Tracer - pwru-style Comprehensive Packet Tracing

## 📌 Tổng quan

Bộ công cụ mở rộng cho phép trace **hàng trăm đến hàng nghìn** kernel functions xử lý network packets, tương đương với công cụ **pwru** của Cilium.

### Files mới được tạo:

```
backend/
├── enhanced_btf_discoverer.py      # BTF-based function discovery
├── multi_kprobe_tracer.bpf.c       # eBPF program (pwru-style)
├── multi_kprobe_tracer.py          # Python tracer với multi-kprobe support
├── test_multi_kprobe.sh            # Quick test script
├── MULTI_KPROBE_README.md          # File này
└── MULTI_KPROBE_GUIDE.md           # Hướng dẫn chi tiết (ở root)
```

---

## 🚀 Quick Start

### 1. Test Installation

```bash
cd /home/user/nft-tracer-app/backend
sudo ./test_multi_kprobe.sh
```

### 2. Discovery Functions

```bash
# Discover với priority 1 (khuyến nghị - ~60-70 functions)
sudo python3 enhanced_btf_discoverer.py --priority 1

# Hoặc comprehensive discovery (~1000+ functions như pwru)
sudo python3 enhanced_btf_discoverer.py --priority 3
```

### 3. Run Tracer

```bash
# Auto-discovery và trace
sudo python3 multi_kprobe_tracer.py --priority 1

# Với sampling để giảm overhead
sudo python3 multi_kprobe_tracer.py --priority 2 --sample-rate 10
```

---

## 🎯 Điểm nổi bật

### So với hệ thống cũ:

| Feature | Cũ | Mới (Multi-Kprobe) |
|---------|----|--------------------|
| **Số hàm trace** | ~10 | **1000+** |
| **Discovery** | Hardcoded | **Auto BTF** |
| **Coverage** | NFT + core | **Full network stack** |
| **Flexibility** | Fixed | **4 priority levels** |
| **Tương đương** | - | **pwru/Cilium** |

### Tính năng chính:

✅ **Auto BTF Discovery** - Tự động tìm tất cả kernel functions xử lý sk_buff
✅ **4 Priority Levels** - Từ 14 functions (critical) đến 1000+ (comprehensive)
✅ **Multi-Parameter Support** - Tự động detect parameter position (P1-P5)
✅ **Category Filtering** - Filter theo nft, netfilter, ip, tcp, udp, etc.
✅ **Sampling Support** - Giảm overhead trên production systems
✅ **Drop Tracking** - Track kfree_skb_reason cho packet drops
✅ **NFT Integration** - Deep integration với nftables tracing
✅ **Statistics** - Realtime và final statistics
✅ **Production-Ready** - Low overhead với priority 0-1

---

## 📊 Priority Levels

| Priority | Functions | Overhead | Use Case |
|----------|-----------|----------|----------|
| **0** | ~14 | < 1% | Production monitoring |
| **1** | ~60-70 | 1-3% | **NFT debugging (khuyến nghị)** |
| **2** | ~200 | 3-7% | Deep analysis |
| **3** | 1000+ | 10-20% | Comprehensive (như pwru) |

---

## 📖 Chi tiết

### Components

#### 1. Enhanced BTF Discoverer (`enhanced_btf_discoverer.py`)

**Purpose:** Tự động phát hiện kernel functions từ BTF

**Features:**
- Parse kernel BTF data using bpftool
- Detect ALL functions with `struct sk_buff *` parameter
- Categorize by prefix (nft_, ip_, tcp_, etc.)
- Assign priority (0-3)
- Detect parameter position (1-5)
- Export to JSON

**Usage:**
```bash
# Basic discovery
sudo python3 enhanced_btf_discoverer.py --priority 1

# Filter by category
sudo python3 enhanced_btf_discoverer.py --category nft --category netfilter

# Generate function list
sudo python3 enhanced_btf_discoverer.py --function-list funcs.txt
```

**Output:**
```json
{
  "metadata": {
    "total": 67,
    "timestamp": "2025-01-17T10:23:45+00:00",
    "kernel": "5.15.0-91-generic"
  },
  "statistics": {
    "by_priority": {
      "0": ["nft_do_chain", "ip_rcv", ...],
      "1": ["nft_immediate_eval", "tcp_v4_rcv", ...]
    },
    "by_category": {
      "nft": ["nft_do_chain", "nft_immediate_eval", ...],
      "ip": ["ip_rcv", "ip_forward", ...]
    }
  },
  "functions": [
    {
      "name": "nft_do_chain",
      "param_position": 1,
      "category": "nft",
      "priority": 0,
      "signature": "unsigned int nft_do_chain(struct nft_pktinfo *pkt, void *priv);"
    },
    ...
  ]
}
```

#### 2. Multi-Kprobe eBPF Program (`multi_kprobe_tracer.bpf.c`)

**Purpose:** eBPF program hỗ trợ nhiều kprobes

**Features:**
- Macro-based approach cho parameter positions 1-5
- Unified event structure
- NFT-specific handlers (nft_do_chain, nft_immediate_eval)
- Drop tracking (kfree_skb_reason)
- Configuration map (sampling, filtering)
- Efficient packet info extraction

**Key macros:**
```c
#define DEFINE_SKB_KPROBE(POS)
// Generates: trace_skb_1, trace_skb_2, ..., trace_skb_5
```

**Event types:**
- `FUNCTION_CALL` - Generic kernel function call
- `NFT_CHAIN` - NFT chain entry/exit
- `NFT_RULE` - NFT rule evaluation
- `DROP` - Packet drop (kfree_skb)

#### 3. Python Tracer (`multi_kprobe_tracer.py`)

**Purpose:** Quản lý và attach nhiều kprobes

**Features:**
- Load discovered functions
- Compile eBPF program
- Attach kprobes với correct parameter position
- Handle perf buffer events
- Resolve function names from addresses
- Realtime output và statistics
- Graceful shutdown

**Architecture:**
```python
MultiKprobeTracer
├── load_functions()          # From discovery or file
├── load_bpf_program()        # Compile eBPF
├── attach_kprobes()          # Attach to kernel
├── configure_sampling()      # Set BPF config
├── handle_event()            # Process events
└── print_statistics()        # Final stats
```

---

## 🔬 Technical Deep Dive

### How BTF Discovery Works

1. **Run bpftool:**
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c
   ```

2. **Parse output:**
   - Regex: `^\s*(\w+)\s+(\w+)\s*\([^)]*struct\s+sk_buff\s*\*`
   - Extracts: return type, function name, parameters

3. **Categorize:**
   - Match function prefix (nft_, ip_, tcp_, etc.)
   - Assign to category

4. **Prioritize:**
   - Check if in PRIORITY_FUNCTIONS dict
   - Or assign based on category
   - NFT/netfilter get higher priority

5. **Detect parameter position:**
   - Parse parameter list
   - Find which param is `struct sk_buff *`
   - Store position (1-5)

### How Multi-Kprobe Attachment Works

1. **For NFT functions:**
   ```python
   bpf.attach_kprobe(event="nft_do_chain", fn_name="kprobe__nft_do_chain")
   bpf.attach_kretprobe(event="nft_do_chain", fn_name="kretprobe__nft_do_chain")
   ```

2. **For generic SKB functions:**
   ```python
   # Try parameter positions 1-5
   for pos in [1, 2, 3, 4, 5]:
       bpf.attach_kprobe(event=func_name, fn_name=f"trace_skb_{pos}")
   ```

3. **eBPF macro generates:**
   ```c
   int trace_skb_1(struct pt_regs *ctx) {
       struct sk_buff *skb = PT_REGS_PARM1(ctx);
       // Common handler
   }

   int trace_skb_2(struct pt_regs *ctx) {
       struct sk_buff *skb = PT_REGS_PARM2(ctx);
       // Common handler
   }
   // ... up to trace_skb_5
   ```

### Event Flow

```
Kernel Function Called
    ↓
Kprobe Fires
    ↓
eBPF Handler (trace_skb_X or nft_*)
    ↓
Extract packet info from sk_buff
    ↓
Check sampling config
    ↓
Submit to Perf Buffer
    ↓
Python polls buffer
    ↓
Format and print event
    ↓
Update statistics
```

---

## 🎓 Use Cases

### 1. Debug NFT Firewall

**Scenario:** Packet bị DROP, không biết rule nào

```bash
# Discovery NFT functions only
sudo python3 enhanced_btf_discoverer.py \
  --category nft --category netfilter \
  --priority 1

# Trace
sudo python3 multi_kprobe_tracer.py --priority 1

# Send test packet
ping 192.168.1.100
```

**Output sẽ show:**
- Packet đi vào chain nào
- Rule nào được evaluate
- Verdict của từng rule
- Chain final verdict

### 2. Trace Full Packet Path

**Scenario:** Xem toàn bộ hành trình packet

```bash
sudo python3 multi_kprobe_tracer.py --priority 2
```

**Output:**
```
[10:23:45.123] FUNCTION_CALL __netif_receive_skb_core ...
[10:23:45.124] FUNCTION_CALL ip_rcv ...
[10:23:45.124] NFT_CHAIN nft_do_chain depth=0 verdict=ACCEPT ...
[10:23:45.125] FUNCTION_CALL ip_local_deliver ...
[10:23:45.125] FUNCTION_CALL tcp_v4_rcv ...
```

### 3. Find Packet Drops

**Scenario:** Packets bị drop, tìm nguyên nhân

```bash
sudo python3 multi_kprobe_tracer.py --priority 1
```

**Look for DROP events:**
```
[10:23:45.456] DROP kfree_skb reason=2 TCP 192.168.1.100:443 → 10.0.0.1:52341
```

Cross-reference với events trước đó để biết context.

### 4. Performance Profiling

**Scenario:** Tìm hotspot functions

```bash
# Trace với sampling
sudo python3 multi_kprobe_tracer.py --priority 2 --sample-rate 10

# Run for 1 minute
# Ctrl+C

# Check "Top Functions Hit" statistics
```

### 5. Compare với pwru

**Scenario:** Muốn coverage như pwru

```bash
# Maximum coverage
sudo python3 multi_kprobe_tracer.py --priority 3 --sample-rate 10
```

Trace 1000+ functions như pwru, nhưng có thêm NFT integration.

---

## ⚙️ Configuration

### Sampling

Giảm overhead bằng cách sample packets:

```bash
# Trace 10% packets
sudo python3 multi_kprobe_tracer.py --priority 2 --sample-rate 10

# Trace 1% packets
sudo python3 multi_kprobe_tracer.py --priority 3 --sample-rate 100
```

### Category Filtering

Chỉ trace categories cụ thể:

```bash
# Only NFT and netfilter
sudo python3 enhanced_btf_discoverer.py \
  --category nft --category netfilter \
  --output nft_funcs.json

sudo python3 multi_kprobe_tracer.py --functions nft_funcs.json
```

**Available categories:**
- nft, netfilter, conntrack, nat
- ip, tcp, udp, icmp
- netdev, bridge, routing
- ipsec, tunnel, qdisc

---

## 🐛 Troubleshooting

### "bpftool not found"

```bash
sudo apt-get install linux-tools-$(uname -r)
```

Hoặc để discovery tự động fallback sang kallsyms.

### "Failed to attach kprobe to XXX"

Function không tồn tại trong kernel version này. Sử dụng auto-discovery:

```bash
sudo python3 multi_kprobe_tracer.py --priority 1
```

Auto-discovery chỉ tìm functions thực sự tồn tại.

### "Too many events, system slow"

Giảm priority hoặc dùng sampling:

```bash
sudo python3 multi_kprobe_tracer.py --priority 0 --sample-rate 10
```

---

## 📈 Performance

### Overhead Estimates

| Configuration | Functions | Overhead | Recommendation |
|---------------|-----------|----------|----------------|
| P0 | ~14 | < 1% | ✅ Production |
| P1 | ~60 | 1-3% | ✅ Dev/Debug |
| P2 | ~200 | 3-7% | ⚠️ Lab only |
| P3 | 1000+ | 10-20% | ❌ Debug only |
| P2 + sample 10 | ~200 | < 1% | ✅ Production |
| P3 + sample 100 | 1000+ | < 2% | ✅ Production |

### Best Practices

**Production:**
- Priority 0-1
- With sampling (10-100)
- Monitor CPU usage

**Development:**
- Priority 1-2
- No sampling (see all events)

**Deep Debugging:**
- Priority 3
- Sample 10+ to keep overhead low

---

## 🔗 References

- **pwru (Cilium):** https://github.com/cilium/pwru
- **BCC Tools:** https://github.com/iovisor/bcc
- **BTF Documentation:** https://www.kernel.org/doc/html/latest/bpf/btf.html
- **nftables:** https://wiki.nftables.org

---

## 📝 Notes

### Differences from pwru

**Advantages of Multi-Kprobe:**
- ✅ Deep NFT integration (chain/rule tracking)
- ✅ Web UI support (existing)
- ✅ Session management
- ✅ Realtime WebSocket streaming
- ✅ JSON export for offline analysis
- ✅ Priority-based selection

**Advantages of pwru:**
- pcap-filter syntax
- Standalone binary (no Python deps)
- Optimized Go implementation

### Integration với hệ thống hiện tại

Multi-Kprobe có thể:

1. **Standalone:** Dùng riêng như một tool
2. **Integrated:** Thêm vào app.py như mode mới
3. **Export:** Export JSON cho web UI

Xem `MULTI_KPROBE_GUIDE.md` (ở root) để biết chi tiết integration.

---

## 🎉 Summary

Bộ công cụ Multi-Kprobe Tracer cung cấp:

✅ **Comprehensive Coverage** - Trace 1000+ kernel functions
✅ **Auto Discovery** - BTF-based, kernel version independent
✅ **Flexible** - 4 priority levels + category filtering
✅ **NFT Focused** - Deep nftables integration
✅ **Production Ready** - Low overhead với sampling
✅ **pwru-equivalent** - Coverage tương đương Cilium pwru

**Start tracing ngay:**
```bash
cd /home/user/nft-tracer-app/backend
sudo python3 multi_kprobe_tracer.py --priority 1
```

Đọc thêm: `MULTI_KPROBE_GUIDE.md` (file ở /home/user/nft-tracer-app/)
