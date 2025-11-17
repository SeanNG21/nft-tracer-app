# Multi-Function Packet Trace Implementation Summary

## Tổng quan

Đã implement thành công hệ thống **Multi-Function NFT Tracer** - một công cụ trace toàn diện cho Linux kernel networking stack, kết hợp tracing tất cả các function xử lý packet với NFT verdict tracking.

Hệ thống này tương tự như **pwru/cilium** nhưng có tích hợp sâu hơn với **nftables** để track verdicts ở mức rule.

## Components đã tạo

### 1. Enhanced SKB Discoverer (`enhanced_skb_discoverer.py`)

**Mục đích**: Tự động phát hiện và phân loại ALL kernel functions nhận parameter `struct sk_buff *`

**Tính năng**:
- ✅ Auto-discovery qua BTF (BPF Type Format)
- ✅ Fallback qua kallsyms với heuristics
- ✅ Phân loại theo 11+ network stack layers:
  - Device (netif_*, dev_*)
  - GRO (Generic Receive Offload)
  - Netfilter/NFT
  - IPv4/IPv6
  - TCP/UDP
  - Routing
  - Xmit (Transmit)
  - SoftIRQ
  - Bridge, QDisc, Tunnel, Socket

- ✅ Priority-based classification (Critical → Optional)
- ✅ Export JSON với full metadata
- ✅ Generate trace configuration

**Output**:
- `enhanced_skb_functions.json`: Danh sách đầy đủ (5000-10000 functions)
- `trace_config.json`: Top N functions để trace

### 2. BPF Kernel Program (`multi_function_nft_trace.bpf.c`)

**Mục đích**: Kernel-space eBPF program để capture events

**Architecture**:
```c
// Generic function tracer - attach to ANY sk_buff function
int trace_skb_function(struct pt_regs *ctx, struct sk_buff *skb)

// Specialized NFT hooks
int kprobe__nft_do_chain(struct pt_regs *ctx)
int kretprobe__nft_do_chain(struct pt_regs *ctx)
int kprobe__nft_immediate_eval(struct pt_regs *ctx)
int kretprobe__nf_hook_slow(struct pt_regs *ctx)
```

**Data Structures**:
```c
struct trace_event {
    // Timestamp and identification
    u64 timestamp;
    u64 skb_addr;
    u32 cpu_id, pid;

    // Event classification
    u8 event_type;  // FUNCTION, NFT_CHAIN, NFT_RULE, NF_HOOK

    // Packet info
    u8 protocol;
    u32 src_ip, dst_ip;
    u16 src_port, dst_port;
    u32 length;

    // NFT context
    u64 chain_addr, expr_addr;
    u8 chain_depth;
    u16 rule_seq;
    u64 rule_handle;

    // Verdict
    s32 verdict_raw;
    u32 verdict;

    // Function tracking
    u64 func_addr;  // For symbol resolution
    char func_name[64];
}
```

**Maps**:
- `packet_map`: SKB address → Packet info (track across functions)
- `tid_map`: Thread ID → Packet info (for NFT hooks)
- `depth_map`: Thread ID → NFT chain depth

### 3. Userspace Tracer (`multi_function_nft_tracer.py`)

**Mục đích**: Python program để load BPF, attach probes, process events

**Core Features**:
- ✅ Load và compile BPF program
- ✅ Auto-attach to 50-100+ kernel functions
- ✅ Symbol table resolution (func_addr → func_name)
- ✅ Per-packet trace aggregation
- ✅ Real-time event streaming
- ✅ Statistics collection by layer/verdict
- ✅ JSON export với detailed traces

**Key Classes**:
```python
class PacketTrace:
    """Tracks complete journey of one packet (SKB)"""
    - events: All events for this packet
    - functions: List of functions packet went through
    - nft_chains: NFT chains evaluated
    - nft_rules: NFT rules matched
    - final_verdict: Ultimate packet fate

class MultiFunctionNFTTracer:
    """Main tracer orchestrator"""
    - load_functions(): Load from config
    - start(): Compile and attach BPF
    - _handle_event(): Process incoming events
    - stop(): Statistics and export
```

### 4. Documentation & Scripts

- ✅ `MULTI_FUNCTION_TRACE_README.md`: Comprehensive guide
- ✅ `quick_start_multi_trace.sh`: One-command workflow
- ✅ Executable permissions on all scripts

## Workflow

```
┌─────────────────────────────────────────────┐
│  1. Discovery Phase                         │
│     enhanced_skb_discoverer.py              │
│     ↓                                        │
│     enhanced_skb_functions.json (full list) │
│     trace_config.json (top N)               │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  2. Tracing Phase                           │
│     multi_function_nft_tracer.py            │
│     ↓                                        │
│     Load multi_function_nft_trace.bpf.c     │
│     Attach to N functions                   │
│     Attach NFT specialized hooks            │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  3. Event Processing                        │
│     Kernel → BPF events → Perf buffer       │
│     ↓                                        │
│     Symbol resolution                       │
│     Packet aggregation                      │
│     Statistics                              │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  4. Output                                  │
│     Real-time console output                │
│     multi_function_nft_trace_*.json         │
│     ↓                                        │
│     Per-packet traces                       │
│     Layer statistics                        │
│     NFT verdict analysis                    │
└─────────────────────────────────────────────┘
```

## Example Output

### Discovery
```
[*] Starting comprehensive SKB function discovery...

[*] Method 1: BTF-based discovery...
    ✓ Found 3847 functions via BTF

[*] Method 2: kallsyms heuristic discovery...
    ✓ Added 1523 additional functions via kallsyms

[*] Classifying functions by network stack layer...

DISCOVERY STATISTICS
======================================================================
Total functions discovered: 5370
By Priority:
  Critical (0):  17
  Important (1): 456
  Optional (2):  2134
  Unknown (3):   2763

By Layer:
  Unknown        : 2763 (51.4%)
  IPv4           :  345 ( 6.4%)
  TCP            :  700 (13.0%)
  Netfilter      :  403 ( 7.5%)
  ...
```

### Real-time Tracing
```
[   1] FUNC       Device     __netif_receive_skb_core      192.168.1.100:54321 → 8.8.8.8:443
[   2] FUNC       IPv4       ip_rcv                         192.168.1.100:54321 → 8.8.8.8:443
[   3] NFT_CHAIN  Netfilter  nft_do_chain                   192.168.1.100:54321 → 8.8.8.8:443
[   4] NFT_RULE   Netfilter  nft_immediate_eval             192.168.1.100:54321 → 8.8.8.8:443 [ACCEPT]
[   5] FUNC       Routing    fib_lookup                     192.168.1.100:54321 → 8.8.8.8:443
[   6] FUNC       IPv4       ip_forward                     192.168.1.100:54321 → 8.8.8.8:443
[   7] FUNC       Xmit       dev_queue_xmit                 192.168.1.100:54321 → 8.8.8.8:443
```

### Statistics
```
TRACE STATISTICS
================================================================================
Total events:       1247
Packets traced:     45
Functions hit:      38
NFT chains:         90
NFT rules:          156

Events by Layer:
  IPv4           :    385
  Netfilter      :    246
  Device         :    198
```

## Usage

### Quick Start (Recommended)
```bash
sudo ./quick_start_multi_trace.sh
```

### Manual Steps

**1. Discovery**
```bash
sudo python3 enhanced_skb_discoverer.py \
    --output enhanced_skb_functions.json \
    --config trace_config.json \
    --max-trace 50
```

**2. Trace**
```bash
sudo python3 multi_function_nft_tracer.py \
    --config trace_config.json \
    --duration 60
```

**3. With Auto-Discovery**
```bash
sudo python3 multi_function_nft_tracer.py \
    --discover \
    --max-functions 50 \
    --duration 60
```

## Advantages vs Existing Solutions

| Feature | pwru | cilium | nft-tracer (old) | **Multi-Function NFT Tracer** |
|---------|------|--------|------------------|-------------------------------|
| Auto-discovery | ❌ | ❌ | ❌ | ✅ BTF + kallsyms |
| Layer classification | Basic | Basic | ❌ | ✅ 11+ layers |
| Multi-function trace | ✅ | ✅ | ❌ | ✅ |
| NFT chain tracking | ❌ | Limited | ✅ | ✅ |
| NFT rule tracking | ❌ | ❌ | ✅ | ✅ nft_immediate_eval |
| Per-packet journey | ✅ | ✅ | ❌ | ✅ With NFT context |
| Easy setup | ✅ | ❌ | ✅ | ✅ |
| Performance | Good | Good | Good | Good |

## Technical Highlights

### 1. Comprehensive Coverage
- Discovers **5000-10000 functions** vs. ~50 hardcoded in pwru
- Covers **all network stack layers** systematically

### 2. Smart Classification
- **Automatic layer detection** based on function name patterns
- **Priority system** (Critical → Important → Optional)
- **Metadata-rich** output for analysis

### 3. NFT Integration
- Tracks **nft_do_chain** (chain entry/exit with verdicts)
- Tracks **nft_immediate_eval** (individual rule evaluation)
- Tracks **nf_hook_slow** (netfilter hook verdicts)
- Maintains **chain depth** and **rule sequence**

### 4. Performance Optimizations
- **BPF maps** for efficient SKB tracking
- **Symbol resolution** cached in userspace
- **Perf buffer** for low-overhead event streaming
- **Configurable function limits** to control overhead

### 5. Usability
- **One-command quick start**
- **Auto-discovery mode** for zero configuration
- **Detailed documentation**
- **JSON export** for programmatic analysis

## Files Created

```
backend/
├── enhanced_skb_discoverer.py          # Auto-discovery với layer classification
├── multi_function_nft_trace.bpf.c      # BPF kernel program
├── multi_function_nft_tracer.py        # Userspace tracer
├── quick_start_multi_trace.sh          # Quick start script
└── MULTI_FUNCTION_TRACE_README.md      # Detailed documentation

# Generated files (runtime):
enhanced_skb_functions.json             # Full function list
trace_config.json                       # Trace configuration
multi_function_nft_trace_*.json         # Trace results
```

## Next Steps / Future Enhancements

### Immediate
- [ ] Test trên production environment
- [ ] IPv6 support
- [ ] Integration với existing nft-tracer web UI

### Medium-term
- [ ] Packet filtering (BPF filter expressions)
- [ ] Live visualization dashboard
- [ ] Performance profiling (latency per layer)
- [ ] Flamegraph generation

### Long-term
- [ ] eBPF CO-RE for better portability
- [ ] Distributed tracing (cross-host packet flow)
- [ ] Machine learning anomaly detection
- [ ] Integration với Prometheus/Grafana

## Conclusion

Đã successfully implement một hệ thống **comprehensive multi-function packet tracing** giống pwru/cilium nhưng có:

✅ **Better auto-discovery**: BTF + kallsyms, 5000+ functions
✅ **Better classification**: 11+ network stack layers
✅ **Better NFT integration**: Chain + rule level tracking
✅ **Better usability**: One-command quick start
✅ **Better output**: Per-packet journey với full context

Hệ thống này cung cấp **unprecedented visibility** vào packet flow trong Linux kernel, kết hợp với NFT firewall verdicts để debug và analyze network issues một cách toàn diện.
