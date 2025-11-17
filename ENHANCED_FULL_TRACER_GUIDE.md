# Enhanced Full Tracer - Complete Guide
## Trace ALL Functions + NFT Verdicts

Hướng dẫn sử dụng **Enhanced Full Tracer** - công cụ kết hợp tracing nhiều kernel functions VỚI NFT verdict tracking.

---

## 📌 Tổng quan

**Enhanced Full Tracer** kết hợp 2 khả năng:

1. **Multi-Function Tracing** - Trace 100+ kernel functions mà packet đi qua
2. **NFT Verdict Tracking** - Track chi tiết verdicts từ nftables rules

**Output bạn sẽ thấy:**
- ✅ Tất cả kernel functions mà packet đi qua
- ✅ NFT chain entry/exit với verdicts
- ✅ NFT rule evaluations với verdicts cụ thể
- ✅ Packet drops với reasons
- ✅ Correlation theo SKB address

---

## 🎯 Điểm khác biệt

### So với các tracers khác:

| Tracer | Functions | NFT Verdicts | Best For |
|--------|-----------|--------------|----------|
| **nft_tracer** | 0 | ✅ Chi tiết | NFT debugging only |
| **multi_kprobe_tracer** | 1000+ | ❌ Không có | Network stack analysis |
| **full_tracer** | ~10 | ✅ Có | Kết hợp cơ bản |
| **enhanced_full_tracer** | **100-1000+** | **✅ Chi tiết** | **ALL-IN-ONE** ⭐ |

### Khi nào dùng Enhanced Full Tracer?

✅ Muốn thấy packet đi qua hàm nào + verdict ra sao
✅ Debug NFT rules nhưng cần context từ network stack
✅ Trace comprehensive nhất có thể
✅ All-in-one solution

---

## 🚀 Quick Start

### Test ngay

```bash
cd /home/user/nft-tracer-app/backend
sudo ./test_enhanced_full.sh
```

### Usage cơ bản

```bash
# Trace ALL functions + NFT verdicts (priority 1 - recommended)
sudo python3 enhanced_full_tracer.py --priority 1

# Output:
# [10:23:45.123] CPU:0 SKB:0xffff... FUNC       __netif_receive_skb_core   P1 | TCP 192.168.1.100:443 → 10.0.0.1:52341
# [10:23:45.124] CPU:0 SKB:0xffff... FUNC       ip_rcv                     P1 | TCP 192.168.1.100:443 → 10.0.0.1:52341
# [10:23:45.124] CPU:0 SKB:0xffff... NFT_CHAIN  nft_do_chain               hook=INPUT depth=0 verdict=ACCEPT
# [10:23:45.125] CPU:0 SKB:0xffff... NFT_RULE   nft_immediate_eval         rule#1 verdict=ACCEPT
# [10:23:45.125] CPU:0 SKB:0xffff... FUNC       ip_local_deliver           P1 | TCP 192.168.1.100:443 → 10.0.0.1:52341
# [10:23:45.126] CPU:0 SKB:0xffff... FUNC       tcp_v4_rcv                 P1 | TCP 192.168.1.100:443 → 10.0.0.1:52341
```

---

## 📊 Modes

### Mode 1: ALL Functions + NFT Verdicts (Default)

Trace **TẤT CẢ** functions + NFT verdicts

```bash
sudo python3 enhanced_full_tracer.py --priority 1
```

**Output:**
- Function calls (FUNC)
- NFT chain events (NFT_CHAIN)
- NFT rule events (NFT_RULE) với verdicts
- Drops (DROP)

**Use case:** Xem toàn bộ packet journey + NFT decisions

### Mode 2: NFT-Only (Verdicts Only)

Chỉ hiển thị NFT events, suppress function calls

```bash
sudo python3 enhanced_full_tracer.py --priority 1 --nft-only
```

**Output:**
- NFT_CHAIN events
- NFT_RULE events với verdicts
- DROP events

Function calls vẫn được trace (để correlate với NFT) nhưng không hiển thị.

**Use case:** Focus vào NFT decisions, giảm noise

### Mode 3: Group by SKB (Packet Journey View)

Group events theo SKB address để thấy complete packet journey

```bash
sudo python3 enhanced_full_tracer.py --priority 1 --group-by-skb
```

**Output:**
```
============================================================
Packet Journey: SKB 0xffff888100a2c800 (8 events)
============================================================
[10:23:45.123] CPU:0 SKB:0xffff888100a2c800 FUNC       __netif_receive_skb_core P1 | TCP ...
[10:23:45.124] CPU:0 SKB:0xffff888100a2c800 FUNC       ip_rcv                   P1 | TCP ...
[10:23:45.124] CPU:0 SKB:0xffff888100a2c800 NFT_CHAIN  nft_do_chain             hook=INPUT verdict=ACCEPT ...
[10:23:45.125] CPU:0 SKB:0xffff888100a2c800 NFT_RULE   nft_immediate_eval       rule#1 verdict=ACCEPT ...
[10:23:45.125] CPU:0 SKB:0xffff888100a2c800 FUNC       ip_local_deliver         P1 | TCP ...
[10:23:45.126] CPU:0 SKB:0xffff888100a2c800 FUNC       tcp_v4_rcv               P1 | TCP ...
```

**Use case:** Debug specific packet path, understand complete journey

---

## ⚙️ Options

### Priority Levels

```bash
# Priority 0: Critical only (~14 functions)
sudo python3 enhanced_full_tracer.py --priority 0

# Priority 1: Important (recommended, ~60-70 functions)
sudo python3 enhanced_full_tracer.py --priority 1

# Priority 2: Normal (~200 functions)
sudo python3 enhanced_full_tracer.py --priority 2

# Priority 3: Comprehensive (1000+ functions like pwru)
sudo python3 enhanced_full_tracer.py --priority 3
```

### Sampling

Giảm overhead bằng sampling:

```bash
# Trace 10% packets
sudo python3 enhanced_full_tracer.py --priority 2 --sample-rate 10

# Trace 1% packets
sudo python3 enhanced_full_tracer.py --priority 3 --sample-rate 100
```

**Note:** Sampling áp dụng cho function calls, NFT events LUÔN được emit.

### Custom Function List

Sử dụng pre-discovered function list:

```bash
# Discovery trước
sudo python3 enhanced_btf_discoverer.py --priority 1 --output funcs.json

# Sử dụng
sudo python3 enhanced_full_tracer.py --functions funcs.json
```

Hoặc plain text file:

```bash
# funcs.txt:
# __netif_receive_skb_core
# ip_rcv
# ip_local_deliver
# tcp_v4_rcv

sudo python3 enhanced_full_tracer.py --functions funcs.txt
```

---

## 📖 Output Format

### Event Types

```
FUNC        - Generic kernel function call
NFT_CHAIN   - NFT chain entry/exit with verdict
NFT_RULE    - NFT rule evaluation with verdict
DROP        - Packet drop (kfree_skb)
```

### Column Meanings

```
[timestamp] CPU:X SKB:addr EVENT_TYPE function_name details | packet_info
```

**Examples:**

```
# Function call
[10:23:45.123] CPU:0 SKB:0xffff888... FUNC       ip_rcv P1 | TCP 192.168.1.100:443 → 10.0.0.1:52341 len=1500

# NFT Chain
[10:23:45.124] CPU:0 SKB:0xffff888... NFT_CHAIN  nft_do_chain hook=INPUT depth=0 verdict=ACCEPT | TCP 192.168.1.100:443 → 10.0.0.1:52341

# NFT Rule with verdict
[10:23:45.125] CPU:0 SKB:0xffff888... NFT_RULE   nft_immediate_eval rule#1 handle=5 verdict=ACCEPT | TCP ...

# Drop
[10:23:45.456] CPU:2 SKB:0xffff888... DROP       kfree_skb reason=2 | TCP 192.168.1.100:443 → 10.0.0.1:52341
```

### Statistics (Ctrl+C)

```
==============================================================================
ENHANCED FULL TRACER STATISTICS
==============================================================================
Duration: 30.45s
Total Events: 12,543
Events/sec: 411.87

Event Types:
  FUNC             9,234 (73.6%)
  NFT_CHAIN          856 ( 6.8%)
  NFT_RULE           423 ( 3.4%)
  DROP                30 ( 0.2%)

NFT Verdicts:
  ACCEPT     1,245
  DROP          34

Top Protocols:
  TCP      8,234
  UDP      3,142
  ICMP       167
==============================================================================
```

---

## 🎓 Use Cases

### Use Case 1: Debug Firewall Rules

**Scenario:** Packet bị DROP, cần biết rule nào và tại sao

```bash
# Run tracer
sudo python3 enhanced_full_tracer.py --priority 1

# Generate test traffic
ping 192.168.1.100

# Observe output:
# 1. Thấy packet đi qua functions nào
# 2. Vào NFT chain nào (hook=INPUT/FORWARD/etc.)
# 3. Rule nào được evaluate
# 4. Verdict cuối cùng là gì
# 5. Nếu DROP, xem reason
```

**Example output:**
```
[10:23:45.123] FUNC       ip_rcv ...
[10:23:45.124] NFT_CHAIN  nft_do_chain hook=INPUT depth=0 verdict=DROP
[10:23:45.125] NFT_RULE   nft_immediate_eval rule#3 handle=10 verdict=DROP
                                               ^^^^^^^^^^^^^^ Rule này DROP!
[10:23:45.126] DROP       kfree_skb reason=1
```

### Use Case 2: Trace Packet Journey

**Scenario:** Muốn thấy complete packet path từ NIC đến application

```bash
# Group by SKB để thấy complete journey
sudo python3 enhanced_full_tracer.py --priority 1 --group-by-skb

# Output sẽ group theo packet:
# Packet Journey: SKB 0x... (10 events)
# 1. __netif_receive_skb_core (NIC)
# 2. ip_rcv (IP layer)
# 3. nft_do_chain (Firewall)
# 4. ip_local_deliver
# 5. tcp_v4_rcv (TCP layer)
# ...
```

### Use Case 3: Performance Analysis

**Scenario:** Tìm functions nào được gọi nhiều nhất

```bash
# Trace với sampling để giảm overhead
sudo python3 enhanced_full_tracer.py --priority 2 --sample-rate 10

# Run for a while
# Ctrl+C

# Check statistics:
# Top Functions:
#   ip_rcv: 3,421
#   tcp_v4_rcv: 2,987
#   ...
```

### Use Case 4: NFT-Only Debugging

**Scenario:** Chỉ quan tâm NFT verdicts, không cần function calls

```bash
# NFT-only mode
sudo python3 enhanced_full_tracer.py --priority 1 --nft-only

# Output chỉ có:
# NFT_CHAIN events
# NFT_RULE events với verdicts
# DROP events
```

Giảm noise, focus vào NFT decisions.

### Use Case 5: Production Monitoring

**Scenario:** Monitor production system với overhead thấp

```bash
# Priority 0 (critical only) + sampling
sudo python3 enhanced_full_tracer.py --priority 0 --sample-rate 10

# Overhead < 1%
# Vẫn thấy được:
# - Core path functions
# - NFT verdicts
# - Drops
```

---

## 🔧 Advanced Usage

### Combine với tcpdump

```bash
# Terminal 1: Capture packets
sudo tcpdump -i eth0 -w capture.pcap

# Terminal 2: Trace
sudo python3 enhanced_full_tracer.py --priority 1

# Correlate timestamps để match packets với traces
```

### Filter by Protocol/Port

**Coming soon** - Sẽ support filtering trong future version.

Hiện tại có thể pipe qua grep:

```bash
sudo python3 enhanced_full_tracer.py --priority 1 | grep "TCP"
sudo python3 enhanced_full_tracer.py --priority 1 | grep "443"
```

### Export to JSON

**Coming soon** - Sẽ support JSON export.

Hiện tại có thể redirect output:

```bash
sudo python3 enhanced_full_tracer.py --priority 1 > trace.log
```

---

## 🏗️ Architecture

### How It Works

```
Kernel Function Called
    ↓
Kprobe Fires
    ↓
eBPF Handler
    ↓
┌─────────────────┬─────────────────┐
│ Generic SKB     │  NFT Specific   │
│ trace_skb_1-5   │  nft_do_chain   │
│                 │  nft_immediate  │
└─────────────────┴─────────────────┘
    ↓
Extract packet info
Check config (nft_only, sampling)
    ↓
Store in skb_map (for correlation)
    ↓
Submit to Perf Buffer
    ↓
Python polls buffer
    ↓
Format & Display
    ↓
Group by SKB (optional)
    ↓
Statistics
```

### Correlation by TID

NFT events được correlate với function calls bằng cách:

1. Generic functions store event trong `skb_map` với key = TID
2. NFT hooks (nft_do_chain, nft_immediate_eval) lookup stored event
3. Enrich với NFT-specific data (chain, rule, verdict)
4. Emit combined event

Điều này cho phép thấy được:
- Packet đi qua functions nào
- Và verdict từ NFT rule nào

---

## 📊 Performance

### Overhead Estimates

| Config | Functions | NFT | Overhead | Recommendation |
|--------|-----------|-----|----------|----------------|
| P0 | 14 | ✅ | < 1% | ✅ Production |
| P1 | 60 | ✅ | 1-3% | ✅ Dev/Debug |
| P2 | 200 | ✅ | 3-7% | ⚠️ Lab only |
| P3 | 1000+ | ✅ | 10-20% | ❌ Debug only |
| P1 + NFT-only | 60* | ✅ | < 1% | ✅ Production |
| P2 + S10 | 200 | ✅ | < 1% | ✅ Production |

*Functions traced but not displayed

### Best Practices

**Production:**
- `--priority 0-1` + `--sample-rate 10-100`
- Or `--nft-only` (still trace functions for correlation)

**Development:**
- `--priority 1` no sampling

**Deep Debug:**
- `--priority 2-3` + `--sample-rate 10+`

---

## 🐛 Troubleshooting

### No NFT events showing

**Cause:** No nftables rules or no traffic matching rules

**Solution:**
```bash
# Check nftables rules
sudo nft list ruleset

# Generate test traffic
ping 192.168.1.100
curl http://example.com
```

### Too many events

**Cause:** High traffic + low priority

**Solutions:**
```bash
# 1. Use NFT-only mode
sudo python3 enhanced_full_tracer.py --priority 1 --nft-only

# 2. Use sampling
sudo python3 enhanced_full_tracer.py --priority 1 --sample-rate 10

# 3. Lower priority
sudo python3 enhanced_full_tracer.py --priority 0
```

### Missing some verdicts

**Cause:** Sampling suppresses some events

**Solution:**
```bash
# Disable sampling for NFT-only mode
sudo python3 enhanced_full_tracer.py --priority 1 --nft-only --sample-rate 1
```

NFT events are ALWAYS emitted, but check sample-rate setting.

---

## 🔗 Related Tools

### Comparison

**Use nft_tracer.py when:**
- Chỉ quan tâm NFT verdicts
- Không cần network stack context

**Use multi_kprobe_tracer.py when:**
- Chỉ quan tâm network stack functions
- Không có nftables

**Use enhanced_full_tracer.py when:**
- Cần cả hai: functions + verdicts ⭐
- All-in-one solution
- Most comprehensive tracing

---

## 📝 Summary

Enhanced Full Tracer là **all-in-one solution** cho:

✅ Multi-function tracing (100-1000+ functions)
✅ NFT verdict tracking (chains + rules)
✅ Correlation by SKB address
✅ Flexible modes (ALL, NFT-only, grouped)
✅ Production-ready với sampling
✅ Complete packet journey visibility

**Quick Start:**
```bash
# Recommended usage
sudo python3 enhanced_full_tracer.py --priority 1

# NFT-focused
sudo python3 enhanced_full_tracer.py --priority 1 --nft-only

# Packet journey view
sudo python3 enhanced_full_tracer.py --priority 1 --group-by-skb
```

**Best for:**
- NFT firewall debugging với network stack context
- Understanding complete packet flow
- Comprehensive analysis
- All-in-one tracing solution

Happy tracing! 🚀
