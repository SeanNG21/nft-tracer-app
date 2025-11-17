# Multi-Kprobe Tracer Guide
## Comprehensive Network Stack Tracing (pwru-style)

Hướng dẫn sử dụng Enhanced Multi-Kprobe Tracer để trace nhiều kernel functions tương đương với pwru/Cilium.

---

## 📋 Tổng quan

Hệ thống mới bao gồm 3 components chính:

1. **Enhanced BTF Discoverer** (`enhanced_btf_discoverer.py`)
   - Tự động phát hiện TẤT CẢ kernel functions xử lý `sk_buff`
   - Phân loại theo category và priority
   - Có thể discover 1000+ functions như pwru

2. **Multi-Kprobe eBPF Program** (`multi_kprobe_tracer.bpf.c`)
   - Hỗ trợ trace nhiều kernel functions đồng thời
   - Sử dụng macro để handle nhiều parameter positions (1-5)
   - Tích hợp NFT tracing và drop tracking

3. **Python Tracer** (`multi_kprobe_tracer.py`)
   - Quản lý và attach nhiều kprobes
   - Realtime event processing
   - Statistics và reporting

---

## 🎯 So sánh với hệ thống cũ

| Feature | Hệ thống cũ | Hệ thống mới (Multi-Kprobe) |
|---------|-------------|----------------------------|
| Số hàm trace | ~10 hàm hardcoded | 1000+ hàm auto-discovered |
| Discovery | Manual | Auto BTF-based |
| Flexibility | Fixed functions | User-selectable priority |
| Coverage | NFT + core path | Full network stack |
| Parameter position | Fixed P1 | P1-P5 auto-detect |
| Drop tracking | Limited | kfree_skb_reason support |
| Tương đương | - | pwru/Cilium level |

---

## 📦 Yêu cầu

### System Requirements
- Linux kernel >= 4.18 (BTF support)
- BCC (BPF Compiler Collection) installed
- Root/sudo privileges
- bpftool installed: `apt-get install linux-tools-$(uname -r)`

### Python Dependencies
```bash
# Already included in backend/requirements.txt
pip3 install bcc psutil
```

---

## 🚀 Quick Start

### Bước 1: Discover kernel functions

```bash
cd /home/user/nft-tracer-app/backend

# Discovery với priority 1 (critical + important) - Khuyến nghị
sudo python3 enhanced_btf_discoverer.py --priority 1 --output funcs_p1.json

# Hoặc discovery comprehensive (all functions, như pwru)
sudo python3 enhanced_btf_discoverer.py --priority 3 --output funcs_p3.json
```

**Output:**
```
[*] Enhanced BTF Discovery (max_priority=1)
[*] Discovering SKB functions from kernel BTF...
[*] Running bpftool to dump kernel BTF...
[✓] Found 1024 sk_buff functions via BTF

============================================================
[✓] DISCOVERY COMPLETE: 67 functions
============================================================

By Priority:
  [0] Critical: 14
  [1] Important: 53

Top Categories:
  netfilter: 18
  nft: 12
  ip: 15
  tcp: 8
  netdev: 7
  ...
```

### Bước 2: Run tracer

```bash
# Sử dụng auto-discovery với priority 1
sudo python3 multi_kprobe_tracer.py --priority 1

# Hoặc sử dụng pre-discovered function list
sudo python3 multi_kprobe_tracer.py --functions funcs_p1.json

# Verbose mode
sudo python3 multi_kprobe_tracer.py --priority 1 --verbose
```

**Output:**
```
[*] Auto-discovering SKB functions (priority <= 1)
[*] Discovering SKB functions from kernel BTF...
[✓] Discovered 67 functions

[*] Loading eBPF program...
[✓] eBPF program compiled successfully

[*] Configuration: sample_rate=1, track_drops=1

[*] Attaching kprobes to 67 functions...
[✓] Attached 69 kprobes successfully

[✓] Tracing 69 kernel functions... (Ctrl+C to stop)

[10:23:45.123] CPU:0 SKB:0xffff888100a2c800 FUNCTION_CALL __netif_receive_skb_core P1 TCP 192.168.1.100:52341 → 192.168.1.1:443 len=60 (ksoftirqd/0)
[10:23:45.124] CPU:0 SKB:0xffff888100a2c800 FUNCTION_CALL ip_rcv P1 TCP 192.168.1.100:52341 → 192.168.1.1:443 len=60 (ksoftirqd/0)
[10:23:45.124] CPU:0 SKB:0xffff888100a2c800 NFT_CHAIN nft_do_chain depth=0 verdict=ACCEPT TCP 192.168.1.100:52341 → 192.168.1.1:443 len=60 (ksoftirqd/0)
[10:23:45.125] CPU:0 SKB:0xffff888100a2c800 FUNCTION_CALL ip_local_deliver P1 TCP 192.168.1.100:52341 → 192.168.1.1:443 len=60 (ksoftirqd/0)
[10:23:45.125] CPU:0 SKB:0xffff888100a2c800 FUNCTION_CALL tcp_v4_rcv P1 TCP 192.168.1.100:52341 → 192.168.1.1:443 len=60 (ksoftirqd/0)
```

---

## 📊 Priority Levels

Hệ thống phân loại functions theo 4 mức priority:

### Priority 0: Critical (Core Packet Path)
**~14 functions** - Chỉ trace các hàm quan trọng nhất

- NFT core: `nft_do_chain`, `nft_immediate_eval`
- Main path: `__netif_receive_skb_core`, `ip_rcv`, `ip_output`
- Drops: `kfree_skb_reason`

**Use case:** Production monitoring với overhead thấp nhất

```bash
sudo python3 multi_kprobe_tracer.py --priority 0
```

### Priority 1: Important (Recommended)
**~60-70 functions** - Critical + detailed processing

- NFT rules: `nft_lookup_eval`, `nft_payload_eval`, `nft_cmp_eval`
- IP layer: `ip_forward`, `ip_local_deliver`, `ip_finish_output`
- TCP/UDP: `tcp_v4_rcv`, `udp_rcv`
- Conntrack: `nf_conntrack_in`
- NAT: `nf_nat_ipv4_in`, `nf_nat_ipv4_out`

**Use case:** NFT debugging và network troubleshooting (khuyến nghị)

```bash
sudo python3 multi_kprobe_tracer.py --priority 1
```

### Priority 2: Normal
**~200 functions** - Thêm GRO/GSO, routing, bridge

- GRO: `napi_gro_receive`, `dev_gro_receive`
- Queue: `dev_queue_xmit`, `__dev_queue_xmit`
- Routing: `ip_route_input_slow`, `fib_validate_source`
- Fragment: `ip_fragment`, `ip_defrag`
- Bridge: `br_handle_frame`, `br_forward`

**Use case:** Deep debugging, performance analysis

```bash
sudo python3 multi_kprobe_tracer.py --priority 2
```

### Priority 3: Comprehensive (All)
**1000+ functions** - Tương đương pwru

Bao gồm tất cả functions handle `sk_buff` trong kernel.

**Use case:** Comprehensive analysis, khi cần trace mọi thứ

```bash
sudo python3 multi_kprobe_tracer.py --priority 3
```

⚠️ **Warning:** Priority 3 có overhead cao, chỉ dùng cho debugging, không dùng production!

---

## 🔧 Advanced Usage

### Filter by Category

```bash
# Chỉ discover NFT và netfilter functions
sudo python3 enhanced_btf_discoverer.py \
  --priority 2 \
  --category nft \
  --category netfilter \
  --output nft_only.json

# Trace with filtered list
sudo python3 multi_kprobe_tracer.py --functions nft_only.json
```

**Available categories:**
- `nft` - nftables core
- `netfilter` - netfilter hooks
- `netdev` - network device layer
- `ip` - IP layer
- `tcp`, `udp` - Transport layers
- `conntrack` - Connection tracking
- `nat` - NAT
- `bridge` - Bridge
- `routing` - Routing
- `ipsec` - IPsec
- `tunnel` - Tunneling
- `qdisc` - QoS/Traffic control

### Sampling (Reduce Overhead)

```bash
# Trace 10% of packets (sample 1 out of 10)
sudo python3 multi_kprobe_tracer.py --priority 2 --sample-rate 10

# Trace 1% of packets
sudo python3 multi_kprobe_tracer.py --priority 3 --sample-rate 100
```

Sampling giúp giảm overhead khi trace nhiều functions trên hệ thống high-traffic.

### Generate Function List

```bash
# Generate plain text list (one function per line)
sudo python3 enhanced_btf_discoverer.py \
  --priority 1 \
  --function-list functions.txt

# Use the list
sudo python3 multi_kprobe_tracer.py --functions functions.txt
```

### Show Top N Functions

```bash
# Show top 50 functions in discovery
sudo python3 enhanced_btf_discoverer.py --priority 2 --show-top 50
```

---

## 📈 Statistics và Output

### Realtime Output Format

```
[timestamp] CPU:X SKB:addr EVENT_TYPE function_name details
```

**Example:**
```
[10:23:45.123] CPU:0 SKB:0xffff888100a2c800 FUNCTION_CALL ip_rcv P1 TCP 192.168.1.100:443 → 10.0.0.1:52341 len=1500 (ksoftirqd/0)
```

**Fields:**
- `timestamp` - HH:MM:SS.mmm
- `CPU` - CPU core number
- `SKB` - Socket buffer address (packet identifier)
- `EVENT_TYPE` - FUNCTION_CALL, NFT_CHAIN, NFT_RULE, DROP
- `function_name` - Kernel function name
- `P1-P5` - Parameter position of sk_buff
- Packet info: protocol, IPs, ports, length
- Process name

### Statistics (Ctrl+C)

Khi dừng tracer (Ctrl+C), hệ thống hiển thị thống kê:

```
======================================================================
TRACE STATISTICS
======================================================================
Duration: 30.45s
Total Events: 12,543
Events/sec: 411.87

Event Types:
  FUNCTION_CALL: 11,234
  NFT_CHAIN: 856
  NFT_RULE: 423
  DROP: 30

Top Protocols:
  TCP: 8,234
  UDP: 3,142
  ICMP: 167

Top Functions Hit:
  __netif_receive_skb_core: 3,421
  ip_rcv: 3,421
  nft_do_chain: 856
  ip_local_deliver: 2,134
  tcp_v4_rcv: 1,987
  ip_forward: 1,287
  nft_immediate_eval: 423
  nf_conntrack_in: 856
  ip_finish_output: 1,134
  dev_queue_xmit: 987
  ...
======================================================================
```

---

## 🎓 Use Cases

### Use Case 1: Debug NFT Firewall Rules

**Scenario:** Packet bị DROP nhưng không biết rule nào

```bash
# Discovery NFT functions
sudo python3 enhanced_btf_discoverer.py \
  --priority 1 \
  --category nft \
  --category netfilter

# Trace
sudo python3 multi_kprobe_tracer.py --priority 1

# Gửi test packet
ping 192.168.1.100

# Observe output để thấy:
# - Packet đi qua chain nào
# - Rule nào được eval
# - Verdict cuối cùng là gì
```

### Use Case 2: Trace Packet Journey Through Full Stack

**Scenario:** Muốn thấy toàn bộ hành trình của packet từ NIC đến application

```bash
# Trace comprehensive với priority 2
sudo python3 multi_kprobe_tracer.py --priority 2 --verbose

# Output sẽ show:
# 1. netif_receive_skb (NIC)
# 2. ip_rcv (IP layer)
# 3. nft_do_chain (Firewall)
# 4. ip_local_deliver
# 5. tcp_v4_rcv (TCP layer)
# 6. ... (to socket)
```

### Use Case 3: Find Packet Drops

**Scenario:** Packets đang bị drop, cần tìm nguyên nhân

```bash
# Priority 1 includes kfree_skb tracking
sudo python3 multi_kprobe_tracer.py --priority 1

# Look for DROP events:
[10:23:45.456] CPU:2 SKB:0xffff888200b3d000 DROP kfree_skb reason=2 TCP ...

# reason=2 might be SKB_DROP_REASON_NOT_SPECIFIED
# Cross-reference với function trước đó để biết context
```

### Use Case 4: Performance Analysis

**Scenario:** Tìm functions nào được gọi nhiều nhất

```bash
# Trace với sampling
sudo python3 multi_kprobe_tracer.py --priority 2 --sample-rate 10

# Run for 1 minute, then Ctrl+C
# Check "Top Functions Hit" để thấy hotspots
```

### Use Case 5: Compare with pwru

**Scenario:** Muốn coverage tương đương pwru

```bash
# Use priority 3 for maximum coverage
sudo python3 multi_kprobe_tracer.py --priority 3 --sample-rate 10

# Pwru thường trace ~1,600 functions
# Hệ thống này có thể discover 1,000-2,000 functions tùy kernel
```

---

## ⚙️ Integration với Hệ thống Hiện tại

### Option 1: Standalone Usage

Sử dụng multi-kprobe tracer độc lập:

```bash
cd /home/user/nft-tracer-app/backend
sudo python3 multi_kprobe_tracer.py --priority 1
```

### Option 2: Integrate vào Backend API

Có thể tích hợp vào `app.py` như một tracing mode mới:

```python
# In app.py, add new mode
TRACE_MODES = {
    'nft': 'NFT-only tracing',
    'universal': 'Universal tracer',
    'full': 'Full mode (NFT + paths)',
    'multi': 'Multi-kprobe comprehensive',  # NEW
}

# When mode='multi', use multi_kprobe_tracer instead
if mode == 'multi':
    from multi_kprobe_tracer import MultiKprobeTracer
    tracer = MultiKprobeTracer(priority=priority)
    tracer.run()
```

### Option 3: Export to JSON for Web UI

Modify `multi_kprobe_tracer.py` để export JSON format tương thích với web UI:

```python
# In handle_event(), append to session events
session_events.append({
    'timestamp': event.timestamp,
    'skb_addr': event.skb_addr,
    'function': func_name,
    'event_type': event_type,
    # ... other fields
})

# On exit, save to JSON
with open(f'output/session_{session_id}.json', 'w') as f:
    json.dump(session_events, f, indent=2)
```

Sau đó web UI có thể load và visualize.

---

## 🐛 Troubleshooting

### Issue: "bpftool not found"

```bash
# Install bpftool
sudo apt-get install linux-tools-$(uname -r)

# Or use fallback (kallsyms discovery)
# Discovery sẽ tự động fallback nếu bpftool không có
```

### Issue: "Failed to attach kprobe"

**Nguyên nhân:** Function không tồn tại trong kernel version này

**Giải pháp:** Sử dụng auto-discovery thay vì hardcoded list:

```bash
# Let discovery find only functions that exist
sudo python3 multi_kprobe_tracer.py --priority 1
```

### Issue: "Too many events, system slow"

**Nguyên nhân:** Quá nhiều functions được trace trên high-traffic system

**Giải pháp:**

1. Giảm priority:
```bash
sudo python3 multi_kprobe_tracer.py --priority 0
```

2. Hoặc dùng sampling:
```bash
sudo python3 multi_kprobe_tracer.py --priority 2 --sample-rate 10
```

### Issue: "No functions found"

**Nguyên nhân:** Kernel không có BTF support

**Giải pháp:**

```bash
# Check BTF support
ls /sys/kernel/btf/vmlinux

# If not exists, upgrade kernel >= 4.18 with BTF enabled
# Or use kallsyms fallback (automatic)
```

### Issue: "Permission denied"

```bash
# Must run as root
sudo python3 multi_kprobe_tracer.py --priority 1
```

---

## 📚 Technical Details

### How It Works

1. **Discovery Phase:**
   - Parse kernel BTF data using `bpftool btf dump`
   - Find all functions with `struct sk_buff *` parameter
   - Categorize by prefix (nft_, ip_, tcp_, etc.)
   - Assign priority based on importance
   - Detect parameter position (1-5)

2. **Compilation Phase:**
   - Load eBPF C program (`multi_kprobe_tracer.bpf.c`)
   - BCC compiles to eBPF bytecode
   - Kernel verifier validates safety

3. **Attachment Phase:**
   - For each function, attach kprobe to correct parameter position
   - NFT functions use specialized handlers
   - Generic functions use macro-generated handlers

4. **Tracing Phase:**
   - Kprobes fire when functions called
   - Extract packet metadata from sk_buff
   - Submit events to perf buffer
   - Python reads and processes events

5. **Output Phase:**
   - Format events for display
   - Track statistics
   - Resolve function names from addresses

### Performance Considerations

**Overhead estimates:**

| Priority | Functions | Overhead | Use Case |
|----------|-----------|----------|----------|
| 0 | ~14 | < 1% | Production monitoring |
| 1 | ~60 | 1-3% | Development/debugging |
| 2 | ~200 | 3-7% | Deep analysis |
| 3 | 1000+ | 10-20% | Comprehensive debug only |

**Overhead với sampling:**

- `--sample-rate 10`: Giảm overhead ~90%
- `--sample-rate 100`: Giảm overhead ~99%

**Best practices:**
- Production: Priority 0-1 với sampling
- Development: Priority 1-2 no sampling
- Deep debug: Priority 3 với sampling 10+

---

## 🔬 Comparison: Multi-Kprobe vs pwru

| Feature | pwru | NFT Tracer Multi-Kprobe |
|---------|------|------------------------|
| Language | Go | Python + C (eBPF) |
| Functions traced | ~1,600 | 1,000-2,000 (tùy kernel) |
| BTF discovery | ✅ Yes | ✅ Yes |
| Parameter positions | P1-P5 | P1-P5 |
| NFT integration | ❌ No | ✅ Yes (deep) |
| Drop tracking | ✅ kfree_skb_reason | ✅ kfree_skb_reason |
| Filtering | pcap-filter syntax | Config-based |
| Output format | JSON/text | Text + JSON export |
| Web UI | ❌ No | ✅ Yes (existing) |
| Session management | ❌ No | ✅ Yes |
| Realtime streaming | ❌ No | ✅ Yes (WebSocket) |

**Khi nào dùng pwru:**
- Cần pcap-filter syntax
- Standalone tool, không cần integration
- Go ecosystem

**Khi nào dùng Multi-Kprobe:**
- Cần NFT-specific analysis
- Integration với web UI
- Session management và export
- Realtime visualization

---

## 📖 API Reference

### enhanced_btf_discoverer.py

```bash
python3 enhanced_btf_discoverer.py [OPTIONS]

Options:
  --priority, -p INT    Max priority (0-3, default: 1)
  --category, -c STR    Filter by category (repeatable)
  --output, -o FILE     Output JSON file (default: discovered_functions.json)
  --function-list, -f FILE  Output plain text list
  --show-top, -t INT    Show top N functions (default: 30)
```

### multi_kprobe_tracer.py

```bash
python3 multi_kprobe_tracer.py [OPTIONS]

Options:
  --functions, -f FILE  Function list file
  --priority, -p INT    Priority level 0-3 (default: 1)
  --sample-rate, -s INT Sample rate (default: 1 = all)
  --verbose, -v         Verbose output
```

---

## 🎉 Summary

Bạn đã có một hệ thống tracing comprehensive tương đương pwru với:

✅ Auto BTF discovery cho 1000+ kernel functions
✅ Flexible priority levels (0-3)
✅ Multi-parameter position support (P1-P5)
✅ NFT deep integration
✅ Drop tracking với kfree_skb_reason
✅ Sampling để giảm overhead
✅ Category filtering
✅ Realtime statistics
✅ Có thể integrate vào web UI hiện tại

**Next Steps:**
1. Test với priority 1 trước
2. Compare với hệ thống cũ
3. Integrate vào backend API nếu cần
4. Deploy lên production với priority 0 + sampling

Happy tracing! 🚀
