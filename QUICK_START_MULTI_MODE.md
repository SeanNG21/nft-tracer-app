# Quick Start: Multi-Function NFT Tracer

## 🚀 5-Minute Setup

Trace **1000+ network functions** + **NFT verdicts** trong 5 phút!

---

## Prerequisites

```bash
# Check requirements
python3 --version  # >= 3.8
node --version     # >= 14
uname -r          # Linux kernel >= 5.3

# Check BPF support
ls /sys/kernel/btf/vmlinux  # Should exist
```

---

## Step 1: Start Backend (1 min)

```bash
cd /home/user/nft-tracer-app/backend

# Install dependencies (if needed)
pip3 install flask flask-cors bcc psutil flask-socketio python-socketio

# Start server
python3 app.py

# Expected output:
# [✓] Realtime visualization module loaded
# [*] Starting backend server on 0.0.0.0:5000
# [*] Press Ctrl+C to stop
```

Backend sẽ chạy tại: `http://localhost:5000`

---

## Step 2: Start Frontend (1 min)

```bash
# Terminal mới
cd /home/user/nft-tracer-app/frontend

# Install dependencies (if needed)
npm install

# Start dev server
npm start

# Expected output:
# Compiled successfully!
# Local: http://localhost:3000
```

Frontend sẽ tự động mở browser tại: `http://localhost:3000`

---

## Step 3: Discover Functions (30 seconds)

Trong UI:

1. Click tab **🔬 Discovery**
2. Click button **🔍 Bắt đầu Discovery**
3. Wait... (10-30 giây)
4. Result: **"✓ Đã phát hiện 1500+ functions!"**

---

## Step 4: Create Multi Mode Session (30 seconds)

Trong UI:

1. Click tab **📊 Sessions**
2. Configure:
   ```
   Session ID: (leave blank - auto generate)
   Mode: Multi-Function Tracer (Advanced) 🚀
   Max Functions: 500
   ```
3. Click **▶️ Bắt đầu Trace**
4. Wait for status: **[Running]**

---

## Step 5: Generate Traffic (1 min)

```bash
# Terminal mới
ping -c 10 8.8.8.8

# Hoặc
curl https://google.com
curl https://cloudflare.com
curl https://github.com

# Hoặc
wget https://example.com
```

---

## Step 6: View Results (1 min)

Trong UI:

### Real-time View

1. Session card sẽ update mỗi giây:
   ```
   Events/sec: 234
   Functions 🚀: 827
   Functions Hit: 156
   ```

2. Click session → tab **📊 Realtime Stats**
   - Live event graph
   - Hook flow diagram
   - Top functions

### Stop & Analyze

1. Click **⏹️ Dừng & Export**
2. Go to **📁 Files** tab
3. Click **🔍 Analyze** trên trace file vừa tạo

### Multi-Mode Viewer

Sẽ thấy:
- ✅ **Function Path**: Tất cả 100+ functions packet đi qua
- ✅ **NFT Timeline**: Rule evaluations + verdicts
- ✅ **Categories**: Distribution chart theo function type
- ✅ **Network Info**: Protocol, IPs, ports

---

## 🎯 What You Get

### Comprehensive Trace Output

```json
{
  "skb_addr": "0xffff888012345678",
  "duration_ms": 1.234,

  "functions_path": [
    "__netif_receive_skb_core",      // Entry point
    "ip_rcv",
    "ip_rcv_finish",
    "nf_hook_slow",                  // Netfilter entry
    "nf_conntrack_in",
    "nft_do_chain",                  // NFT chain entry
    "nft_immediate_eval",            // Rule 1 eval
    "nft_immediate_eval",            // Rule 2 eval
    "ip_local_deliver",
    "tcp_v4_rcv",
    "tcp_v4_do_rcv",
    ... // 100+ more functions
  ],

  "nft_events": [
    {
      "type": "rule_eval",
      "rule_seq": 1,
      "verdict": "CONTINUE"
    },
    {
      "type": "rule_eval",
      "rule_seq": 2,
      "verdict": "ACCEPT"        // ← Final verdict
    }
  ],

  "stats": {
    "total_functions": 127,
    "total_rules_evaluated": 2,
    "final_verdict": "ACCEPT"
  }
}
```

---

## 💡 Example Use Cases

### 1. Debug Packet Drops

**Scenario:** Packets không reach destination

```bash
# Start multi mode trace
# Send packet
ping 8.8.8.8

# Analyze result:
# - Check functions_path → tìm function cuối cùng
# - Check nft_events → tìm DROP verdict
# - Function trước DROP = nơi packet bị drop
```

**Example Output:**
```
functions_path: [
  ...
  "nf_hook_slow",
  "nft_do_chain",
  "nft_immediate_eval"  ← Stopped here
]

nft_events: [
  {"verdict": "DROP"}    ← Found the culprit!
]
```

### 2. Analyze NFT Rule Performance

**Scenario:** Muốn biết rule nào được evaluate

```bash
# Multi mode sẽ show:
# - Tất cả nft_immediate_eval calls
# - Timestamp mỗi rule
# - Verdict từng rule
# - Functions xung quanh NFT processing
```

**Example Output:**
```
nft_events: [
  {rule_seq: 1, timestamp: 0.123ms, verdict: "CONTINUE"},
  {rule_seq: 2, timestamp: 0.125ms, verdict: "CONTINUE"},
  {rule_seq: 3, timestamp: 0.127ms, verdict: "ACCEPT"}
]

→ Rule 3 là final verdict
→ Total NFT processing: 0.004ms
```

### 3. Compare Network Paths

**Scenario:** TCP vs UDP packet paths

```bash
# Trace TCP
curl https://google.com  # → TCP trace

# Trace UDP
dig google.com          # → UDP trace

# Compare functions_path:
# TCP: tcp_v4_rcv → tcp_v4_do_rcv → tcp_rcv_established
# UDP: udp_rcv → udp_unicast_rcv_skb → __udp4_lib_rcv
```

---

## 🔧 Advanced Configuration

### High Volume Traffic

```javascript
// Frontend: Increase max_functions
max_functions: 1000    // Trace more functions

// But: Higher CPU overhead
// Recommended: Start with 100-500
```

### Filter Specific Protocol

```python
# Backend: Enable BPF filtering (in multi_function_tracer.bpf.c)
# Already implemented, just need to activate via map:

bpf_multi["filter_map"][0] = {
    'filter_protocol': 6,  # TCP only
    'filter_src_ip': 0,    # No IP filter
    'filter_dst_ip': 0,
}
```

### Custom Categories

```javascript
// Frontend: Add custom function categories
// Edit MultiModeViewer.jsx:

const categorizeFunction = (funcName) => {
  if (funcName.includes('ipsec_'))
    return 'ipsec';  // New category

  // ... rest
};
```

---

## 📊 Performance Tips

### 1. Start Small
```
First session: max_functions = 100
If OK: max_functions = 500
If still OK: max_functions = 1000+
```

### 2. Monitor CPU
```bash
# Check CPU usage while tracing
top -p $(pgrep -f "python3 app.py")

# If > 80% CPU:
# → Reduce max_functions
# → Add BPF filtering
```

### 3. Limit Trace Duration
```
Don't leave multi mode running for hours!
Recommended: 1-5 minutes per session
```

---

## 🐛 Common Issues

### Issue: "BCC not available"

```bash
# Install BCC
sudo apt-get install bpfcc-tools python3-bpfcc

# Or build from source:
git clone https://github.com/iovisor/bcc.git
cd bcc && mkdir build && cd build
cmake .. && make && sudo make install
```

### Issue: "No functions discovered"

```bash
# Check bpftool
which bpftool

# Install if missing
sudo apt-get install linux-tools-common linux-tools-$(uname -r)

# Check BTF
ls -la /sys/kernel/btf/vmlinux
```

### Issue: "Too many events, high CPU"

```javascript
// Solution 1: Reduce max_functions
max_functions: 100  // Instead of 1000

// Solution 2: Add packet filtering
// (Need backend code modification)

// Solution 3: Use 'full' mode instead
mode: 'full'  // Only 30 critical functions
```

### Issue: "Frontend shows empty viewer"

```bash
# Check browser console for errors
# Verify trace data structure:

{
  "functions_path": [...],  ← Must exist
  "nft_events": [...],      ← Must exist
  "packet_info": {...}      ← Must exist
}

# If missing, check backend export format
```

---

## 📈 Next Steps

### 1. Explore Other Modes

```
Mode: NFT Tracer
→ Only NFT verdicts, no functions
→ Fastest, lowest overhead
→ Use khi chỉ cần debug nftables

Mode: Full Tracer
→ ~30 critical functions + NFT verdicts
→ Balanced performance
→ Use khi cần overview packet path

Mode: Multi Tracer
→ 1000+ functions + NFT verdicts
→ Comprehensive analysis
→ Use khi cần deep debugging
```

### 2. Customize BPF Program

```c
// Edit: backend/multi_function_tracer.bpf.c

// Add custom filtering
if (meta.protocol != 6) {  // Only TCP
    return 0;
}

// Add custom events
struct custom_event evt = {...};
events.perf_submit(ctx, &evt, sizeof(evt));
```

### 3. Export Custom Formats

```python
# Edit: backend/app.py

# Add CSV export
@app.route('/api/traces/<filename>/csv')
def export_csv(filename):
    # Convert JSON to CSV
    ...
```

### 4. Integration with Monitoring

```bash
# Export metrics to Prometheus
# Example: backend/prometheus_exporter.py

from prometheus_client import Counter, Histogram

packets_traced = Counter('packets_traced_total', 'Total packets traced')
trace_duration = Histogram('trace_duration_seconds', 'Trace duration')
```

---

## ✅ Checklist

- ✅ Backend running on port 5000
- ✅ Frontend running on port 3000
- ✅ Functions discovered (1000+)
- ✅ Multi mode session created
- ✅ Traffic generated
- ✅ Results visible in MultiModeViewer
- ✅ Can filter by category
- ✅ NFT events showing verdicts
- ✅ Category distribution chart displayed

---

## 🎓 Learning Resources

- **Backend Guide**: [MULTI_MODE_GUIDE.md](./MULTI_MODE_GUIDE.md)
- **Frontend Guide**: [FRONTEND_MULTI_MODE_GUIDE.md](./FRONTEND_MULTI_MODE_GUIDE.md)
- **pwru Documentation**: https://github.com/cilium/pwru
- **eBPF Tutorial**: https://ebpf.io/what-is-ebpf
- **NFTables Wiki**: https://wiki.nftables.org

---

## 🎉 Success Criteria

Bạn đã setup thành công nếu:

1. ✅ Trace 1 packet và thấy 100+ functions trong path
2. ✅ Thấy NFT verdicts (ACCEPT/DROP/CONTINUE)
3. ✅ Filter được functions theo category
4. ✅ Thấy timeline NFT rules được evaluate
5. ✅ Export được JSON file với full data

**Congratulations! 🎊**

Bạn đã có tool trace comprehensive nhất cho Linux networking + nftables!

---

**Happy Tracing!** 🚀

**Questions?** Open issue tại: https://github.com/SeanNG21/nft-tracer-app/issues
