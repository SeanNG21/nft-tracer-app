# Auto BTF Discovery - PWru Style

## Tổng quan

Multi-function tracer giờ hỗ trợ **runtime auto-discovery** giống PWru - tự động scan BTF để tìm functions khi start, không cần pre-discovery step!

## 🎯 So sánh: Trước vs Sau

### ❌ Trước (2-step process):

```bash
# Step 1: Discovery (riêng biệt)
sudo python3 enhanced_skb_discoverer.py --output trace_config.json

# Step 2: Trace
sudo python3 multi_function_backend.py --config trace_config.json
```

### ✅ Sau (PWru style - 1 step):

```bash
# Chỉ cần start tracer - auto-discovery tự động chạy!
sudo python3 multi_function_backend.py
```

## 🔍 Cơ chế hoạt động

### PWru approach:

```
┌─────────────────────────────────────────┐
│ 1. Load /sys/kernel/btf/vmlinux        │
│    ↓                                    │
│ 2. Parse BTF type FUNC                 │
│    ↓                                    │
│ 3. Filter functions với skb param      │
│    ↓                                    │
│ 4. Classify by layer (Device, IP, TCP) │
│    ↓                                    │
│ 5. Prioritize (critical > important)   │
│    ↓                                    │
│ 6. Attach kprobe và trace ngay          │
└─────────────────────────────────────────┘
```

### Implementation:

**File: `backend/multi_function_backend.py`**

```python
def load_functions(self):
    """Auto-discovery if no config"""
    if self.config_file and os.path.exists(self.config_file):
        # Load from config
        ...
    else:
        # AUTO-DISCOVERY via BTF
        print("[*] Auto-discovering via BTF...")
        discoverer = EnhancedSKBDiscoverer()
        all_functions = discoverer.discover_all()

        # Filter priority 0-1 (critical + important)
        filtered = [f for f in all_functions if f.priority <= 1]

        # Use top N functions
        self.functions_to_trace = filtered[:self.max_functions]
```

**Discovery methods:**

1. **BTF-based** (most accurate):
   - Run `bpftool btf dump file /sys/kernel/btf/vmlinux`
   - Parse C-style function declarations
   - Find functions with `struct sk_buff *` parameter

2. **kallsyms heuristic** (broader coverage):
   - Read `/proc/kallsyms`
   - Find functions matching SKB patterns: `_skb_`, `_rcv`, `_xmit`, `nf_`, `tcp_`, etc.

## 📊 Function Classification

Functions được phân loại theo **11 layers**:

| Layer | Examples | Priority |
|-------|----------|----------|
| **Device** | `__netif_receive_skb_core`, `dev_queue_xmit` | 0 (critical) |
| **IPv4** | `ip_rcv`, `ip_forward`, `ip_output` | 0 (critical) |
| **TCP** | `tcp_v4_rcv`, `tcp_transmit_skb` | 0 (critical) |
| **Netfilter** | `nf_hook_slow`, `nft_do_chain`, `nft_immediate_eval` | 0-1 (critical/important) |
| **Routing** | `fib_lookup`, `ip_route_input` | 1 (important) |
| **GRO** | `napi_gro_receive`, `inet_gro_receive` | 1 (important) |
| **UDP** | `udp_rcv`, `udp_send_skb` | 1 (important) |
| **Xmit** | `dev_hard_start_xmit`, `sch_direct_xmit` | 2 (optional) |
| **SoftIRQ** | `net_rx_action`, `napi_poll` | 2 (optional) |
| **Bridge** | `br_handle_frame`, `br_forward` | 2 (optional) |
| **QDisc** | `qdisc_restart`, `__qdisc_run` | 2 (optional) |

**Priority filtering:**
- Auto-discovery mode: Only trace priority 0-1 (critical + important)
- Config mode: Trace all enabled functions

## 🚀 Sử dụng

### 1. Via Backend Script

```bash
# Auto-discovery (no config needed)
sudo python3 multi_function_backend.py --max-functions 50 --duration 30

# With config (skip auto-discovery)
sudo python3 multi_function_backend.py --config trace_config.json
```

### 2. Via API

```bash
# Auto-discovery mode (don't send config parameter)
curl -X POST http://localhost:5000/api/multi-function/start \
  -H "Content-Type: application/json" \
  -d '{
    "max_functions": 50
  }'

# Response:
{
  "status": "started",
  "functions_count": 45,
  "config": "AUTO-DISCOVERY (BTF)",
  "auto_discovery": true,
  "mode": "auto-btf"
}
```

```bash
# Config mode (send config parameter)
curl -X POST http://localhost:5000/api/multi-function/start \
  -H "Content-Type: application/json" \
  -d '{
    "config": "trace_config.json",
    "max_functions": 100
  }'

# Response:
{
  "status": "started",
  "functions_count": 100,
  "config": "trace_config.json",
  "auto_discovery": false,
  "mode": "config"
}
```

### 3. Check Status

```bash
curl http://localhost:5000/api/multi-function/status

# Response:
{
  "running": true,
  "auto_discovery": true,
  "mode": "auto-btf",
  "functions_count": 45,
  "stats": {
    "total_events": 1234,
    "packets_seen": 56,
    ...
  }
}
```

## 🎨 Frontend Integration

Frontend có thể detect auto-discovery mode:

```javascript
// Start with auto-discovery
const response = await fetch('/api/multi-function/start', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    max_functions: 50
    // No config = auto-discovery
  })
});

const data = await response.json();

if (data.auto_discovery) {
  console.log('🔍 Auto-discovery mode');
  console.log(`Discovered ${data.functions_count} functions via BTF`);
} else {
  console.log('📄 Config mode');
  console.log(`Loaded ${data.functions_count} functions from ${data.config}`);
}
```

## ⚙️ Configuration

### Default behavior:

| Parameter | Auto-Discovery | Config Mode |
|-----------|----------------|-------------|
| Discovery source | BTF + kallsyms | JSON file |
| Priority filter | 0-1 only | All enabled |
| Max functions | User specified | User specified |
| Layers | All 11 layers | Config defined |

### Override auto-discovery:

1. **Force config mode**: Provide `config` parameter
2. **Force auto-discovery**: Set `config: null` or omit parameter

## 🧩 Architecture

```
┌──────────────────────────────────────────────────┐
│         MultiFunctionBackendTracer               │
│                                                  │
│  load_functions()                                │
│    ├─ config exists? → load from file           │
│    └─ no config? → _auto_discover_functions()   │
│         │                                        │
│         └─> EnhancedSKBDiscoverer                │
│              ├─ discover_all()                   │
│              │   ├─ _discover_via_btf()         │
│              │   │   └─ bpftool btf dump        │
│              │   └─ _discover_via_kallsyms()    │
│              │       └─ /proc/kallsyms          │
│              ├─ _classify_all_functions()       │
│              │   └─ Assign layer & priority     │
│              └─ Return sorted list               │
│                                                  │
│  start()                                         │
│    └─> Attach kprobes to discovered functions   │
└──────────────────────────────────────────────────┘
```

## 📈 Performance

| Metric | Auto-Discovery | Config Mode |
|--------|----------------|-------------|
| Startup time | +2-5 seconds (BTF scan) | <1 second |
| Functions discovered | ~500-2000 (filtered to priority 0-1) | Config defined |
| Memory overhead | Minimal (discovery runs once) | None |
| Runtime overhead | Same (after discovery) | Same |

## 🔧 Troubleshooting

### "bpftool not found"
```bash
apt install linux-tools-$(uname -r)
```

### "BTF not supported"
Kernel phải >= 5.2 với CONFIG_DEBUG_INFO_BTF=y
```bash
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
```

### "No functions discovered"
Fallback to hardcoded critical functions:
- `__netif_receive_skb_core`
- `ip_rcv`, `ip_local_deliver`
- `tcp_v4_rcv`
- `dev_queue_xmit`

## 🎯 Use Cases

### 1. Quick troubleshooting (Auto-discovery)
```bash
# Start ngay không cần config
sudo python3 multi_function_backend.py --duration 30
ping 8.8.8.8
```

### 2. Custom function selection (Config mode)
```bash
# Generate config với custom filters
sudo python3 discovery/enhanced_skb_discoverer.py \
  --layers Netfilter IPv4 --priority 0

# Use config
sudo python3 multi_function_backend.py --config trace_config.json
```

### 3. Production monitoring (Config mode)
```bash
# Pre-generate optimized config cho production
# Deploy với config file cố định
```

## 📚 References

- [PWru - eBPF-based packet tracer](https://github.com/cilium/pwru)
- [BTF (BPF Type Format)](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [bpftool documentation](https://man7.org/linux/man-pages/man8/bpftool.8.html)
