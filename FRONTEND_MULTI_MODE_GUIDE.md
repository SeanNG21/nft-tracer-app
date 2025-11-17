# Frontend Multi-Mode Guide

## 🎨 Overview

Frontend UI đã được nâng cấp để hỗ trợ **Multi-Function Tracer Mode** với:
- ✅ Specialized viewer cho comprehensive traces
- ✅ Interactive function filtering by category
- ✅ NFT verdict timeline visualization
- ✅ Category distribution charts
- ✅ Mobile responsive design

---

## 🖼️ Screenshots

### 1. Mode Selection
```
┌─────────────────────────────────────────────┐
│ Mode: Multi-Function Tracer (Advanced) 🚀  │
│                                             │
│ ⚠️ Advanced Mode: Trace 1000+ functions    │
│ như pwru/cilium. Có thể gây high CPU       │
│ overhead. Recommended cho deep analysis.    │
│                                             │
│ Max Functions: [500]  (1-2000)              │
│ Set 0 để trace TẤT CẢ discovered functions │
└─────────────────────────────────────────────┘
```

### 2. Session Stats
```
┌─────────────────────────────────────────────┐
│ Session: multi_trace_001          [Running] │
│                                             │
│ Events/sec: 1234                            │
│ Total Events: 56,789                        │
│ Functions 🚀: 827                           │
│ Functions Hit: 312                          │
│                                             │
│ ⏱️ Uptime: 5m 23s                          │
│ [⏹️ Dừng & Export]                         │
└─────────────────────────────────────────────┘
```

### 3. MultiModeViewer (Packet Detail)
```
┌─────────────────────────────────────────────────────────┐
│ 🚀 Multi-Mode Comprehensive Trace                      │
│ SKB: 0xffff888012345678                                 │
├─────────────────────────────────────────────────────────┤
│ Total Functions: 127  │  NFT Rules: 2                   │
│ Duration: 1.234ms     │  Final Verdict: ACCEPT          │
├─────────────────────────────────────────────────────────┤
│ 🌐 Network Information                            [▼]   │
│   Protocol: TCP                                         │
│   Source: 192.168.1.100:54321                           │
│   Destination: 8.8.8.8:443                              │
├─────────────────────────────────────────────────────────┤
│ 📋 Function Call Path (127 functions)             [▼]   │
│   [All] [🔥nft:5] [🛡️netfilter:12] [📡tcp:23]          │
│                                                         │
│   1  🔌 __netif_receive_skb_core                        │
│   2  🌐 ip_rcv                                          │
│   3  🌐 ip_rcv_finish                                   │
│   4  🛡️ nf_hook_slow                                   │
│   ... (123 more)                                        │
├─────────────────────────────────────────────────────────┤
│ 🔥 NFT Events (2)                                 [▼]   │
│   ● 📜 Rule Evaluation  [0.123ms]                       │
│     Rule: #1 (0x5)                                      │
│     Verdict: CONTINUE                                   │
│                                                         │
│   ● 📜 Rule Evaluation  [0.125ms]                       │
│     Rule: #2 (0x6)                                      │
│     Verdict: ACCEPT                                     │
├─────────────────────────────────────────────────────────┤
│ 📊 Function Categories Distribution               [▼]   │
│   📡 tcp: 23  ████████████████ 18.1%                    │
│   🛡️ netfilter: 12  ████████ 9.4%                      │
│   🌐 ip: 18  ███████████ 14.2%                          │
│   ...                                                   │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Usage

### Step 1: Start Frontend
```bash
cd /home/user/nft-tracer-app/frontend
npm install  # if needed
npm start
```

Frontend sẽ chạy tại: `http://localhost:3000`

### Step 2: Create Multi Mode Session

1. Navigate to **📊 Sessions** tab
2. Select mode: **Multi-Function Tracer (Advanced) 🚀**
3. Configure:
   - **Session ID**: (optional) `my_multi_trace`
   - **Max Functions**: `500` (hoặc 0 cho unlimited)
4. Click **▶️ Bắt đầu Trace**

### Step 3: Generate Traffic

```bash
# Terminal riêng
ping -c 10 8.8.8.8
# hoặc
curl https://google.com
```

### Step 4: View Real-time Stats

- Session card sẽ show stats live
- Click vào session để xem **📈 Chi tiết Session**
- Switch to **📊 Realtime Stats** tab

### Step 5: Stop & Analyze

1. Click **⏹️ Dừng & Export**
2. Go to **📁 Files** tab
3. Click **🔍 Analyze** trên trace file

---

## 🎯 MultiModeViewer Features

### 1. Function Path Visualization

**Features:**
- Hiển thị tất cả functions (1000+) packet đi qua
- Mỗi function có:
  - Index số (thứ tự gọi)
  - Color dot theo category
  - Function name (code font)
  - Category badge
- Click function để select/highlight

### 2. Category Filtering

**Available Categories:**
- 🔥 **nft**: nftables functions (`nft_*`, `nf_tables_*`)
- 🛡️ **netfilter**: Netfilter hooks (`nf_*`, `xt_*`, `ipt_*`)
- 📡 **tcp**: TCP stack (`tcp_*`, `__tcp_*`)
- 📨 **udp**: UDP stack (`udp_*`, `__udp_*`)
- 🌐 **ip**: IP layer (`ip_*`, `ipv4_*`, `ipv6_*`)
- 🔌 **network**: Network device (`netif_*`, `dev_*`)
- 📦 **skb**: SKB operations (`skb_*`)
- ⚙️ **other**: Other functions

**Usage:**
- Click category button để filter
- Function list sẽ chỉ show category đó
- Click "All" để show tất cả

### 3. NFT Events Timeline

**Features:**
- Vertical timeline với dots
- Mỗi event hiển thị:
  - Type (Chain Entry/Exit, Rule Evaluation)
  - Timestamp (relative)
  - Rule number & handle
  - Verdict với color-coding
- Timeline line nối các events

**Verdict Colors:**
- 🟢 **ACCEPT**: Green
- 🔴 **DROP**: Red
- 🔵 **CONTINUE**: Blue
- 🟡 **RETURN**: Yellow

### 4. Category Distribution

**Features:**
- Visual bar chart
- Shows percentage per category
- Sorted by count (descending)
- Color-coded bars

### 5. Network Information

**Shows:**
- Protocol (TCP/UDP/ICMP/etc)
- Source IP:Port
- Destination IP:Port
- Packet length

---

## 🎨 UI Components

### Core Components

```
frontend/src/
├── App.js                  ← Mode selection, session management
├── TraceViewer.jsx         ← Main trace analyzer (conditional rendering)
├── MultiModeViewer.jsx     ← Multi mode specialized viewer
├── MultiModeViewer.css     ← Styling for multi mode
├── PacketList.jsx          ← Packet list (reused)
└── PacketDetail.jsx        ← Normal mode detail (reused)
```

### Component Hierarchy

```
App
├── Sessions Tab
│   ├── Session Creation Form
│   │   └── Mode Selector (includes 'multi')
│   └── Active Sessions List
│       └── Session Cards (with multi mode badge)
│
├── Files Tab
│   └── TraceViewer
│       ├── PacketList
│       └── Conditional:
│           ├── MultiModeViewer (if mode='multi')
│           └── PacketDetail (if mode != 'multi')
│
└── Realtime Tab
    └── RealtimeView
```

---

## 🔧 Configuration

### Max Functions Limits

```javascript
// App.js
{newSession.mode === 'multi' ? (
  <input
    type="number"
    min="1"
    max={2000}  // ← Multi mode: up to 2000
    value={newSession.maxFunctions}
  />
) : (
  <input
    type="number"
    min="1"
    max={100}   // ← Other modes: up to 100
    value={newSession.maxFunctions}
  />
)}
```

### Performance Warnings

```javascript
// Show warning if > 500 functions
{newSession.maxFunctions > 500 && (
  <small className="warning">
    ⚠️ {newSession.maxFunctions}+ functions sẽ gây very high overhead!
  </small>
)}
```

---

## 📊 Data Flow

### Multi Mode Data Flow

```
1. User creates session (mode='multi')
   └─→ POST /api/sessions

2. Backend starts BPF tracing
   └─→ multi_function_tracer.bpf.c loads
   └─→ Attaches 1000+ kprobes

3. Real-time stats (WebSocket)
   └─→ socketio.on('session_stats')
   └─→ Update session card

4. User stops session
   └─→ DELETE /api/sessions/{id}
   └─→ Export JSON file

5. User analyzes trace
   └─→ GET /api/traces/{filename}
   └─→ TraceViewer renders
   └─→ mode === 'multi' ? MultiModeViewer : PacketDetail
```

### MultiModeViewer Props

```javascript
<MultiModeViewer
  trace={{
    skb_addr: "0xffff...",
    first_seen_ns: 123456789,
    duration_ns: 1234567,

    functions_path: [
      "__netif_receive_skb_core",
      "ip_rcv",
      "nf_hook_slow",
      ... // 1000+ more
    ],

    nft_events: [
      {
        type: "rule_eval",
        rule_seq: 1,
        rule_handle: 5,
        verdict: "CONTINUE",
        timestamp_ns: 123456800
      },
      ...
    ],

    packet_info: {
      protocol: "TCP",
      src_ip: "192.168.1.100",
      dst_ip: "8.8.8.8",
      src_port: 54321,
      dst_port: 443,
      length: 1500
    },

    stats: {
      total_functions: 127,
      total_rules_evaluated: 2,
      final_verdict: "ACCEPT"
    }
  }}
/>
```

---

## 🎭 Styling

### Color Scheme

```css
/* Primary Colors */
--primary: #667eea;        /* Purple gradient */
--secondary: #764ba2;

/* Category Colors */
--nft: #e74c3c;           /* Red */
--netfilter: #e67e22;     /* Orange */
--tcp: #3498db;           /* Blue */
--udp: #9b59b6;           /* Purple */
--ip: #1abc9c;            /* Teal */
--network: #2ecc71;       /* Green */
--skb: #f39c12;           /* Yellow-orange */
--other: #95a5a6;         /* Gray */

/* Verdict Colors */
--accept: #d4edda / #155724;
--drop: #f8d7da / #721c24;
--continue: #d1ecf1 / #0c5460;
--return: #fff3cd / #856404;
```

### Responsive Breakpoints

```css
@media (max-width: 768px) {
  /* Mobile: Stack grids, hide less important info */
  .mmv-stats-row {
    grid-template-columns: 1fr;
  }

  .mmv-function-category {
    display: none;  /* Hide category badges on mobile */
  }
}
```

---

## 🐛 Troubleshooting

### Issue: Mode 'multi' không xuất hiện trong dropdown

**Solution:**
```bash
# Check backend API
curl http://localhost:5000/api/modes

# Should return:
{
  "modes": [
    ...
    {"id": "multi", "name": "Multi-Function Tracer (Advanced)", ...}
  ]
}

# If not, restart backend
cd backend
python3 app.py
```

### Issue: MultiModeViewer shows empty

**Solution:**
- Check trace data structure trong browser console
- Verify `trace.functions_path` array exists
- Check `trace.nft_events` array
- Make sure backend exports correct format

### Issue: Categories not colored

**Solution:**
```bash
# Check MultiModeViewer.css is loaded
# Inspect element → Computed styles → should have category colors

# If missing, rebuild frontend
cd frontend
npm run build
npm start
```

### Issue: Functions không filter được

**Solution:**
- Check browser console for errors
- Verify `categorizeFunction()` logic
- Test with console:
```javascript
const categorizeFunction = (name) => {
  if (name.includes('tcp_')) return 'tcp';
  // ... rest of logic
};
console.log(categorizeFunction('tcp_v4_rcv')); // Should return 'tcp'
```

---

## 📈 Performance Tips

### 1. Limit Functions for Testing
```javascript
// Start with lower number for testing
max_functions: 100  // Instead of 1000+
```

### 2. Use Category Filtering
```javascript
// Filter to specific category to reduce rendering
filterCategory: 'nft'  // Only show nft functions
```

### 3. Enable Virtualization (Future)
```javascript
// For 1000+ functions, implement virtual scrolling
// Using react-window or react-virtualized
```

---

## 🎓 Advanced Customization

### Add Custom Categories

```javascript
// MultiModeViewer.jsx
const categorizeFunction = (funcName) => {
  // Add your custom category
  if (funcName.includes('xfrm_'))
    return 'ipsec';  // ← New category

  // ... existing logic
};

const categoryColors = {
  ...
  ipsec: '#8e44ad',  // ← Add color
};

const categoryIcons = {
  ...
  ipsec: '🔐',  // ← Add icon
};
```

### Customize Timeline

```css
/* MultiModeViewer.css */
.mmv-nft-event-dot {
  width: 20px;          /* Larger dots */
  height: 20px;
  background: #667eea;
}

.mmv-nft-event-line {
  width: 3px;           /* Thicker line */
  background: linear-gradient(to bottom, #667eea, #764ba2);
}
```

---

## ✅ Checklist

- ✅ Backend API updated with 'multi' mode
- ✅ Frontend mode selector includes multi option
- ✅ Max functions limit increased to 2000
- ✅ MultiModeViewer component created
- ✅ Conditional rendering in TraceViewer
- ✅ Category filtering implemented
- ✅ NFT timeline visualization
- ✅ Distribution charts
- ✅ Responsive design
- ✅ Error handling
- ✅ Documentation complete

---

## 📚 Related Documentation

- [MULTI_MODE_GUIDE.md](./MULTI_MODE_GUIDE.md): Backend implementation
- [Backend API Docs](./backend/README.md): API reference
- [Component API](./frontend/README.md): Component props

---

**Created:** 2025-11-17
**Author:** Claude
**Version:** 1.0.0
