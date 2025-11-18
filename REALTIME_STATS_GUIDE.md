# 📊 Hướng Dẫn Sử Dụng Realtime Stats cho Sessions

## Tổng Quan

Realtime Stats cung cấp khả năng theo dõi trực tiếp (realtime) các metrics của trace sessions thông qua WebSocket. Bạn có thể xem live graphs, packet flow, latency, và nhiều metrics khác mà không cần refresh trang.

## Kiến Trúc

```
┌─────────────────┐         WebSocket          ┌──────────────────┐
│   Frontend      │ <────────────────────────> │    Backend       │
│ (React + IO)    │  session_stats_update      │  (Flask + IO)    │
└─────────────────┘                             └──────────────────┘
         │                                                 │
         │                                                 │
         ▼                                                 ▼
┌─────────────────┐                             ┌──────────────────┐
│SessionRealtime  │                             │SessionStats      │
│Stats Component  │                             │Tracker           │
└─────────────────┘                             └──────────────────┘
```

## Backend Components

### 1. `realtime_extension.py`

File backend chính cung cấp realtime stats cho sessions.

**Class chính:**
- `SessionStatsTracker`: Track stats cho từng session
- `RealtimeExtension`: Quản lý multiple session trackers và WebSocket

**Data Structures:**
- `NodeStats`: Thống kê cho pipeline nodes (NIC, Netfilter, TCP/UDP, v.v.)
- `EdgeStats`: Thống kê transitions giữa các nodes
- `PipelineStats`: Thống kê cho Inbound/Outbound/Local Delivery/Forward pipelines
- `LayerStats`: Thống kê cho từng layer
- `HookStats`: Thống kê cho từng hook

**Metrics được track:**
- Packet count và packet rate (packets/sec)
- Latency percentiles (p50, p90, p99, avg) tính bằng microseconds
- Verdict breakdown (ACCEPT, DROP, STOLEN, QUEUE, v.v.)
- Top functions được gọi nhiều nhất
- In-flight packets (packets đang xử lý)
- Pipeline completion stats (started, in-flight, completed)

### 2. `session_stats_extension.py`

File backend standalone tương tự `realtime_extension.py` nhưng có thể chạy độc lập. Cấu trúc và metrics giống hệt.

## Frontend Components

### 1. `SessionRealtimeStats.js`

React component hiển thị realtime stats cho một session cụ thể.

**Features:**
- WebSocket connection tự động
- Live update mỗi 1 giây
- Pipeline flow visualization (Inbound/Outbound)
- Hook-based packet flow
- Latency heatmap
- Verdict statistics
- Top latency contributors

**Props:**
- `sessionId`: ID của session cần track

## Cách Sử Dụng

### 1. Start Backend với Realtime Support

```bash
cd backend
sudo python3 app.py
```

Backend sẽ tự động load `realtime_extension.py` nếu có flask-socketio.

### 2. Tạo Trace Session

Trong frontend (http://localhost:3000):

1. Vào tab **"📊 Sessions"**
2. Chọn mode **"full"** (recommended cho realtime stats đầy đủ)
3. Click **"▶️ Bắt đầu Trace"**

### 3. Xem Realtime Stats

1. Click vào session card để xem chi tiết
2. Chuyển sang tab **"📊 Realtime Stats"**
3. Stats sẽ tự động cập nhật mỗi 1 giây

### Các Panels Hiển Thị:

#### 📈 Overview Stats
- Total Packets: Tổng số packets đã xử lý
- Packets/Sec: Tốc độ xử lý hiện tại
- Uptime: Thời gian chạy
- Mode: Chế độ trace (FULL/NFT/MULTIFUNCTION)

#### 🚀 Pipeline Statistics (Full Mode only)
- **Inbound**: Packets vào (started, in-flight, completed)
- **Outbound**: Packets ra (started, in-flight, completed)
- **Local Delivery**: Packets gửi đến local socket
- **Forward**: Packets được forward

#### ⚖️ Netfilter Verdict Statistics
- Tổng số verdicts theo loại (ACCEPT, DROP, STOLEN, v.v.)
- Phần trăm mỗi verdict
- Color-coded badges

#### 🔥 Top Latency Contributors
- Top 5 nodes có average latency cao nhất
- Potential bottlenecks
- Sample count

#### 🔄 Enhanced Packet Pipeline Flow
- **Inbound Traffic Flow:**
  - NIC → Driver (NAPI) → GRO → TC Ingress → Netfilter PREROUTING → Conntrack → NAT PREROUTING → Routing Decision
  - Branches:
    - Local Delivery: Netfilter INPUT → TCP/UDP → Socket
    - Forward: Netfilter FORWARD → Netfilter POSTROUTING → NIC TX

- **Outbound Traffic Flow:**
  - Application → TCP/UDP Output → Netfilter OUTPUT → Routing Lookup → NAT POSTROUTING → TC Egress → Driver TX → NIC

Mỗi node hiển thị:
- Count: Số events đã qua node
- In-flight: Số packets đang xử lý tại node
- Packet rate: Tốc độ hiện tại (pkt/s)
- Latency: p50 latency (microseconds)
- Top functions: Functions được gọi nhiều nhất
- Verdicts: Verdict breakdown cho Netfilter nodes
- Drops/Errors: Số packets bị drop hoặc lỗi

## WebSocket Events

### Client → Server

#### `join_session`
Tham gia vào session room để nhận stats updates.

```javascript
socket.emit('join_session', { session_id: 'session_123' });
```

#### `leave_session`
Rời khỏi session room.

```javascript
socket.emit('leave_session', { session_id: 'session_123' });
```

### Server → Client

#### `joined_session`
Xác nhận đã join room thành công.

```javascript
socket.on('joined_session', (data) => {
  // data = { session_id: 'session_123' }
});
```

#### `session_stats_update`
Stats update mỗi 1 giây.

```javascript
socket.on('session_stats_update', (data) => {
  // data = {
  //   session_id: 'session_123',
  //   stats: {
  //     total_packets: 1234,
  //     total_events: 5678,
  //     packets_per_second: 45.2,
  //     uptime_seconds: 120.5,
  //     mode: 'full',
  //     hooks: { ... },
  //     nodes: { ... },
  //     edges: [ ... ],
  //     pipelines: [ ... ],
  //     total_verdicts: { ... },
  //     top_latency: [ ... ]
  //   }
  // }
});
```

## Testing WebSocket Connection

Sử dụng test page để debug WebSocket connection:

1. Mở file `frontend/src/SessionRealtimeStatsTest.html` trong browser
2. Click **"Connect"** để kết nối WebSocket
3. Nhập Session ID và click **"Join Session"**
4. Quan sát event log và stats updates

## Troubleshooting

### 1. "Realtime Stats Không Khả Dụng"

**Nguyên nhân:**
- Backend chưa cài flask-socketio
- Backend chưa chạy với realtime extension

**Giải pháp:**
```bash
pip3 install flask-socketio python-socketio
sudo python3 backend/app.py
```

### 2. WebSocket Không Kết Nối

**Kiểm tra:**
1. Backend có chạy không?
   ```bash
   curl http://localhost:5000/api/health
   ```

2. SocketIO port có mở không?
   ```bash
   netstat -tlnp | grep 5000
   ```

3. Firewall có block không?
   ```bash
   sudo ufw status
   ```

**Giải pháp:**
- Kiểm tra console log trong browser (F12 → Console)
- Kiểm tra backend log
- Thử connect bằng test page

### 3. Stats Không Update

**Kiểm tra:**
1. Session có đang running không?
2. WebSocket có connected không? (xem status indicator)
3. Có traffic đi qua không? (generate traffic: `ping 8.8.8.8`)

**Giải pháp:**
- Refresh trang và reconnect
- Kiểm tra backend log: `tail -f backend/logs/app.log`
- Kiểm tra session có được track không:
  ```bash
  curl http://localhost:5000/api/session/list
  ```

### 4. "Session not found in trackers"

**Nguyên nhân:**
- Session được tạo nhưng tracking chưa được start
- Session ID không khớp

**Giải pháp:**
- Xác nhận session ID đúng
- Stop và start lại session
- Kiểm tra backend log để thấy session được track:
  ```
  [Session] Started tracking for session: session_123 (mode: full)
  ```

### 5. Performance Issues / High Memory

**Nguyên nhân:**
- Quá nhiều packets được track
- Memory không được cleanup

**Giải pháp:**
- Giảm `max_functions` khi tạo session
- Backend tự động cleanup sau 10,000 SKBs
- Restart session nếu cần

## Best Practices

### 1. Chọn Mode Phù Hợp

- **full**: Xem đầy đủ pipeline flow, latency, nodes (recommended)
- **nft**: Chỉ xem NFT verdicts và hooks
- **multifunction**: Aggregate stats, ít chi tiết hơn

### 2. Memory Management

- Backend giới hạn tracking tối đa 10,000 SKBs
- Cleanup tự động khi vượt ngưỡng
- Stop session khi không cần để free memory

### 3. Packet Rate

- Update mỗi 1 giây (optimal readability)
- Không block main thread
- Async processing

### 4. Production Usage

- Disable debug logging
- Giảm max_functions về 20-30
- Monitor memory usage
- Set up alerts cho high drop rate

## API Endpoints

### Session Management

```
GET  /api/sessions                      # List all sessions
POST /api/sessions                      # Create new session
GET  /api/sessions/<id>/stats           # Get session stats
DELETE /api/sessions/<id>               # Stop session

GET  /api/session/<id>/stats            # Get realtime stats
POST /api/session/<id>/start            # Start tracking
POST /api/session/<id>/stop             # Stop tracking
GET  /api/session/list                  # List tracked sessions
```

### Realtime Extension

```
POST /api/realtime/enable               # Enable global realtime tracer
POST /api/realtime/disable              # Disable global realtime tracer
GET  /api/realtime/stats                # Get global realtime stats
POST /api/realtime/reset                # Reset stats
```

## Architecture Details

### Stats Calculation Flow

```
1. eBPF kernel hooks capture events
   ↓
2. Events sent to userspace via perf buffer
   ↓
3. SessionStatsTracker processes events
   ↓
4. Stats aggregated by node/hook/layer
   ↓
5. Every 1 second, emit via WebSocket
   ↓
6. Frontend receives and updates UI
```

### Memory Management

```python
# Auto-cleanup when SKB tracking exceeds limit
if len(self.skb_tracking) > 10000:
    # Remove oldest 1000 entries
    oldest_keys = list(self.skb_tracking.keys())[:1000]
    for key in oldest_keys:
        # Cleanup in-flight packets
        for node_stats in self.nodes.values():
            node_stats.in_flight_packets.discard(key)
        del self.skb_tracking[key]
```

### Thread Safety

- All stats operations use locks
- WebSocket emit runs in separate thread
- No blocking on main event loop

## Contributions

File `session_stats_extension.py` được tạo giống hệt `realtime_extension.py` để có thể:
- Chạy standalone (testing)
- Tách biệt logic session tracking
- Dễ maintain và debug

## License

MIT License - See LICENSE file for details
