# 🚀 Hướng Dẫn Chạy NFT Tracer App

Hướng dẫn chi tiết cách chạy ứng dụng NFT Tracer với hệ thống monitoring mới.

## 📋 Yêu Cầu Hệ Thống

- **OS**: Linux (Ubuntu/Debian recommended)
- **Python**: 3.8+
- **Node.js**: 16+ và npm
- **Root privileges**: Cần cho eBPF
- **Dependencies**:
  - BCC (BPF Compiler Collection)
  - Flask, Flask-SocketIO
  - React (frontend)

## ⚙️ Cài Đặt

### 1. Backend Dependencies

```bash
# Update system
sudo apt-get update

# Install Python dependencies
cd /home/user/nft-tracer-app/backend
sudo pip3 install flask flask-socketio flask-cors python-socketio bcc

# Hoặc từ requirements.txt (nếu có)
sudo pip3 install -r requirements.txt
```

### 2. Frontend Dependencies

```bash
cd /home/user/nft-tracer-app/frontend
npm install
```

## 🚀 Chạy Ứng Dụng

### Cách 1: Chạy Backend + Frontend Riêng Biệt (Recommended)

#### Terminal 1 - Backend:

```bash
cd /home/user/nft-tracer-app/backend
sudo python3 app.py
```

**Output mong đợi:**
```
╔══════════════════════════════════════════════╗
║     Unified Packet Tracing Backend v2.0      ║
║            FULL + REALTIME MODE              ║
╚══════════════════════════════════════════════╝

[*] Starting Flask-SocketIO server...
[*] Host: 0.0.0.0
[*] Port: 5000

[✓] Realtime API routes registered: /api/realtime/{enable,disable,stats,reset}
[✓] Monitoring API routes registered: /api/monitoring/{history,summary,alerts}
[*] RealtimeExtension initialized

 * Running on http://0.0.0.0:5000
```

#### Terminal 2 - Frontend:

```bash
cd /home/user/nft-tracer-app/frontend
npm start
```

**Output mong đợi:**
```
Compiled successfully!

You can now view kernel-packet-tracer-frontend in the browser.

  Local:            http://localhost:3000
  On Your Network:  http://192.168.x.x:3000
```

### Cách 2: Chạy Backend Standalone (Testing)

```bash
cd /home/user/nft-tracer-app/backend
sudo python3 realtime_extension.py --port 5000 --host 0.0.0.0
```

## 🔍 Kiểm Tra Hoạt Động

### 1. Kiểm tra Backend API

```bash
# Test health
curl http://localhost:5000/api/status

# Test monitoring API (sau khi enable)
curl http://localhost:5000/api/monitoring/history?hours=1
curl http://localhost:5000/api/monitoring/summary?hours=1
curl http://localhost:5000/api/monitoring/alerts
```

### 2. Kiểm tra Frontend

Mở browser tại: **http://localhost:3000**

1. Click vào tab **"Realtime"** (hoặc vào URL `/realtime`)
2. Click nút **"▶️ Enable"**
3. Bạn sẽ thấy:
   - ✅ Stats cards cập nhật real-time
   - ✅ Pipeline statistics
   - ✅ **Historical Metrics** charts (3 biểu đồ)
   - ✅ **Alert bell** 🔔 ở góc phải trên cùng

## 🎯 Sử Dụng Monitoring Features

### 1. Historical Timeline Charts

Sau khi Enable, cuộn xuống phần **"Historical Metrics"**:

- **Time Range Selector**: Chọn khoảng thời gian (15min → 3 days)
- **3 Charts**:
  - **Packet Flow**: Số lượng packets in/out/drop/accept
  - **Latency**: Độ trễ avg & p99
  - **Drop Rate**: % packets bị drop
- **Summary Stats**: Cards hiển thị tổng hợp metrics

### 2. Alert Notifications

- **Alert Bell** 🔔: Góc phải trên cùng
- **Toast Notifications**: Tự động hiện khi có alert
- **Alert History**: Click vào bell icon để xem lịch sử

### 3. Alert Rules (Mặc Định)

System sẽ tự động cảnh báo khi:

| Rule | Condition | Duration |
|------|-----------|----------|
| High Drop Rate | >5% | 10s |
| Critical Drop Rate | >20% | 5s |
| High Latency | >1ms (p99) | 30s |
| Critical Latency | >5ms (p99) | 10s |
| Low Packet Rate | <1 pps | 60s |
| High Error Count | >10 errors | 30s |

## 📊 Database & Storage

### SQLite Database

Metrics được lưu tự động tại:
```
/home/user/nft-tracer-app/backend/data/monitoring.db
```

### Kiểm tra Database

```bash
sqlite3 /home/user/nft-tracer-app/backend/data/monitoring.db

# Check tables
sqlite> .tables
metrics_raw  metrics_1min  metrics_5min

# View recent data
sqlite> SELECT COUNT(*) FROM metrics_raw;
sqlite> SELECT * FROM metrics_raw ORDER BY timestamp DESC LIMIT 5;

# Exit
sqlite> .quit
```

### Retention Policy

- **metrics_raw** (1s): 1 hour
- **metrics_1min** (1min): 24 hours
- **metrics_5min** (5min): **3 days**

Data tự động cleanup mỗi giờ.

## 🐛 Troubleshooting

### Backend không start

**Lỗi: Permission denied**
```bash
# Phải chạy với sudo
sudo python3 app.py
```

**Lỗi: Module not found**
```bash
# Cài lại dependencies
sudo pip3 install flask flask-socketio flask-cors bcc
```

**Lỗi: BPF compilation failed**
```bash
# Check BCC installation
python3 -c "from bcc import BPF; print('BCC OK')"

# Reinstall BCC nếu cần
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

### Frontend không kết nối

**Lỗi: CORS / Connection refused**
```bash
# Check backend đang chạy
curl http://localhost:5000/api/status

# Check proxy trong frontend/package.json
cat frontend/package.json | grep proxy
# Phải có: "proxy": "http://localhost:5000"
```

**Lỗi: 404 for /api/monitoring/history**
```bash
# Check backend logs
# Phải thấy dòng:
# [✓] Monitoring API routes registered: /api/monitoring/{history,summary,alerts}

# Restart backend nếu cần
sudo pkill -f "python3 app.py"
sudo python3 app.py
```

### Historical charts không hiện data

**Nguyên nhân**: Chưa có data (cần enable monitoring một lúc)

**Giải pháp**:
1. Enable monitoring
2. Đợi ít nhất 1-2 phút
3. Refresh page hoặc đổi time range

### Alerts không hoạt động

**Kiểm tra**:
```bash
# Test alert API
curl http://localhost:5000/api/monitoring/alerts
curl http://localhost:5000/api/monitoring/alerts/rules

# Check WebSocket connection (trong browser console)
# Phải thấy: [Alert] WebSocket connected
```

## 📱 Ports Đang Sử Dụng

- **Backend**: Port 5000 (Flask + SocketIO)
- **Frontend**: Port 3000 (React dev server)

Thay đổi port nếu cần:
```bash
# Backend
sudo python3 app.py --port 8000

# Frontend
PORT=3001 npm start
```

## 🔧 Development Mode

### Hot Reload

- **Frontend**: Tự động reload khi save file
- **Backend**: Cần restart manually khi thay đổi code

### Debug Logs

**Backend**:
```python
# Trong realtime_extension.py, thêm:
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Frontend**:
```javascript
// Browser Console (F12)
// Filter: "Alert", "History", "Monitoring"
```

## 📈 Performance Tips

1. **Database size**: Auto-vacuum mỗi giờ, nhưng có thể manual:
   ```bash
   sqlite3 backend/data/monitoring.db "VACUUM;"
   ```

2. **Memory usage**: Nếu RAM cao, giảm retention:
   ```python
   # Trong timeseries_db.py
   raw_cutoff = now - 1800  # 30 phút thay vì 1 giờ
   ```

3. **Alert frequency**: Tăng duration để giảm noise:
   ```python
   # Trong alert_engine.py
   AlertRule(..., duration=60)  # 60s thay vì 10s
   ```

## 📚 API Documentation

### GET /api/monitoring/history
Query historical metrics
```bash
curl "http://localhost:5000/api/monitoring/history?hours=3&granularity=1min"
```

### GET /api/monitoring/summary
Get summary stats
```bash
curl "http://localhost:5000/api/monitoring/summary?hours=24"
```

### GET /api/monitoring/alerts
Get active alerts
```bash
curl http://localhost:5000/api/monitoring/alerts
```

### GET /api/monitoring/alerts/history
Get alert history
```bash
curl "http://localhost:5000/api/monitoring/alerts/history?limit=100"
```

### POST /api/monitoring/alerts/clear
Clear all alerts
```bash
curl -X POST http://localhost:5000/api/monitoring/alerts/clear
```

## 🎓 Tham Khảo

- **MONITORING_FEATURES.md**: Chi tiết về monitoring system
- **README.md**: Project overview
- **Backend code**: `backend/realtime_extension.py`
- **Frontend code**: `frontend/src/RealtimeView.js`

---

**Chúc bạn sử dụng thành công!** 🎉

Nếu gặp vấn đề, check console logs (backend & browser) và xem Troubleshooting section.
