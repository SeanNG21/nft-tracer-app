# Test Environment - Quick Reference

## Tổng Quan

Hệ thống test environment hoàn chỉnh để **generate network traffic** cho NFT Tracer. Dùng để test code và viết báo cáo.

## 🚀 Quick Start

```bash
cd test-environment

# Option 1: Quick start menu
./quick-start.sh

# Option 2: Docker Compose (Recommended)
cd docker
docker-compose -f docker-compose.test-env.yml up

# Option 3: Local Python
python3 services/mock-web-server.py &
python3 services/mock-api-service.py &
python3 traffic-generators/http-traffic-generator.py mixed
```

## 📦 Có Gì Trong Test Environment?

### 1. Mock Services (Các ứng dụng giả lập)
- **Mock Web Server** (port 8080) - HTTP traffic
- **Mock API Service** (port 8081) - REST API traffic
- **Mock Databases** (Redis, PostgreSQL, MySQL) - Database traffic

### 2. Traffic Generators
- **HTTP Traffic Generator** - Generate HTTP requests
- **Network Traffic Generator** - TCP, UDP, ICMP traffic
- **Attack Simulator** - Simulate attacks (SQL injection, XSS, DDoS, etc.)

### 3. Deployment Options
- **Local** - Chạy Python scripts trực tiếp
- **Docker** - Docker Compose với multiple services
- **Kubernetes** - K8s manifests cho production-like setup

## 🎯 Scenarios Có Sẵn

| Scenario | Mô Tả | Command |
|----------|-------|---------|
| Normal | User behavior bình thường | `python3 traffic-generators/http-traffic-generator.py normal` |
| Burst | Traffic burst (load testing) | `python3 traffic-generators/http-traffic-generator.py burst` |
| Mixed | Mixed protocols | `python3 traffic-generators/http-traffic-generator.py mixed` |
| Attack | Security testing | `python3 scenarios/attack-simulator.py all` |

## 📊 Workflow Để Viết Báo Cáo

### Bước 1: Start NFT Tracer
```bash
cd backend
sudo python3 app.py
# Mở http://localhost:5000
```

### Bước 2: Start Test Environment
```bash
cd test-environment/docker
docker-compose -f docker-compose.test-env.yml up
```

### Bước 3: Generate Traffic
```bash
# Terminal khác
cd test-environment
python3 traffic-generators/http-traffic-generator.py all
python3 traffic-generators/network-traffic-generator.py all
```

### Bước 4: Capture Screenshots
- NFT Tracer Dashboard
- Traffic statistics
- Packet traces
- Docker containers running

### Bước 5: Export Data
```bash
# Export traces
curl http://localhost:5000/api/traces > traces.json

# Export stats
curl http://localhost:5000/api/stats > stats.json

# Save logs
docker-compose logs > test-logs.txt
```

## 🐳 Docker Commands

```bash
# Start environment
docker-compose -f docker/docker-compose.test-env.yml up -d

# View logs
docker-compose -f docker/docker-compose.test-env.yml logs -f

# Check services
docker-compose -f docker/docker-compose.test-env.yml ps

# Stop
docker-compose -f docker/docker-compose.test-env.yml down

# Restart
docker-compose -f docker/docker-compose.test-env.yml restart
```

## ☸️ Kubernetes Commands

```bash
cd test-environment/k8s

# Deploy
kubectl apply -f namespace.yaml
kubectl apply -f mock-web-server.yaml
kubectl apply -f mock-api-service.yaml
kubectl apply -f databases.yaml

# Check status
kubectl get pods -n nft-tracer-test

# Port forward
kubectl port-forward -n nft-tracer-test svc/mock-web-server 8080:8080

# Run traffic generator
kubectl apply -f traffic-generator-job.yaml
```

## 📝 Nội Dung Báo Cáo Đề Xuất

### 1. Giới Thiệu Môi Trường Test
- Kiến trúc test environment
- Các services được deploy
- Network topology diagram

### 2. Kịch Bản Thử Nghiệm
- **Normal Traffic**: User behavior bình thường
- **Heavy Load**: Performance testing
- **Attack Patterns**: Security testing
- **Database Traffic**: DB connections

### 3. Kết Quả Thu Được
- **Packets Captured**: Tổng số packets bắt được
- **Protocols Detected**: HTTP, TCP, UDP, ICMP
- **Traffic Patterns**: Normal vs abnormal
- **Attack Detection**: SQLi, XSS detected?

### 4. Screenshots
- Test environment architecture
- Traffic generation logs
- NFT Tracer dashboard
- Packet trace visualization
- Statistics và metrics

### 5. Phân Tích & Đánh Giá
- NFT Tracer có capture đúng traffic không?
- Performance under load?
- Attack detection accuracy?
- Recommendations

## 📸 Screenshots Cần Capture

1. **Architecture**
   ```bash
   docker ps  # Running containers
   kubectl get pods  # K8s pods
   ```

2. **Traffic Generation**
   ```bash
   # Logs của traffic generator
   docker-compose logs traffic-generator
   ```

3. **NFT Tracer Dashboard**
   - Main dashboard: `http://localhost:5000`
   - Traces page: `http://localhost:5000/traces`
   - Stats page: `http://localhost:5000/stats`

4. **Captured Data**
   - Packet table
   - Protocol distribution
   - Timeline visualization

## 🔍 Verify Everything is Working

### Check Services
```bash
# Web server
curl http://localhost:8080/health

# API service
curl http://localhost:8081/health

# NFT Tracer
curl http://localhost:5000/health
```

### Check Traffic
```bash
# Generate test traffic
python3 test-environment/traffic-generators/http-traffic-generator.py normal

# Verify NFT Tracer captured it
curl http://localhost:5000/api/traces | jq '.'
```

## 🎓 Tips cho Báo Cáo

1. **Bắt đầu đơn giản**: Test normal traffic trước
2. **Document everything**: Screenshots + logs
3. **Show metrics**: Numbers, graphs, statistics
4. **Compare scenarios**: Normal vs Attack traffic
5. **Include code snippets**: Show traffic generator code
6. **Explain results**: Why NFT Tracer detected/missed patterns

## 📁 File Structure

```
test-environment/
├── services/              # Mock applications
│   ├── mock-web-server.py
│   ├── mock-api-service.py
│   └── mock-database-client.py
├── traffic-generators/    # Traffic generators
│   ├── http-traffic-generator.py
│   └── network-traffic-generator.py
├── scenarios/            # Test scenarios
│   ├── attack-simulator.py
│   └── run-scenarios.py
├── docker/              # Docker deployment
│   ├── docker-compose.test-env.yml
│   ├── Dockerfile.mock-services
│   └── Dockerfile.traffic-generator
├── k8s/                # Kubernetes manifests
│   ├── namespace.yaml
│   ├── mock-web-server.yaml
│   └── traffic-generator-job.yaml
├── quick-start.sh      # Quick start script
├── requirements.txt    # Python dependencies
└── README.md          # Full documentation
```

## ⚠️ Important Notes

1. **Root required**: NFT Tracer cần sudo để capture packets
2. **Ports used**: 8080, 8081, 5000, 3000, 6379, 5432, 3306
3. **Attack simulator**: Chỉ dùng để test, không dùng cho mục đích xấu
4. **Resources**: Docker containers cần ~2GB RAM

## 🆘 Troubleshooting

### Services không start
```bash
# Check ports
lsof -i :8080
lsof -i :8081

# Rebuild Docker
docker-compose build --no-cache
```

### NFT Tracer không capture traffic
```bash
# Check permissions
sudo python3 backend/app.py

# Check interface
ip addr show
```

### Traffic generator errors
```bash
# Check connectivity
curl http://localhost:8080/health

# Check dependencies
pip install -r test-environment/requirements.txt
```

## 📚 Documentation

- **Full Guide**: `test-environment/README.md`
- **Environment Setup**: `ENVIRONMENTS.md`
- **Quick Start**: `QUICKSTART.md`

## Support

Nếu cần help:
1. Đọc `test-environment/README.md` (detailed docs)
2. Chạy `./quick-start.sh` (interactive menu)
3. Check logs: `docker-compose logs`

---

**Chúc bạn viết báo cáo thành công!** 📝✨
