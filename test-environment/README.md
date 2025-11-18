# NFT Tracer Test Environment

Môi trường testing hoàn chỉnh để generate network traffic cho việc test và demo ứng dụng NFT Tracer.

## 📋 Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Kiến Trúc](#kiến-trúc)
3. [Cài Đặt](#cài-đặt)
4. [Sử Dụng](#sử-dụng)
5. [Scenarios](#scenarios)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Viết Báo Cáo](#viết-báo-cáo)

## Tổng Quan

Test environment này bao gồm:

- **Mock Services**: Web server, API service, databases
- **Traffic Generators**: HTTP, TCP, UDP, DNS traffic
- **Attack Simulators**: Các attack patterns cho security testing
- **Orchestration**: Docker Compose & Kubernetes manifests
- **Test Scenarios**: Predefined scenarios cho nhiều use cases

## Kiến Trúc

```
┌─────────────────────────────────────────────────────┐
│              NFT Tracer Application                  │
│         (Bắt và phân tích network traffic)          │
└────────────────┬────────────────────────────────────┘
                 │ Captures traffic from
                 ▼
┌─────────────────────────────────────────────────────┐
│           Test Environment Network                   │
├─────────────────────────────────────────────────────┤
│  Mock Services:                                      │
│  ├─ Web Server (Flask) - Port 8080                  │
│  ├─ API Service (Flask) - Port 8081                 │
│  ├─ Redis - Port 6379                               │
│  ├─ PostgreSQL - Port 5432                          │
│  └─ MySQL - Port 3306                               │
│                                                      │
│  Traffic Generators:                                │
│  ├─ HTTP Traffic Generator                          │
│  ├─ Network Traffic Generator (TCP/UDP/ICMP)        │
│  └─ Attack Simulator (Security testing)             │
│                                                      │
│  Nginx Reverse Proxy - Port 80                      │
└─────────────────────────────────────────────────────┘
```

## Cài Đặt

### Yêu Cầu

- Docker & Docker Compose
- Python 3.9+
- (Optional) Kubernetes cluster

### Cài Đặt Dependencies

```bash
cd test-environment
pip install -r requirements.txt
```

## Sử Dụng

### 1. Chạy Local (Standalone Scripts)

#### Mock Services

```bash
# Web Server
python3 services/mock-web-server.py

# API Service
python3 services/mock-api-service.py

# Database Client
python3 services/mock-database-client.py
```

#### Traffic Generators

```bash
# HTTP Traffic
python3 traffic-generators/http-traffic-generator.py normal
python3 traffic-generators/http-traffic-generator.py burst
python3 traffic-generators/http-traffic-generator.py mixed

# Network Traffic
python3 traffic-generators/network-traffic-generator.py tcp
python3 traffic-generators/network-traffic-generator.py udp
python3 traffic-generators/network-traffic-generator.py mixed

# Attack Simulation (⚠️ Chỉ dùng để test!)
python3 scenarios/attack-simulator.py sql
python3 scenarios/attack-simulator.py xss
python3 scenarios/attack-simulator.py all
```

### 2. Chạy với Docker Compose

#### Start Test Environment

```bash
cd test-environment/docker

# Start all services
docker-compose -f docker-compose.test-env.yml up -d

# View logs
docker-compose -f docker-compose.test-env.yml logs -f

# Stop
docker-compose -f docker-compose.test-env.yml down
```

#### Start NFT Tracer để Capture Traffic

```bash
# Trong terminal khác, start NFT Tracer
cd ../../backend
sudo python3 app.py

# Hoặc dùng Docker
cd ../
docker-compose up nft-tracer-backend
```

### 3. Chạy Specific Scenarios

```bash
# Normal user behavior
docker-compose -f docker-compose.test-env.yml run \
  -e SCENARIO=normal \
  traffic-generator

# Heavy load testing
docker-compose -f docker-compose.test-env.yml run \
  -e SCENARIO=heavy \
  traffic-generator

# API testing
docker-compose -f docker-compose.test-env.yml run \
  -e SCENARIO=api \
  traffic-generator

# Continuous monitoring (1 hour)
docker-compose -f docker-compose.test-env.yml run \
  -e SCENARIO=continuous \
  -e DURATION=3600 \
  traffic-generator
```

## Scenarios

### Available Scenarios

| Scenario | Mô Tả | Duration | Use Case |
|----------|-------|----------|----------|
| `normal` | Normal user behavior | 1-2 phút | Baseline traffic |
| `heavy` | Heavy load testing | 1-2 phút | Performance testing |
| `api` | API testing (CRUD) | 2-3 phút | API monitoring |
| `mixed` | Mixed traffic patterns | 2-3 phút | General testing |
| `database` | Database connections | 1-2 phút | DB traffic analysis |
| `continuous` | Long-running traffic | Configurable | Extended testing |
| `all` | All scenarios | 10-15 phút | Comprehensive test |

### Custom Scenario

Tạo scenario riêng bằng cách edit `scenarios/run-scenarios.py`:

```python
def run_custom_scenario(self):
    """Your custom scenario"""
    logging.info("Running custom scenario...")

    # Your code here
    http_gen = HTTPTrafficGenerator(self.web_url)
    http_gen.generate_normal_traffic(duration=60)
```

## Kubernetes Deployment

### Deploy Test Environment trên K8s

```bash
cd test-environment/k8s

# Create namespace
kubectl apply -f namespace.yaml

# Deploy services
kubectl apply -f mock-web-server.yaml
kubectl apply -f mock-api-service.yaml
kubectl apply -f databases.yaml

# Deploy traffic generator (one-time job)
kubectl apply -f traffic-generator-job.yaml

# Monitor
kubectl get pods -n nft-tracer-test
kubectl logs -n nft-tracer-test -l app=traffic-generator -f
```

### Deploy NFT Tracer trên K8s

```bash
# Trong main project directory
kubectl apply -f k8s/nft-tracer-deployment.yaml

# Hoặc sử dụng Helm
helm install nft-tracer ./charts/nft-tracer
```

### Continuous Traffic Generation

```bash
# CronJob chạy traffic mỗi 30 phút
kubectl get cronjobs -n nft-tracer-test

# Trigger manual run
kubectl create job --from=cronjob/traffic-generator-cron manual-run-1 \
  -n nft-tracer-test
```

## Viết Báo Cáo

### 1. Thu Thập Data

```bash
# Start NFT Tracer với logging
cd backend
sudo python3 app.py > nft-tracer.log 2>&1 &

# Start test environment
cd ../test-environment/docker
docker-compose -f docker-compose.test-env.yml up

# Chạy scenarios
docker-compose -f docker-compose.test-env.yml run \
  -e SCENARIO=all \
  traffic-generator

# Dừng và lưu logs
docker-compose -f docker-compose.test-env.yml logs > test-logs.txt
```

### 2. Phân Tích Kết Quả

NFT Tracer sẽ capture các loại traffic:

#### HTTP Traffic
- GET/POST requests từ mock-web-server
- API calls từ mock-api-service
- Response codes, sizes, timing

#### TCP Traffic
- Connections đến databases (PostgreSQL:5432, MySQL:3306, Redis:6379)
- Connection establishment, data transfer, teardown

#### Attack Patterns (nếu chạy attack simulator)
- SQL injection attempts
- XSS attempts
- Port scanning
- Brute force login

### 3. Trích Xuất Metrics

```bash
# Xem traces trong NFT Tracer web UI
http://localhost:5000

# Export data
curl http://localhost:5000/api/traces > traces.json

# Statistics
curl http://localhost:5000/api/stats > stats.json
```

### 4. Screenshots cho Báo Cáo

Capture các màn hình sau:

1. **Test Environment Architecture**
   - `docker ps` output
   - `kubectl get pods` output

2. **Traffic Generation**
   - Logs của traffic generator
   - Real-time traffic trong terminal

3. **NFT Tracer Dashboard**
   - Packet trace visualization
   - Statistics dashboard
   - Real-time monitoring

4. **Analysis Results**
   - Captured packets table
   - Protocol distribution
   - Traffic patterns

### 5. Nội Dung Báo Cáo Đề Xuất

#### Phần 1: Môi Trường Test
- Kiến trúc test environment
- Các services được deploy
- Network topology

#### Phần 2: Scenarios Tested
- Mô tả từng scenario
- Duration và volume
- Expected vs actual results

#### Phần 3: Kết Quả
- Packets captured
- Protocol breakdown
- Performance metrics

#### Phần 4: Analysis
- Traffic patterns identified
- Attack detection (nếu có)
- NFTables rules triggered

#### Phần 5: Evaluation
- NFT Tracer effectiveness
- Performance under load
- Recommendations

## Examples

### Example 1: Basic Testing

```bash
# Terminal 1: Start services
docker-compose -f docker/docker-compose.test-env.yml up

# Terminal 2: Start NFT Tracer
cd ../backend && sudo python3 app.py

# Terminal 3: Generate traffic
python3 traffic-generators/http-traffic-generator.py mixed

# Result: View captured traffic in http://localhost:5000
```

### Example 2: Security Testing

```bash
# Start services
docker-compose -f docker/docker-compose.test-env.yml up -d

# Start NFT Tracer
cd ../backend && sudo python3 app.py

# Simulate attacks
python3 scenarios/attack-simulator.py all

# Analyze: Check if NFT Tracer detected attack patterns
```

### Example 3: Performance Testing

```bash
# Start services
docker-compose -f docker/docker-compose.test-env.yml up -d

# Start NFT Tracer
cd ../backend && sudo python3 app.py

# Heavy load
python3 traffic-generators/http-traffic-generator.py burst
python3 traffic-generators/network-traffic-generator.py flood

# Monitor: Check NFT Tracer performance under load
```

## Troubleshooting

### Services không start

```bash
# Check logs
docker-compose -f docker/docker-compose.test-env.yml logs

# Rebuild images
docker-compose -f docker/docker-compose.test-env.yml build --no-cache

# Check ports
lsof -i :8080
lsof -i :8081
```

### NFT Tracer không capture traffic

```bash
# Check permissions
sudo python3 app.py

# Check network interface
ip addr show

# Check iptables/nftables
sudo nft list ruleset
```

### Traffic Generator errors

```bash
# Check connectivity
curl http://localhost:8080/health
curl http://localhost:8081/health

# Check DNS
ping mock-web-server  # Trong Docker network
```

## Advanced Usage

### Custom Traffic Pattern

```python
# traffic-generators/custom-pattern.py
from http_traffic_generator import HTTPTrafficGenerator

gen = HTTPTrafficGenerator('http://localhost:8080')

# Your custom pattern
for i in range(100):
    gen.make_request('GET', '/api/data')
    time.sleep(0.1)
```

### Build Custom Docker Images

```bash
cd docker

# Build mock services
docker build -f Dockerfile.mock-services -t nft-tracer/mock-services:latest ..

# Build traffic generator
docker build -f Dockerfile.traffic-generator -t nft-tracer/traffic-generator:latest ..
```

## Files Structure

```
test-environment/
├── services/
│   ├── mock-web-server.py       # Flask web server
│   ├── mock-api-service.py      # REST API service
│   └── mock-database-client.py  # Database client
├── traffic-generators/
│   ├── http-traffic-generator.py     # HTTP traffic
│   └── network-traffic-generator.py  # TCP/UDP/ICMP
├── scenarios/
│   ├── attack-simulator.py      # Attack patterns
│   └── run-scenarios.py         # Scenario orchestrator
├── docker/
│   ├── docker-compose.test-env.yml  # Main compose file
│   ├── Dockerfile.mock-services     # Services image
│   ├── Dockerfile.traffic-generator # Generator image
│   └── nginx-test.conf              # Nginx config
├── k8s/
│   ├── namespace.yaml
│   ├── mock-web-server.yaml
│   ├── mock-api-service.yaml
│   ├── databases.yaml
│   └── traffic-generator-job.yaml
└── README.md
```

## Tips

1. **Start nhỏ**: Test với 1 service trước khi chạy full environment
2. **Monitor resources**: Docker containers có thể dùng nhiều CPU/memory
3. **Save logs**: Lưu logs để phân tích sau
4. **Screenshots**: Capture screenshots trong quá trình test
5. **Timing**: Một số scenarios cần vài phút để generate meaningful data

## Support

Nếu gặp vấn đề:
1. Check logs: `docker-compose logs`
2. Verify connectivity: `curl http://localhost:8080/health`
3. Check NFT Tracer: `http://localhost:5000`
4. Review documentation: `ENVIRONMENTS.md`

---

**Happy Testing!** 🚀
