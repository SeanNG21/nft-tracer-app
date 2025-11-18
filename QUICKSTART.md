# NFT Tracer - Quick Start Guide

Hướng dẫn nhanh để bắt đầu sử dụng hệ thống môi trường testing và staging.

## Cài Đặt Nhanh (5 phút)

```bash
# 1. Setup môi trường (chỉ chạy 1 lần)
./scripts/setup-env.sh

# 2. Khởi động development
make dev
# Hoặc: ./scripts/env-manager.sh start development

# 3. Truy cập ứng dụng
# Frontend: http://localhost:3000
# Backend:  http://localhost:5000
```

## Các Lệnh Thường Dùng

### Sử dụng Makefile (Khuyến nghị)

```bash
make help        # Xem tất cả lệnh
make dev         # Khởi động development
make test        # Chạy tests
make staging     # Khởi động staging
make logs        # Xem logs
make stop        # Dừng environment
make clean       # Dọn dẹp
```

### Sử dụng Scripts Trực Tiếp

```bash
# Quản lý môi trường
./scripts/env-manager.sh start development
./scripts/env-manager.sh stop development
./scripts/env-manager.sh status
./scripts/env-manager.sh logs development

# Chạy tests
./scripts/run-tests.sh
```

## 3 Môi Trường Chính

### 1. Development (Port 3000/5000)
```bash
make dev
```
- Debug enabled
- Hot reload
- Verbose logging

### 2. Testing (Port 3001/5001)
```bash
make test
```
- Automated tests
- eBPF mocked
- Coverage reports

### 3. Staging (Port 80/5000)
```bash
make staging
```
- Production mode
- Full eBPF enabled
- Optimized builds

## Workflow Cơ Bản

### Phát Triển Feature Mới

```bash
# 1. Start dev environment
make dev

# 2. Make your changes
# Files auto-reload

# 3. Run tests
make test

# 4. Stop when done
make stop
```

### Kiểm Tra Trước Commit

```bash
# Chạy full test suite
make test-coverage

# Xem coverage reports
open backend/htmlcov/index.html
open frontend/coverage/lcov-report/index.html
```

### Deploy lên Staging

```bash
# 1. Start staging
make staging

# 2. Verify health
curl http://localhost:5000/health

# 3. Monitor logs
make stg-logs

# 4. Stop after verification
make stop
```

## Cấu Trúc Files

```
nft-tracer-app/
├── .env.example          # Template
├── .env.development      # Dev config
├── .env.testing         # Test config
├── .env.staging         # Staging config
├── .env                 # Symlink -> current env
├── Makefile             # Quick commands
├── docker-compose.yml   # Main compose file
├── docker-compose.testing.yml
├── docker-compose.staging.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── scripts/
│   ├── setup-env.sh     # Initial setup
│   ├── env-manager.sh   # Manage environments
│   └── run-tests.sh     # Run tests
├── backend/
│   ├── config.py        # Config loader
│   └── tests/
│       ├── conftest.py  # Test fixtures
│       └── test_*.py    # Test files
└── ENVIRONMENTS.md      # Full documentation
```

## Xem Logs

```bash
# All services
make logs

# Specific service
make dev-logs     # Development
make test-logs    # Testing
make stg-logs     # Staging

# Docker compose directly
docker-compose logs -f backend
docker-compose logs -f frontend
```

## Troubleshooting

### Port đã được sử dụng
```bash
# Tìm và kill process
lsof -i :5000
kill -9 <PID>
```

### Docker issues
```bash
# Clean và rebuild
make clean
make docker-rebuild
make setup
```

### Permission errors
```bash
# Ensure scripts are executable
chmod +x scripts/*.sh
```

### Tests fail
```bash
# Check logs
make test-logs

# Run specific tests
cd backend && pytest tests/test_config.py -v
cd frontend && npm test
```

## Environment Variables

Các biến quan trọng trong `.env.*` files:

```bash
# Backend
BACKEND_PORT=5000
DATABASE_PATH=./backend/nft_tracer.db
ENABLE_EBPF=True

# Frontend
FRONTEND_PORT=3000
REACT_APP_API_URL=http://localhost:5000

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/nft-tracer.log
```

## Next Steps

1. Đọc [ENVIRONMENTS.md](./ENVIRONMENTS.md) để hiểu chi tiết
2. Xem [SETUP_AND_RUN.md](./SETUP_AND_RUN.md) cho hướng dẫn cài đặt
3. Tùy chỉnh `.env.*` files theo nhu cầu
4. Thêm tests cho features mới

## Cheat Sheet

| Task | Command |
|------|---------|
| Setup lần đầu | `./scripts/setup-env.sh` |
| Start dev | `make dev` |
| Run tests | `make test` |
| Start staging | `make staging` |
| View logs | `make logs` |
| Stop all | `make stop` |
| Clean up | `make clean` |
| Status | `make status` |
| Help | `make help` |

## Support

Gặp vấn đề? Thử các bước sau:

1. `make status` - Kiểm tra trạng thái
2. `make logs` - Xem logs
3. `make clean && make setup` - Reset toàn bộ
4. Đọc [ENVIRONMENTS.md](./ENVIRONMENTS.md)

---

**Tip:** Sử dụng `make help` để xem tất cả lệnh có sẵn!
