# NFT Tracer - Hướng Dẫn Quản Lý Môi Trường

Tài liệu này hướng dẫn cách thiết lập và quản lý các môi trường khác nhau (development, testing, staging) cho ứng dụng NFT Tracer.

## Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Cài Đặt Ban Đầu](#cài-đặt-ban-đầu)
3. [Các Môi Trường](#các-môi-trường)
4. [Sử Dụng Scripts](#sử-dụng-scripts)
5. [Docker Containers](#docker-containers)
6. [Chạy Tests](#chạy-tests)
7. [Xử Lý Sự Cố](#xử-lý-sự-cố)

## Tổng Quan

Dự án NFT Tracer hỗ trợ 3 môi trường chính:

- **Development** - Môi trường phát triển với debug enabled, hot reload
- **Testing** - Môi trường chạy automated tests, mocking eBPF
- **Staging** - Môi trường giống production để kiểm tra cuối cùng

## Cài Đặt Ban Đầu

### Yêu Cầu Hệ Thống

- Docker & Docker Compose
- Git
- (Optional) Python 3.9+
- (Optional) Node.js 18+

### Cài Đặt

```bash
# Clone repository
git clone <your-repo-url>
cd nft-tracer-app

# Chạy script setup
./scripts/setup-env.sh
```

Script này sẽ:
- Kiểm tra các dependencies
- Tạo thư mục cần thiết
- Thiết lập file .env
- Build Docker images
- Chuẩn bị môi trường phát triển

## Các Môi Trường

### 1. Development Environment

Môi trường phát triển với tính năng debug đầy đủ.

**Cấu hình:** `.env.development`

```bash
# Khởi động
./scripts/env-manager.sh start development

# Hoặc với Docker Compose trực tiếp
docker-compose up
```

**Đặc điểm:**
- Flask debug mode enabled
- React hot reload
- Verbose logging (DEBUG level)
- Database: `nft_tracer_dev.db`
- Ports: Backend 5000, Frontend 3000

**Access:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000
- API Docs: http://localhost:5000/api/docs

### 2. Testing Environment

Môi trường để chạy automated tests.

**Cấu hình:** `.env.testing`

```bash
# Chạy tất cả tests
./scripts/env-manager.sh test

# Hoặc chạy riêng backend/frontend tests
cd backend && pytest tests/
cd frontend && npm test
```

**Đặc điểm:**
- eBPF disabled (mocked)
- In-memory database hoặc test database
- CI mode enabled
- Ports: Backend 5001, Frontend 3001

**Test Coverage:**
- Backend: `backend/htmlcov/index.html`
- Frontend: `frontend/coverage/lcov-report/index.html`

### 3. Staging Environment

Môi trường giống production để kiểm tra cuối cùng.

**Cấu hình:** `.env.staging`

```bash
# Khởi động staging
./scripts/env-manager.sh start staging

# Hoặc với Docker Compose
docker-compose -f docker-compose.staging.yml up -d
```

**Đặc điểm:**
- Production mode (optimized builds)
- eBPF enabled (requires privileges)
- Nginx serving frontend
- Persistent volumes
- Health checks enabled
- Database: `nft_tracer_staging.db`

**Access:**
- Frontend: http://localhost (port 80)
- Backend API: http://localhost:5000
- Metrics: http://localhost:9090

## Sử Dụng Scripts

### Environment Manager (`scripts/env-manager.sh`)

Script chính để quản lý các môi trường.

```bash
# Hiển thị help
./scripts/env-manager.sh help

# Khởi động môi trường
./scripts/env-manager.sh start <development|testing|staging>

# Dừng môi trường
./scripts/env-manager.sh stop <development|testing|staging>

# Restart môi trường
./scripts/env-manager.sh restart <development|testing|staging>

# Xem trạng thái
./scripts/env-manager.sh status

# Xem logs
./scripts/env-manager.sh logs <environment> [service]

# Dọn dẹp tất cả
./scripts/env-manager.sh cleanup
```

### Test Runner (`scripts/run-tests.sh`)

Chạy tất cả tests (backend + frontend + integration).

```bash
./scripts/run-tests.sh
```

### Setup Script (`scripts/setup-env.sh`)

Thiết lập môi trường lần đầu.

```bash
./scripts/setup-env.sh
```

## Docker Containers

### Services

Mỗi môi trường có các services sau:

1. **backend** - Flask application với eBPF tracing
2. **frontend** - React application
3. **redis** - Caching và session management

### Commands Hữu Ích

```bash
# Xem containers đang chạy
docker ps --filter "name=nft-tracer"

# Xem logs
docker-compose logs -f [service]

# Shell vào container
docker-compose exec backend bash
docker-compose exec frontend sh

# Rebuild images
docker-compose build --no-cache

# Xóa volumes
docker-compose down -v

# Xem resource usage
docker stats --filter "name=nft-tracer"
```

## Chạy Tests

### Backend Tests

```bash
# Tất cả tests
cd backend
pytest tests/ -v

# Với coverage
pytest tests/ --cov=. --cov-report=html

# Test cụ thể
pytest tests/test_config.py -v

# Test với markers
pytest -m "not slow" tests/
```

### Frontend Tests

```bash
cd frontend

# Interactive mode
npm test

# CI mode (single run)
npm run test:ci

# Với coverage
npm run test:coverage
```

### Integration Tests

```bash
# Chạy full test suite
./scripts/run-tests.sh

# Hoặc với Docker
./scripts/env-manager.sh test
```

## File Cấu Hình

### Environment Variables

Các file `.env.*` chứa cấu hình cho từng môi trường:

- `.env.example` - Template với tất cả các biến có thể
- `.env.development` - Cấu hình development
- `.env.testing` - Cấu hình testing
- `.env.staging` - Cấu hình staging
- `.env` - Symlink đến environment hiện tại

### Python Configuration

Module `backend/config.py` load và validate environment variables:

```python
from config import get_config

# Lấy config dựa trên FLASK_ENV
config = get_config()

# Hoặc chỉ định cụ thể
config = get_config('testing')

# Sử dụng config
print(config.BACKEND_PORT)
print(config.is_development())
```

## Workflow Phát Triển

### Local Development

```bash
# 1. Khởi động development environment
./scripts/env-manager.sh start development

# 2. Theo dõi logs
./scripts/env-manager.sh logs development

# 3. Code changes tự động reload
# Backend: Flask auto-reload
# Frontend: React hot module replacement

# 4. Chạy tests khi cần
./scripts/run-tests.sh

# 5. Dừng khi xong
./scripts/env-manager.sh stop development
```

### Testing Workflow

```bash
# 1. Chạy tests trước khi commit
./scripts/env-manager.sh test

# 2. Kiểm tra coverage
open backend/htmlcov/index.html
open frontend/coverage/lcov-report/index.html

# 3. Fix các tests fail

# 4. Commit khi tests pass
git add .
git commit -m "feat: your changes"
```

### Staging Deployment

```bash
# 1. Build staging environment
./scripts/env-manager.sh start staging

# 2. Verify health checks
curl http://localhost:5000/health

# 3. Run smoke tests
./scripts/run-tests.sh

# 4. Monitor logs
./scripts/env-manager.sh logs staging

# 5. Promote to production if stable
```

## Xử Lý Sự Cố

### Ports Already in Use

```bash
# Tìm process sử dụng port
lsof -i :5000
lsof -i :3000

# Kill process
kill -9 <PID>

# Hoặc đổi port trong .env file
```

### Docker Build Failures

```bash
# Clean build cache
docker system prune -a

# Rebuild from scratch
docker-compose build --no-cache

# Check disk space
docker system df
```

### eBPF Permission Errors

```bash
# Staging/Production cần privileged mode
# Đảm bảo trong docker-compose.yml có:
privileged: true

# Hoặc chạy với sudo
sudo docker-compose up
```

### Database Issues

```bash
# Reset database
rm backend/nft_tracer_*.db

# Hoặc với Docker volumes
docker-compose down -v
```

### Frontend Build Errors

```bash
# Clear node_modules và reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install

# Clear React cache
rm -rf node_modules/.cache
```

## Best Practices

1. **Không commit file `.env`** - Chỉ commit `.env.example`
2. **Test trước khi commit** - Chạy `./scripts/run-tests.sh`
3. **Review logs thường xuyên** - Phát hiện issues sớm
4. **Backup database** - Trước khi migration hoặc major changes
5. **Document changes** - Update ENVIRONMENTS.md khi thêm config mới
6. **Use staging** - Test thoroughly trước khi production
7. **Monitor resources** - Check Docker stats định kỳ

## Scripts Reference

| Script | Mô Tả |
|--------|-------|
| `setup-env.sh` | Thiết lập ban đầu |
| `env-manager.sh` | Quản lý các môi trường |
| `run-tests.sh` | Chạy test suite |

## Environment Variables Reference

| Variable | Development | Testing | Staging | Mô Tả |
|----------|------------|---------|---------|-------|
| `FLASK_ENV` | development | testing | production | Môi trường Flask |
| `FLASK_DEBUG` | True | False | False | Debug mode |
| `BACKEND_PORT` | 5000 | 5001 | 5000 | Backend port |
| `FRONTEND_PORT` | 3000 | 3001 | 80 | Frontend port |
| `ENABLE_EBPF` | True | False | True | Enable eBPF tracing |
| `LOG_LEVEL` | DEBUG | WARNING | INFO | Log verbosity |

## Support

Nếu gặp vấn đề:

1. Kiểm tra logs: `./scripts/env-manager.sh logs <env>`
2. Xem Docker status: `docker ps -a`
3. Review configuration: `cat .env.<environment>`
4. Check documentation: Đọc lại ENVIRONMENTS.md
5. Clean và rebuild: `./scripts/env-manager.sh cleanup && ./scripts/setup-env.sh`

## Contribution

Khi thêm features mới:

1. Update environment variables trong `.env.example`
2. Update `backend/config.py` nếu cần
3. Thêm tests cho configuration mới
4. Update documentation này
5. Test trên tất cả 3 môi trường

---

**Last Updated:** 2025-01-18
**Version:** 1.0.0
