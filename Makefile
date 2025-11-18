# NFT Tracer Makefile
# Convenient shortcuts for common operations

.PHONY: help setup dev test staging stop logs clean

# Default target
help:
	@echo "NFT Tracer - Available Commands"
	@echo "================================"
	@echo "  make setup      - Initial setup (run once)"
	@echo "  make dev        - Start development environment"
	@echo "  make test       - Run all tests"
	@echo "  make staging    - Start staging environment"
	@echo "  make stop       - Stop current environment"
	@echo "  make logs       - View logs (dev environment)"
	@echo "  make clean      - Clean up all environments"
	@echo "  make status     - Show environment status"
	@echo ""
	@echo "Environment-specific:"
	@echo "  make dev-logs   - Development logs"
	@echo "  make test-logs  - Testing logs"
	@echo "  make stg-logs   - Staging logs"

# Initial setup
setup:
	@echo "Running initial setup..."
	@./scripts/setup-env.sh

# Development environment
dev:
	@echo "Starting development environment..."
	@./scripts/env-manager.sh start development

dev-logs:
	@./scripts/env-manager.sh logs development

# Testing
test:
	@echo "Running tests..."
	@./scripts/env-manager.sh test

test-unit:
	@echo "Running unit tests..."
	@cd backend && pytest tests/ -v --ignore=tests/test_integration.py

test-integration:
	@echo "Running integration tests..."
	@cd backend && pytest tests/test_integration.py -v

test-frontend:
	@echo "Running frontend tests..."
	@cd frontend && npm test -- --watchAll=false

test-coverage:
	@echo "Running tests with coverage..."
	@./scripts/run-tests.sh

test-logs:
	@./scripts/env-manager.sh logs testing

# Staging environment
staging:
	@echo "Starting staging environment..."
	@./scripts/env-manager.sh start staging

stg-logs:
	@./scripts/env-manager.sh logs staging

# Stop environments
stop:
	@echo "Stopping current environment..."
	@docker-compose down

stop-all:
	@echo "Stopping all environments..."
	@docker-compose down
	@docker-compose -f docker-compose.testing.yml down
	@docker-compose -f docker-compose.staging.yml down

# Logs
logs:
	@./scripts/env-manager.sh logs development

# Status
status:
	@./scripts/env-manager.sh status

# Clean up
clean:
	@echo "Cleaning up..."
	@./scripts/env-manager.sh cleanup
	@rm -rf logs/*
	@rm -rf test-results/*
	@rm -f backend/nft_tracer_test.db

clean-all: clean
	@echo "Deep cleaning..."
	@rm -rf backend/__pycache__
	@rm -rf backend/**/__pycache__
	@rm -rf frontend/node_modules
	@rm -rf frontend/build
	@docker system prune -f

# Docker operations
docker-build:
	@echo "Building Docker images..."
	@docker-compose build

docker-rebuild:
	@echo "Rebuilding Docker images from scratch..."
	@docker-compose build --no-cache

docker-ps:
	@docker ps --filter "name=nft-tracer"

# Quick restart
restart-dev:
	@./scripts/env-manager.sh restart development

restart-staging:
	@./scripts/env-manager.sh restart staging

# Install dependencies
install-backend:
	@echo "Installing backend dependencies..."
	@cd backend && pip install -r requirements.txt

install-frontend:
	@echo "Installing frontend dependencies..."
	@cd frontend && npm install

install-all: install-backend install-frontend

# Run locally (without Docker)
run-backend:
	@echo "Running backend locally..."
	@cd backend && python3 app.py

run-frontend:
	@echo "Running frontend locally..."
	@cd frontend && npm start
