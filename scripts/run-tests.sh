#!/bin/bash

# NFT Tracer Test Runner
# This script runs all tests for the application

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Load test environment
export $(cat "${PROJECT_ROOT}/.env.testing" | grep -v '^#' | xargs)

cd "$PROJECT_ROOT"

# Create test results directory
mkdir -p test-results

print_info "Running NFT Tracer Test Suite"
echo "================================"
echo ""

# Run backend tests
print_info "1. Running Backend Tests..."
echo ""

cd "${PROJECT_ROOT}/backend"

if command -v pytest &> /dev/null; then
    pytest tests/ -v --cov=. --cov-report=html --cov-report=term \
        --junitxml=../test-results/backend-results.xml || {
        print_error "Backend tests failed"
        exit 1
    }
    print_success "Backend tests passed"
else
    print_error "pytest not found. Install with: pip install pytest pytest-cov"
    exit 1
fi

echo ""

# Run frontend tests
print_info "2. Running Frontend Tests..."
echo ""

cd "${PROJECT_ROOT}/frontend"

if [ -f "package.json" ]; then
    CI=true npm test -- --watchAll=false --coverage \
        --testResultsProcessor=jest-junit || {
        print_error "Frontend tests failed"
        exit 1
    }
    print_success "Frontend tests passed"
else
    print_warning "No frontend package.json found, skipping frontend tests"
fi

echo ""

# Run integration tests (if available)
print_info "3. Running Integration Tests..."
echo ""

if [ -f "${PROJECT_ROOT}/backend/tests/test_integration.py" ]; then
    cd "${PROJECT_ROOT}/backend"
    pytest tests/test_integration.py -v -s || {
        print_error "Integration tests failed"
        exit 1
    }
    print_success "Integration tests passed"
else
    print_warning "No integration tests found, skipping"
fi

echo ""
echo "================================"
print_success "All tests completed successfully!"
echo ""

# Display coverage summary
print_info "Coverage reports generated:"
echo "  Backend:  file://${PROJECT_ROOT}/backend/htmlcov/index.html"
echo "  Frontend: file://${PROJECT_ROOT}/frontend/coverage/lcov-report/index.html"
