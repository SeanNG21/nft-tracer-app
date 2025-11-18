#!/bin/bash

# NFT Tracer Environment Setup Script
# This script sets up the development environment

set -e

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

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if command -v $1 &> /dev/null; then
        print_success "$1 is installed"
        return 0
    else
        print_warning "$1 is not installed"
        return 1
    fi
}

print_info "NFT Tracer Environment Setup"
echo "============================="
echo ""

# Check prerequisites
print_info "Checking prerequisites..."

check_command "docker" || {
    print_error "Docker is required. Install from: https://docs.docker.com/get-docker/"
    exit 1
}

check_command "docker-compose" || {
    print_warning "docker-compose not found, trying docker compose plugin..."
    if docker compose version &> /dev/null; then
        print_success "docker compose plugin is available"
        alias docker-compose='docker compose'
    else
        print_error "docker-compose is required"
        exit 1
    fi
}

check_command "python3" || print_warning "Python3 not found (optional for local development)"
check_command "node" || print_warning "Node.js not found (optional for local development)"

echo ""

# Create necessary directories
print_info "Creating necessary directories..."
mkdir -p "${PROJECT_ROOT}/logs"
mkdir -p "${PROJECT_ROOT}/backend/data"
mkdir -p "${PROJECT_ROOT}/test-results"
print_success "Directories created"

echo ""

# Set up environment files
print_info "Setting up environment files..."

if [ ! -f "${PROJECT_ROOT}/.env" ]; then
    ln -s .env.development "${PROJECT_ROOT}/.env"
    print_success "Default environment (.env) linked to .env.development"
else
    print_warning ".env file already exists"
fi

# Add .env files to .gitignore if not already there
if ! grep -q "^\.env$" "${PROJECT_ROOT}/.gitignore" 2>/dev/null; then
    echo "# Environment files" >> "${PROJECT_ROOT}/.gitignore"
    echo ".env" >> "${PROJECT_ROOT}/.gitignore"
    echo ".env.local" >> "${PROJECT_ROOT}/.gitignore"
    print_success "Added .env files to .gitignore"
fi

echo ""

# Install Python dependencies (if Python is available)
if command -v python3 &> /dev/null; then
    print_info "Installing Python dependencies (optional)..."
    cd "${PROJECT_ROOT}/backend"

    if command -v pip3 &> /dev/null; then
        pip3 install -r requirements.txt 2>/dev/null || \
            print_warning "Could not install Python dependencies (BCC may need system packages)"
    fi
fi

echo ""

# Install Node dependencies (if Node is available)
if command -v npm &> /dev/null; then
    print_info "Installing Node dependencies (optional)..."
    cd "${PROJECT_ROOT}/frontend"

    if [ -f "package.json" ]; then
        npm install || print_warning "Could not install Node dependencies"
    fi
fi

echo ""

# Make scripts executable
print_info "Making scripts executable..."
chmod +x "${PROJECT_ROOT}"/scripts/*.sh
print_success "Scripts are now executable"

echo ""

# Build Docker images
print_info "Building Docker images (this may take a few minutes)..."
cd "${PROJECT_ROOT}"

docker-compose build || {
    print_error "Failed to build Docker images"
    exit 1
}

print_success "Docker images built successfully"

echo ""
echo "============================="
print_success "Setup completed successfully!"
echo ""
print_info "Next steps:"
echo "  1. Review and customize environment files (.env.development, .env.testing, .env.staging)"
echo "  2. Start development environment: ./scripts/env-manager.sh start development"
echo "  3. Run tests: ./scripts/env-manager.sh test"
echo "  4. View logs: ./scripts/env-manager.sh logs development"
echo ""
print_info "For more information, see: ENVIRONMENTS.md"
