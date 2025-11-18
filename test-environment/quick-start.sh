#!/bin/bash

# Quick Start Script for NFT Tracer Test Environment

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

show_banner() {
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   NFT Tracer Test Environment Quick Start    ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
}

show_menu() {
    echo "Chọn deployment method:"
    echo ""
    echo "  1) Local (Python scripts)"
    echo "  2) Docker Compose"
    echo "  3) Kubernetes"
    echo "  4) Exit"
    echo ""
}

start_local() {
    print_info "Starting local test environment..."
    echo ""

    print_info "Starting Mock Web Server (port 8080)..."
    python3 services/mock-web-server.py &
    WEB_PID=$!

    sleep 2

    print_info "Starting Mock API Service (port 8081)..."
    python3 services/mock-api-service.py &
    API_PID=$!

    sleep 2

    print_success "Services started!"
    echo ""
    print_info "Web Server:  http://localhost:8080"
    print_info "API Service: http://localhost:8081"
    echo ""

    echo "PIDs: Web=$WEB_PID, API=$API_PID"
    echo ""

    read -p "Generate traffic? (y/n): " generate
    if [ "$generate" = "y" ]; then
        print_info "Generating mixed traffic for 60 seconds..."
        python3 traffic-generators/http-traffic-generator.py mixed http://localhost:8080 &
        TRAFFIC_PID=$!

        sleep 60

        kill $TRAFFIC_PID 2>/dev/null || true
    fi

    print_warning "Press Ctrl+C to stop services"
    wait
}

start_docker() {
    print_info "Starting Docker Compose environment..."
    echo ""

    cd docker

    if [ ! -f "docker-compose.test-env.yml" ]; then
        print_error "docker-compose.test-env.yml not found!"
        exit 1
    fi

    print_info "Building images..."
    docker-compose -f docker-compose.test-env.yml build

    print_info "Starting services..."
    docker-compose -f docker-compose.test-env.yml up -d

    print_success "Services started!"
    echo ""

    docker-compose -f docker-compose.test-env.yml ps

    echo ""
    print_info "Web Server:  http://localhost:8080"
    print_info "API Service: http://localhost:8081"
    print_info "Nginx Proxy: http://localhost:80"
    echo ""

    print_info "View logs: docker-compose -f docker/docker-compose.test-env.yml logs -f"
    print_info "Stop:      docker-compose -f docker/docker-compose.test-env.yml down"
}

start_kubernetes() {
    print_info "Deploying to Kubernetes..."
    echo ""

    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl not found. Please install kubectl first."
        exit 1
    fi

    cd k8s

    print_info "Creating namespace..."
    kubectl apply -f namespace.yaml

    print_info "Deploying mock services..."
    kubectl apply -f mock-web-server.yaml
    kubectl apply -f mock-api-service.yaml
    kubectl apply -f databases.yaml

    print_info "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=mock-web-server -n nft-tracer-test --timeout=60s

    print_success "Services deployed!"
    echo ""

    kubectl get pods -n nft-tracer-test

    echo ""
    print_info "Deploy traffic generator:"
    echo "  kubectl apply -f traffic-generator-job.yaml"
    echo ""
    print_info "Port forward to access services:"
    echo "  kubectl port-forward -n nft-tracer-test svc/mock-web-server 8080:8080"
}

generate_traffic() {
    print_info "Select traffic pattern:"
    echo ""
    echo "  1) Normal traffic"
    echo "  2) Burst traffic"
    echo "  3) Mixed traffic"
    echo "  4) All scenarios"
    echo ""

    read -p "Select (1-4): " pattern

    case $pattern in
        1)
            python3 traffic-generators/http-traffic-generator.py normal
            ;;
        2)
            python3 traffic-generators/http-traffic-generator.py burst
            ;;
        3)
            python3 traffic-generators/http-traffic-generator.py mixed
            ;;
        4)
            python3 traffic-generators/http-traffic-generator.py all
            ;;
        *)
            print_error "Invalid selection"
            ;;
    esac
}

main() {
    show_banner

    # Check if we're in the right directory
    if [ ! -d "services" ] || [ ! -d "traffic-generators" ]; then
        print_error "Please run this script from the test-environment directory"
        exit 1
    fi

    show_menu
    read -p "Select (1-4): " choice

    case $choice in
        1)
            start_local
            ;;
        2)
            start_docker
            ;;
        3)
            start_kubernetes
            ;;
        4)
            print_info "Goodbye!"
            exit 0
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac
}

# Cleanup on exit
cleanup() {
    print_warning "Cleaning up..."
    pkill -P $$ 2>/dev/null || true
}

trap cleanup EXIT INT TERM

main "$@"
