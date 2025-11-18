#!/bin/bash

# NFT Tracer Environment Manager
# This script helps manage different environments (development, testing, staging)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Function to print colored output
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

# Function to load environment
load_env() {
    local env_name=$1
    local env_file="${PROJECT_ROOT}/.env.${env_name}"

    if [ ! -f "$env_file" ]; then
        print_error "Environment file not found: $env_file"
        exit 1
    fi

    print_info "Loading environment: $env_name"

    # Create/update .env symlink
    ln -sf ".env.${env_name}" "${PROJECT_ROOT}/.env"

    # Export variables
    export $(cat "$env_file" | grep -v '^#' | xargs)

    print_success "Environment '$env_name' loaded successfully"
}

# Function to start environment
start_env() {
    local env_name=$1

    print_info "Starting $env_name environment..."

    cd "$PROJECT_ROOT"

    case $env_name in
        development)
            load_env "development"
            export BUILD_TARGET=development
            export ENV=dev
            docker-compose up -d
            ;;
        testing)
            load_env "testing"
            docker-compose -f docker-compose.testing.yml up --build --abort-on-container-exit
            ;;
        staging)
            load_env "staging"
            docker-compose -f docker-compose.staging.yml up -d
            ;;
        *)
            print_error "Unknown environment: $env_name"
            print_info "Valid environments: development, testing, staging"
            exit 1
            ;;
    esac

    print_success "$env_name environment started"
}

# Function to stop environment
stop_env() {
    local env_name=$1

    print_info "Stopping $env_name environment..."

    cd "$PROJECT_ROOT"

    case $env_name in
        development)
            docker-compose down
            ;;
        testing)
            docker-compose -f docker-compose.testing.yml down
            ;;
        staging)
            docker-compose -f docker-compose.staging.yml down
            ;;
        *)
            print_error "Unknown environment: $env_name"
            exit 1
            ;;
    esac

    print_success "$env_name environment stopped"
}

# Function to show environment status
show_status() {
    print_info "Environment Status:"
    echo ""

    # Check current environment
    if [ -L "${PROJECT_ROOT}/.env" ]; then
        current_env=$(readlink "${PROJECT_ROOT}/.env" | sed 's/.env.//')
        print_success "Current environment: $current_env"
    else
        print_warning "No environment loaded"
    fi

    echo ""
    print_info "Running containers:"
    docker ps --filter "name=nft-tracer" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

# Function to run tests
run_tests() {
    print_info "Running tests..."

    cd "$PROJECT_ROOT"
    load_env "testing"

    # Run backend tests
    print_info "Running backend tests..."
    docker-compose -f docker-compose.testing.yml run --rm backend-test

    # Run frontend tests
    print_info "Running frontend tests..."
    docker-compose -f docker-compose.testing.yml run --rm frontend-test

    # Cleanup
    docker-compose -f docker-compose.testing.yml down

    print_success "All tests completed"
}

# Function to view logs
view_logs() {
    local env_name=$1
    local service=$2

    cd "$PROJECT_ROOT"

    case $env_name in
        development)
            if [ -z "$service" ]; then
                docker-compose logs -f
            else
                docker-compose logs -f "$service"
            fi
            ;;
        testing)
            docker-compose -f docker-compose.testing.yml logs -f
            ;;
        staging)
            if [ -z "$service" ]; then
                docker-compose -f docker-compose.staging.yml logs -f
            else
                docker-compose -f docker-compose.staging.yml logs -f "$service"
            fi
            ;;
        *)
            print_error "Unknown environment: $env_name"
            exit 1
            ;;
    esac
}

# Function to clean up
cleanup() {
    print_warning "Cleaning up all environments..."

    cd "$PROJECT_ROOT"

    # Stop all containers
    docker-compose down -v 2>/dev/null || true
    docker-compose -f docker-compose.testing.yml down -v 2>/dev/null || true
    docker-compose -f docker-compose.staging.yml down -v 2>/dev/null || true

    # Remove test databases
    rm -f "${PROJECT_ROOT}/backend/nft_tracer_test.db"

    print_success "Cleanup completed"
}

# Function to show help
show_help() {
    echo "NFT Tracer Environment Manager"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start <env>        Start environment (development|testing|staging)"
    echo "  stop <env>         Stop environment"
    echo "  restart <env>      Restart environment"
    echo "  status             Show current environment status"
    echo "  test               Run all tests"
    echo "  logs <env> [svc]   View logs (optional: specify service)"
    echo "  cleanup            Stop all environments and clean up"
    echo "  help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start development"
    echo "  $0 stop staging"
    echo "  $0 test"
    echo "  $0 logs development backend"
    echo ""
}

# Main script logic
main() {
    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi

    command=$1
    shift

    case $command in
        start)
            if [ -z "$1" ]; then
                print_error "Environment name required"
                show_help
                exit 1
            fi
            start_env "$1"
            ;;
        stop)
            if [ -z "$1" ]; then
                print_error "Environment name required"
                show_help
                exit 1
            fi
            stop_env "$1"
            ;;
        restart)
            if [ -z "$1" ]; then
                print_error "Environment name required"
                show_help
                exit 1
            fi
            stop_env "$1"
            sleep 2
            start_env "$1"
            ;;
        status)
            show_status
            ;;
        test)
            run_tests
            ;;
        logs)
            if [ -z "$1" ]; then
                print_error "Environment name required"
                show_help
                exit 1
            fi
            view_logs "$1" "$2"
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
