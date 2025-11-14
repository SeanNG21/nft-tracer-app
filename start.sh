#!/bin/bash

# NFT Tracer Startup Script
# This script starts both backend and frontend in development mode

set -e

echo "======================================"
echo "  NFT Packet Tracer - Startup Script"
echo "======================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  WARNING: Backend requires root privileges to load BPF programs"
    echo "Please run with: sudo ./start.sh"
    exit 1
fi

# Check BCC installation
echo "Checking BCC installation..."
if ! python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "❌ ERROR: BCC not found!"
    echo "Install with: sudo apt-get install bpfcc-tools python3-bpfcc"
    exit 1
fi
echo "✓ BCC installed"

# Check kernel headers
echo "Checking kernel headers..."
if [ ! -d "/usr/src/linux-headers-$(uname -r)" ]; then
    echo "⚠️  WARNING: Kernel headers not found"
    echo "Install with: sudo apt-get install linux-headers-$(uname -r)"
fi

# Check backend dependencies
echo "Checking backend dependencies..."
cd backend
if [ ! -f "requirements.txt" ]; then
    echo "❌ ERROR: requirements.txt not found"
    exit 1
fi

pip3 list | grep -q flask || {
    echo "Installing backend dependencies..."
    pip3 install -r requirements.txt
}
echo "✓ Backend dependencies OK"

cd ..

# Check frontend dependencies
echo "Checking frontend dependencies..."
cd frontend
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi
echo "✓ Frontend dependencies OK"

cd ..

echo ""
echo "======================================"
echo "  Starting Application"
echo "======================================"
echo ""

# Kill existing processes
pkill -f "python3 backend/app.py" 2>/dev/null || true
pkill -f "react-scripts start" 2>/dev/null || true

# Start backend
echo "Starting backend on http://localhost:5000..."
cd backend
python3 app.py &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 3

# Start frontend
echo "Starting frontend on http://localhost:3000..."
cd frontend
npm start &
FRONTEND_PID=$!
cd ..

echo ""
echo "======================================"
echo "  Application Started!"
echo "======================================"
echo ""
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo ""
echo "Access the application at:"
echo "  👉 http://localhost:3000"
echo ""
echo "API endpoints:"
echo "  👉 http://localhost:5000/api/health"
echo ""
echo "Press Ctrl+C to stop both services"
echo ""

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM

wait
