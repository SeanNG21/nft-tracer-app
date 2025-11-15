#!/bin/bash
# Backend Restart Script with Verification
# This script ensures clean restart with latest code

echo "================================================================================"
echo "NFT Tracer Backend Restart Script"
echo "================================================================================"
echo ""

# Step 1: Check git status
echo "[1/6] Checking git status..."
cd /home/user/nft-tracer-app
git status
echo ""

# Step 2: Show recent commits
echo "[2/6] Recent commits:"
git log --oneline -5
echo ""

# Step 3: Find and kill existing backend processes
echo "[3/6] Checking for running backend processes..."
BACKEND_PIDS=$(ps aux | grep '[p]ython3.*app.py' | awk '{print $2}')

if [ -z "$BACKEND_PIDS" ]; then
    echo "    ✓ No backend processes running"
else
    echo "    Found running backend processes:"
    ps aux | grep '[p]ython3.*app.py'
    echo ""
    echo "    Killing processes: $BACKEND_PIDS"
    sudo kill -9 $BACKEND_PIDS
    sleep 2

    # Verify killed
    STILL_RUNNING=$(ps aux | grep '[p]ython3.*app.py' | awk '{print $2}')
    if [ -z "$STILL_RUNNING" ]; then
        echo "    ✓ All backend processes stopped"
    else
        echo "    ⚠ Some processes still running: $STILL_RUNNING"
        echo "    Please manually kill them with: sudo kill -9 $STILL_RUNNING"
        exit 1
    fi
fi
echo ""

# Step 4: Verify parser file exists
echo "[4/6] Verifying NFT parser files..."
if [ -f "backend/nft_ruleset_parser.py" ]; then
    echo "    ✓ nft_ruleset_parser.py exists"
    # Check if it has the debug parameter
    if grep -q "def __init__(self, debug=False):" backend/nft_ruleset_parser.py; then
        echo "    ✓ Parser has debug parameter"
    else
        echo "    ⚠ Parser missing debug parameter - may be old version"
    fi
else
    echo "    ✗ nft_ruleset_parser.py NOT FOUND!"
    exit 1
fi

if [ -f "backend/test_nft_parser.py" ]; then
    echo "    ✓ test_nft_parser.py exists"
else
    echo "    ⚠ test_nft_parser.py not found"
fi
echo ""

# Step 5: Verify app.py has parser integration
echo "[5/6] Verifying app.py has NFT parser integration..."
if grep -q "from nft_ruleset_parser import get_ruleset_parser" backend/app.py; then
    echo "    ✓ app.py imports NFT parser"
else
    echo "    ✗ app.py does NOT import NFT parser!"
    exit 1
fi

if grep -q "Preloading NFT ruleset parser" backend/app.py; then
    echo "    ✓ app.py has parser preload code"
else
    echo "    ⚠ app.py missing parser preload code"
fi
echo ""

# Step 6: Start backend
echo "[6/6] Starting backend..."
echo "================================================================================"
echo "Backend Startup Logs (watch for NFT Parser messages):"
echo "================================================================================"
echo ""

cd backend
sudo python3 app.py

# Note: This script will stay running until you stop the backend with Ctrl+C
