#!/bin/bash
# Diagnostic Script - Run this and share the output
# This helps identify why backend isn't showing parser logs

echo "================================================================================"
echo "NFT TRACER DIAGNOSTIC REPORT"
echo "================================================================================"
echo "Generated: $(date)"
echo ""

cd /home/user/nft-tracer-app

echo "## 1. GIT STATUS"
echo "--------------------------------------------------------------------------------"
echo "Current branch:"
git branch --show-current
echo ""
echo "Latest commit:"
git log --oneline -1
echo ""
echo "Working directory status:"
git status --short
echo ""

echo "## 2. BACKEND FILES"
echo "--------------------------------------------------------------------------------"
if [ -f "backend/nft_ruleset_parser.py" ]; then
    echo "✓ nft_ruleset_parser.py exists"
    ls -lh backend/nft_ruleset_parser.py
else
    echo "✗ nft_ruleset_parser.py MISSING!"
fi
echo ""

if [ -f "backend/app.py" ]; then
    echo "✓ app.py exists"
    ls -lh backend/app.py
else
    echo "✗ app.py MISSING!"
fi
echo ""

echo "## 3. PARSER IMPORT IN APP.PY"
echo "--------------------------------------------------------------------------------"
grep -n "from nft_ruleset_parser import" backend/app.py
echo ""

echo "## 4. PARSER PRELOAD CODE IN APP.PY"
echo "--------------------------------------------------------------------------------"
echo "Looking for preload code around line 1564..."
sed -n '1560,1575p' backend/app.py | cat -n
echo ""

echo "## 5. RUNNING BACKEND PROCESSES"
echo "--------------------------------------------------------------------------------"
BACKEND_PROCS=$(ps aux | grep '[p]ython.*app.py')
if [ -z "$BACKEND_PROCS" ]; then
    echo "No backend processes running"
else
    echo "Found backend processes:"
    echo "$BACKEND_PROCS"
fi
echo ""

echo "## 6. PYTHON ENVIRONMENT"
echo "--------------------------------------------------------------------------------"
echo "Python location: $(which python3)"
echo "Python version: $(python3 --version)"
echo ""

echo "## 7. NFTABLES STATUS"
echo "--------------------------------------------------------------------------------"
if command -v nft &> /dev/null; then
    echo "✓ nft command found: $(which nft)"
    echo ""
    echo "Current ruleset summary:"
    sudo nft list ruleset | head -20
    echo "..."
    echo ""
    echo "Rule count by handle:"
    sudo nft -a list ruleset | grep "# handle" | wc -l
else
    echo "✗ nft command NOT FOUND"
fi
echo ""

echo "## 8. TEST PARSER IMPORT"
echo "--------------------------------------------------------------------------------"
cd backend
python3 << 'EOF'
import sys
try:
    from nft_ruleset_parser import get_ruleset_parser
    print("✓ Parser import successful")
except ImportError as e:
    print(f"✗ Parser import failed: {e}")
    sys.exit(1)
EOF
cd ..
echo ""

echo "## 9. TEST PARSER INITIALIZATION (requires sudo)"
echo "--------------------------------------------------------------------------------"
echo "Running: sudo python3 test_backend_startup.py"
cd backend
sudo python3 test_backend_startup.py 2>&1 | head -40
cd ..
echo ""

echo "================================================================================"
echo "DIAGNOSTIC COMPLETE"
echo "================================================================================"
echo ""
echo "NEXT STEPS:"
echo ""
echo "If all checks pass (✓) but backend still doesn't show parser logs:"
echo "  1. Make sure backend is completely stopped: sudo pkill -9 -f python"
echo "  2. Start backend from backend directory: cd backend && sudo python3 app.py"
echo "  3. Watch the FIRST 20 lines of output carefully"
echo ""
echo "If you see ✗ marks above, those are the problems to fix first."
echo ""
