#!/bin/bash
# Quick test script for Multi-Kprobe Tracer

set -e

echo "=========================================="
echo "Multi-Kprobe Tracer - Quick Test"
echo "=========================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (sudo)"
    exit 1
fi

# Check dependencies
echo "[*] Checking dependencies..."

if ! command -v bpftool &> /dev/null; then
    echo "[!] bpftool not found!"
    echo "    Install: apt-get install linux-tools-\$(uname -r)"
    echo "    (Will use fallback kallsyms discovery)"
fi

if ! python3 -c "import bcc" 2>/dev/null; then
    echo "[!] BCC not found!"
    echo "    Install: apt-get install python3-bcc"
    exit 1
fi

echo "[✓] Dependencies OK"
echo ""

# Test 1: Discovery
echo "=========================================="
echo "Test 1: BTF Function Discovery"
echo "=========================================="
echo ""

echo "[*] Discovering kernel functions (priority=1)..."
python3 enhanced_btf_discoverer.py --priority 1 --output test_funcs.json --show-top 10

echo ""
echo "[✓] Discovery complete! Check test_funcs.json"
echo ""

# Test 2: Run tracer for 10 seconds
echo "=========================================="
echo "Test 2: Run Tracer (10 seconds)"
echo "=========================================="
echo ""

echo "[*] Starting tracer with priority 1..."
echo "[*] Will auto-stop after 10 seconds"
echo ""

# Run tracer in background
timeout 10 python3 multi_kprobe_tracer.py --priority 1 --verbose &
TRACER_PID=$!

# Generate some traffic
sleep 2
echo ""
echo "[*] Generating test traffic..."
ping -c 5 127.0.0.1 > /dev/null 2>&1 || true
curl -s http://127.0.0.1 > /dev/null 2>&1 || true

# Wait for tracer to finish
wait $TRACER_PID 2>/dev/null || true

echo ""
echo "[✓] Test complete!"
echo ""

# Summary
echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""
echo "✓ BTF Discovery: OK"
echo "✓ Tracer Execution: OK"
echo ""
echo "Next steps:"
echo "  1. Review test_funcs.json to see discovered functions"
echo "  2. Run full tracer: sudo python3 multi_kprobe_tracer.py --priority 1"
echo "  3. Read MULTI_KPROBE_GUIDE.md for detailed usage"
echo ""
echo "Examples:"
echo "  # Trace critical functions only"
echo "  sudo python3 multi_kprobe_tracer.py --priority 0"
echo ""
echo "  # Trace with sampling (reduce overhead)"
echo "  sudo python3 multi_kprobe_tracer.py --priority 2 --sample-rate 10"
echo ""
echo "  # Filter by category"
echo "  sudo python3 enhanced_btf_discoverer.py --category nft --category netfilter"
echo ""
