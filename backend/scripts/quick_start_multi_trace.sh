#!/bin/bash
# Quick Start Script for Multi-Function NFT Tracer
# Auto-discovers functions and runs comprehensive packet tracing

set -e

echo "========================================================================"
echo "  Multi-Function NFT Tracer - Quick Start"
echo "========================================================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

# Check dependencies
echo "[*] Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 not found"
    exit 1
fi

if ! python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "[ERROR] BCC not installed"
    echo "Install with: apt install -y python3-bpfcc bpfcc-tools"
    exit 1
fi

if ! command -v bpftool &> /dev/null; then
    echo "[WARNING] bpftool not found - discovery will use kallsyms only"
    echo "Install with: apt install -y linux-tools-\$(uname -r)"
fi

echo "[✓] Dependencies OK"
echo ""

# Step 1: Discovery
echo "========================================================================"
echo "STEP 1: Function Discovery"
echo "========================================================================"
echo "[*] Discovering all kernel functions that handle sk_buff..."
echo "[*] This may take 30-60 seconds..."
echo ""

python3 enhanced_skb_discoverer.py \
    --output enhanced_skb_functions.json \
    --config trace_config.json \
    --max-trace 50 \
    --priority 2

if [ ! -f trace_config.json ]; then
    echo "[ERROR] Discovery failed - trace_config.json not created"
    exit 1
fi

echo ""
echo "[✓] Discovery complete!"
echo "    - enhanced_skb_functions.json: Full function list"
echo "    - trace_config.json: Top 50 functions to trace"
echo ""

# Step 2: Show what will be traced
echo "========================================================================"
echo "STEP 2: Trace Configuration"
echo "========================================================================"
echo "[*] Functions to be traced:"
python3 -c "
import json
with open('trace_config.json', 'r') as f:
    config = json.load(f)
    by_layer = {}
    for func in config['functions'][:20]:  # Show first 20
        layer = func['layer']
        if layer not in by_layer:
            by_layer[layer] = []
        by_layer[layer].append(func['name'])

    for layer in sorted(by_layer.keys()):
        print(f'  {layer}:')
        for fname in by_layer[layer][:5]:
            print(f'    - {fname}')

    total = len([f for f in config['functions'] if f.get('enabled', True)])
    print(f'\\n  Total: {total} functions enabled')
"
echo ""

# Step 3: Ask user
read -p "[*] Ready to start tracing? (Duration: 30 seconds) [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    echo "[*] Cancelled by user"
    exit 0
fi

# Step 4: Run tracer
echo ""
echo "========================================================================"
echo "STEP 3: Running Multi-Function NFT Tracer"
echo "========================================================================"
echo "[*] Starting tracer for 30 seconds..."
echo "[*] Generate network traffic in another terminal to see traces!"
echo ""
echo "Suggested test commands (run in another terminal):"
echo "  - ping -c 5 8.8.8.8"
echo "  - curl http://example.com"
echo "  - nft add rule inet filter input tcp dport 22 accept"
echo ""

python3 multi_function_nft_tracer.py \
    --config trace_config.json \
    --duration 30

echo ""
echo "========================================================================"
echo "DONE!"
echo "========================================================================"
echo "[✓] Trace complete. Check the JSON output file for detailed analysis."
echo ""
ls -lh multi_function_nft_trace_*.json 2>/dev/null | tail -1
echo ""
echo "To analyze the results:"
echo "  cat multi_function_nft_trace_*.json | jq '.summary'"
echo "  cat multi_function_nft_trace_*.json | jq '.packet_traces[0]'"
echo ""
