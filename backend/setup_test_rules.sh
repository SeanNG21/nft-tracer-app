#!/bin/bash
# Setup test nftables rules in kernel for testing rule_eval capture

set -e

echo "============================================================"
echo "Setting up test nftables rules in kernel"
echo "============================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo ./setup_test_rules.sh"
    exit 1
fi

# Check if nft command exists
if ! command -v nft &> /dev/null; then
    echo "❌ nft command not found!"
    echo "Install with: sudo apt-get install nftables"
    exit 1
fi

echo "ℹ Creating table 'ip filter'..."
nft add table ip filter 2>/dev/null || true

echo "ℹ Creating chain 'input' (hook: input, priority: 0)..."
nft add chain ip filter input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true

echo "ℹ Creating chain 'output' (hook: output, priority: 0)..."
nft add chain ip filter output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true

echo "ℹ Flushing existing rules in chains..."
nft flush chain ip filter input 2>/dev/null || true
nft flush chain ip filter output 2>/dev/null || true

echo ""
echo "Adding test rules..."
echo ""

# Rule 1: SSH (port 22) -> ACCEPT
echo "  [1/4] SSH accept (port 22) -> handle 4100"
nft add rule ip filter input tcp dport 22 counter accept handle 4100

# Rule 2: HTTP (port 80) -> ACCEPT
echo "  [2/4] HTTP accept (port 80) -> handle 4101"
nft add rule ip filter input tcp dport 80 counter accept handle 4101

# Rule 3: ICMP echo-request -> DROP
echo "  [3/4] ICMP drop (echo-request) -> handle 4102"
nft add rule ip filter input icmp type echo-request counter drop handle 4102

# Rule 4: Output accept
echo "  [4/4] Output accept (all) -> handle 4200"
nft add rule ip filter output counter accept handle 4200

echo ""
echo "✅ Rules successfully loaded into kernel!"
echo ""
echo "Verifying rules..."
echo "============================================================"
nft -a list table ip filter
echo "============================================================"
echo ""

# Also update cache file
echo "ℹ Caching ruleset to /tmp/nft_ruleset_cache.json..."
nft -j list ruleset > /tmp/nft_ruleset_cache.json
echo "✅ Cache updated"
echo ""

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Start backend: sudo python3 backend/app.py"
echo "  2. Run test: sudo python3 backend/test_rule_eval_capture.py"
echo ""
