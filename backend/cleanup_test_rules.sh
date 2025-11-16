#!/bin/bash
# Cleanup test nftables rules from kernel

set -e

echo "============================================================"
echo "Cleaning up test nftables rules"
echo "============================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo ./cleanup_test_rules.sh"
    exit 1
fi

# Check if nft command exists
if ! command -v nft &> /dev/null; then
    echo "❌ nft command not found!"
    exit 1
fi

echo "ℹ Deleting table 'ip filter' (this will remove all rules)..."
nft delete table ip filter 2>/dev/null && echo "✅ Table deleted" || echo "⚠ Table not found (already clean)"

echo ""
echo "ℹ Clearing cache file..."
rm -f /tmp/nft_ruleset_cache.json && echo "✅ Cache cleared" || true

echo ""
echo "✅ Cleanup complete!"
echo ""
