#!/bin/bash
# Test NFT Setup - Create test ruleset to verify duplicate issue
# This creates a minimal ruleset for testing

set -e

echo "=========================================="
echo "NFT Test Ruleset Setup"
echo "=========================================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] This script must be run as root"
    exit 1
fi

# Backup existing ruleset
echo "[*] Backing up existing nftables ruleset..."
nft list ruleset > /tmp/nft_backup_$(date +%Y%m%d_%H%M%S).nft 2>/dev/null || true

# Flush existing rules (CAREFUL!)
echo "[*] Flushing existing nftables rules..."
read -p "Are you sure you want to flush existing rules? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "[!] Aborted"
    exit 1
fi

nft flush ruleset

# Create test table
echo "[*] Creating test filter table..."
nft add table ip filter

# Create input chain with multiple rules
echo "[*] Creating input chain with test rules..."
nft add chain ip filter input { type filter hook input priority 0\; policy accept\; }

# Add test rules
echo "[*] Adding test rules..."

# Rule 1: Counter for port 22 (SSH)
nft add rule ip filter input tcp dport 22 counter

# Rule 2: Counter for port 80 (HTTP)
nft add rule ip filter input tcp dport 80 counter

# Rule 3: DROP for port 8888 (TEST)
nft add rule ip filter input tcp dport 8888 counter drop

# Rule 4: Another DROP for port 8888 (DUPLICATE - should NOT be reached!)
nft add rule ip filter input tcp dport 8888 counter drop

# Rule 5: Accept for established connections
nft add rule ip filter input ct state established,related counter accept

echo
echo "[✓] Ruleset created successfully!"
echo
echo "Current ruleset:"
echo "=========================================="
nft list ruleset
echo "=========================================="
echo

echo "Test instructions:"
echo "1. Start tracer: cd backend && sudo python3 app.py"
echo "2. In another terminal, start a trace session:"
echo "   curl -X POST http://localhost:5000/api/sessions -H 'Content-Type: application/json' -d '{\"mode\":\"full\"}'"
echo "3. Generate test traffic:"
echo "   nc localhost 8888  (will be dropped by rule 3)"
echo "4. Wait a few seconds, then stop session and download trace"
echo "5. Run analysis: python3 debug_nft_duplicate.py backend/output/trace_*.json"
echo
echo "Expected result:"
echo "- Packet to port 8888 should match rule 3 (DROP)"
echo "- Rule 4 should NOT be evaluated (unreachable after rule 3 DROP)"
echo "- If rule 4 is evaluated → BUG!"
echo
echo "To restore original ruleset:"
echo "  nft -f /tmp/nft_backup_*.nft"
echo
