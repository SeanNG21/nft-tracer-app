#!/bin/bash
# Upload nftables ruleset to backend running in container
#
# Usage:
#   ./upload_ruleset.sh [backend_url]
#
# Example:
#   ./upload_ruleset.sh http://localhost:5000

BACKEND_URL="${1:-http://localhost:5000}"

echo "================================================================"
echo "NFT Ruleset Uploader"
echo "================================================================"

# Check if nft command exists
if ! command -v nft &> /dev/null; then
    echo "ERROR: 'nft' command not found!"
    echo "Please install nftables: apt-get install nftables"
    exit 1
fi

# Export current ruleset to JSON
echo "[1/3] Exporting current nftables ruleset..."
RULESET=$(nft -j list ruleset 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to export ruleset. Are you root?"
    echo "Try: sudo $0"
    exit 1
fi

# Count rules
RULE_COUNT=$(echo "$RULESET" | jq '[.nftables[] | select(.rule)] | length' 2>/dev/null || echo "?")
echo "  → Found $RULE_COUNT rules"

# Upload to backend
echo "[2/3] Uploading to backend at $BACKEND_URL..."
RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "$RULESET" \
    "$BACKEND_URL/api/nft/upload")

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to upload to backend"
    echo "Make sure backend is running at $BACKEND_URL"
    exit 1
fi

# Check response
SUCCESS=$(echo "$RESPONSE" | jq -r '.success' 2>/dev/null)
RULES_LOADED=$(echo "$RESPONSE" | jq -r '.rules_loaded' 2>/dev/null)

if [ "$SUCCESS" = "true" ]; then
    echo "  → Success! Loaded $RULES_LOADED rules"
else
    echo "ERROR: Upload failed"
    echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
    exit 1
fi

# Verify
echo "[3/3] Verifying..."
STATUS=$(curl -s "$BACKEND_URL/api/nft/status" | jq '.' 2>/dev/null)
echo "$STATUS"

echo ""
echo "================================================================"
echo "✓ Ruleset uploaded successfully!"
echo "  Trace events will now include rule_text enrichment"
echo "================================================================"
