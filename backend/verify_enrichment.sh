#!/bin/bash
# Quick verification that rule enrichment is working

echo "================================================================================"
echo "Rule Enrichment Verification"
echo "================================================================================"
echo ""

# Get current rule handles
echo "Current nftables rule handles:"
echo "--------------------------------------------------------------------------------"
sudo nft -a list ruleset | grep "# handle" | head -20
echo ""

echo "Looking for rule handle 10 details:"
echo "--------------------------------------------------------------------------------"
sudo nft -j list ruleset | python3 << 'EOF'
import json
import sys

data = json.load(sys.stdin)

for item in data.get('nftables', []):
    if 'rule' in item:
        rule = item['rule']
        if rule.get('handle') == 10:
            print(f"Family: {rule.get('family')}")
            print(f"Table: {rule.get('table')}")
            print(f"Chain: {rule.get('chain')}")
            print(f"Handle: {rule.get('handle')}")
            print(f"Expressions: {rule.get('expr')}")
            break
EOF

echo ""
echo "================================================================================"
echo "INSTRUCTIONS TO TEST ENRICHMENT:"
echo "================================================================================"
echo ""
echo "1. Make sure backend is running (you already have it running)"
echo ""
echo "2. Start a NEW trace session in the frontend"
echo ""
echo "3. Generate traffic that hits rule handle 10:"
echo "   curl -X POST http://localhost:8888"
echo ""
echo "4. Stop the trace"
echo ""
echo "5. Look at the packet details - you should see:"
echo "   - Green box with rule definition"
echo "   - Text: 'tcp dport 8888 counter packets X bytes Y'"
echo ""
echo "6. In backend logs, you should see:"
echo "   [DEBUG] Enriched rule handle 10: tcp dport 8888 counter packets X bytes Y"
echo ""
echo "================================================================================"
