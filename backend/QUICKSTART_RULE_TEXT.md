# Quick Start: Enable Rule Text Enrichment

## Problem
When running backend in container, `rule_text` is `null` in trace events because `nft` command is not available.

## Solution (Choose ONE method)

### ✅ Method 1: Load Example Rules (FASTEST - for testing)

```bash
cd backend
python3 load_example_ruleset.py
```

**Output:**
```
✓ Successfully loaded 4 rules
  Cache: /tmp/nft_ruleset_cache.json

Rules loaded:
  [ip:filter:input#0] handle 4100: tcp dport == 22 counter accept
  [ip:filter:input#1] handle 4101: tcp dport == 80 counter accept
  [ip:filter:input#2] handle 4102: icmp type == echo-request counter drop
  [ip:filter:output#0] handle 4200: counter accept

Now you can start a trace session and rule_text will be populated!
```

### ✅ Method 2: Upload Real Ruleset from Host

**On host system** (where `nft` command works):

```bash
# Export ruleset
sudo nft -j list ruleset > /tmp/ruleset.json

# Upload to backend (adjust URL if needed)
curl -X POST \
  -H "Content-Type: application/json" \
  --data @/tmp/ruleset.json \
  http://localhost:5000/api/nft/upload
```

**Or use helper script:**
```bash
cd backend
sudo ./upload_ruleset.sh http://localhost:5000
```

### ✅ Method 3: Load from File (if you already have JSON)

```python
from nft_ruleset_parser import get_parser

parser = get_parser()
parser.load_from_json_file('/path/to/your/ruleset.json')
print(f"Loaded {len(parser.rules)} rules")
```

---

## Verify It Works

### 1. Check cache exists:
```bash
ls -lh /tmp/nft_ruleset_cache.json
```

### 2. Check parser status via API:
```bash
curl http://localhost:5000/api/nft/status | jq .
```

**Expected output:**
```json
{
  "nft_command_available": false,
  "cache_file": "/tmp/nft_ruleset_cache.json",
  "cache_exists": true,
  "cache_size_bytes": 1520,
  "rules_loaded": 4,
  "last_update": 1731780123.456
}
```

### 3. List loaded rules:
```bash
curl http://localhost:5000/api/nft/rules | jq '.rules[]'
```

### 4. Start trace session:
```bash
curl -X POST http://localhost:5000/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"mode": "full"}'
```

**Backend should log:**
```
[NFT Parser] Loaded 4 rules from cache: /tmp/nft_ruleset_cache.json
[DEBUG] Loaded 4 nftables rules for session
```

### 5. Generate traffic and check traces:
```bash
# Generate some traffic
ping -c 3 8.8.8.8

# Stop session
curl -X DELETE http://localhost:5000/api/sessions/trace_xyz

# View trace with rule_text
curl http://localhost:5000/api/traces/trace_xyz.json | \
  jq '.traces[].events[] | select(.rule_handle > 0) | {rule_handle, rule_text, rule_position}'
```

**Expected output with rule_text populated:**
```json
{
  "rule_handle": 4100,
  "rule_text": "tcp dport == 22 counter accept",
  "rule_position": 0
}
```

---

## Troubleshooting

### Still seeing `rule_text: null`?

**Check 1:** Is cache loaded?
```bash
curl http://localhost:5000/api/nft/status
```

**Check 2:** Does the rule_handle match?
```bash
# List available rules
curl http://localhost:5000/api/nft/rules | jq '.rules[] | .handle'

# Check specific handle from your trace
curl http://localhost:5000/api/nft/rules/4100
```

**Check 3:** Was session started AFTER loading cache?
- Cache must be loaded BEFORE starting trace session
- If you load cache after session start, stop and restart the session

### Cache gets cleared on reboot?

Cache is stored in `/tmp/` which is cleared on system reboot.

**Solutions:**
1. Run `python3 load_example_ruleset.py` after each backend restart
2. Or modify parser to use permanent cache location
3. Or upload via API after each restart

---

## What Gets Enriched?

Once ruleset is loaded, **every NFT trace event** gets these fields:

```json
{
  "rule_handle": 4100,              // From eBPF hook
  "rule_seq": 1,                    // From eBPF counter (may be wrong)
  "rule_text": "tcp dport == 22 counter accept",  // ✅ From parser
  "rule_position": 0,               // ✅ From parser (actual position - CORRECT)
  "rule_table": "filter",           // ✅ From parser
  "rule_chain": "input"             // ✅ From parser
}
```

**Use case:** Compare `rule_seq` vs `rule_position` to debug eBPF counting logic!

---

## Summary

**Quick test (30 seconds):**
```bash
cd backend
python3 load_example_ruleset.py
# → Cache loaded with 4 rules

# Start backend (if not running)
python3 app.py

# In another terminal, start trace session
curl -X POST http://localhost:5000/api/sessions -H "Content-Type: application/json" -d '{"mode":"full"}'

# Generate traffic, then check traces
# → rule_text will be populated! 🎉
```

**For production (with real rules):**
```bash
# On host
sudo nft -j list ruleset > /tmp/ruleset.json

# Upload to backend
curl -X POST -H "Content-Type: application/json" \
  --data @/tmp/ruleset.json \
  http://localhost:5000/api/nft/upload
```

Done! 🚀
