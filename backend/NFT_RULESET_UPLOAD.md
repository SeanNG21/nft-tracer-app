# NFT Ruleset Upload Guide

## Problem

When running the backend in a **container** or **restricted environment**, the `nft` command may not be available. However, eBPF can still hook into kernel nftables functions and capture events.

Without access to `nft` command, the backend cannot:
- Map `rule_handle` to actual rule text
- Show which rules packets are hitting
- Display rule positions in chains

## Solution

Upload the nftables ruleset from the **host system** to the backend API.

---

## Quick Start

### Option 1: Using the helper script

On the **host system** (where nft command works):

```bash
cd backend
sudo ./upload_ruleset.sh http://localhost:5000
```

The script will:
1. Export current ruleset using `nft -j list ruleset`
2. Upload to backend via POST /api/nft/upload
3. Verify the upload

### Option 2: Manual upload

```bash
# On host: Export ruleset
sudo nft -j list ruleset > ruleset.json

# Upload to backend
curl -X POST \
  -H "Content-Type: application/json" \
  -d @ruleset.json \
  http://localhost:5000/api/nft/upload
```

### Option 3: Copy file into container

```bash
# On host: Export ruleset
sudo nft -j list ruleset > /tmp/ruleset.json

# Copy into container (if using Docker)
docker cp /tmp/ruleset.json <container_id>:/tmp/ruleset.json

# Inside container: Load via Python
python3 -c "
from nft_ruleset_parser import get_parser
parser = get_parser()
parser.load_from_json_file('/tmp/ruleset.json')
print(f'Loaded {len(parser.rules)} rules')
"
```

---

## API Endpoints

### Upload Ruleset
```
POST /api/nft/upload
Content-Type: application/json

Body: Output from "nft -j list ruleset"
```

**Example Response:**
```json
{
  "success": true,
  "rules_loaded": 25,
  "message": "Successfully loaded 25 rules from uploaded ruleset",
  "note": "Rules are now cached and will be used for enriching trace events"
}
```

### Check Parser Status
```
GET /api/nft/status
```

**Example Response:**
```json
{
  "nft_command_available": false,
  "cache_file": "/tmp/nft_ruleset_cache.json",
  "cache_exists": true,
  "cache_size_bytes": 15420,
  "rules_loaded": 25,
  "last_update": 1731780123.456,
  "note": "If nft command is not available and cache is empty, upload ruleset via POST /api/nft/upload"
}
```

### List All Rules
```
GET /api/nft/rules
```

**Example Response:**
```json
{
  "total": 25,
  "rules": [
    {
      "handle": 4100,
      "family": "ip",
      "table": "filter",
      "chain": "input",
      "position": 0,
      "rule_text": "tcp dport 22 accept"
    },
    ...
  ]
}
```

### Get Rule by Handle
```
GET /api/nft/rules/4100
```

**Example Response:**
```json
{
  "handle": 4100,
  "family": "ip",
  "table": "filter",
  "chain": "input",
  "position": 0,
  "rule_text": "tcp dport 22 accept",
  "note": "This is rule #0 (0-indexed) in chain ip:filter:input"
}
```

---

## How It Works

### 1. Parser Priority

The parser tries these methods in order:

1. **nft command** (if available)
   ```bash
   nft -j list ruleset
   ```

2. **Cached file** (`/tmp/nft_ruleset_cache.json`)
   - Created automatically when nft command succeeds
   - Or created when you upload via API

3. **Empty** (with warning)
   - Shows instructions to upload

### 2. Event Enrichment

Once ruleset is loaded, all NFT trace events are automatically enriched:

**Before:**
```json
{
  "rule_handle": 4100,
  "rule_seq": 1,
  "rule_text": null,
  "rule_position": null,
  "rule_table": null,
  "rule_chain": null
}
```

**After Upload:**
```json
{
  "rule_handle": 4100,
  "rule_seq": 1,
  "rule_text": "tcp dport 22 accept",
  "rule_position": 0,
  "rule_table": "filter",
  "rule_chain": "input"
}
```

### 3. Comparing rule_seq vs rule_position

- **`rule_seq`**: Counted by eBPF (may be incorrect due to multiple expressions per rule)
- **`rule_position`**: Actual position from `nft list chain` (always correct)

This allows you to **debug rule_seq issues** by comparing the two values!

---

## Troubleshooting

### "nft command not available and no cache found"

**Symptoms:**
- `rule_text: null` in trace events
- Warning in backend logs

**Solution:**
Upload ruleset from host system using one of the methods above.

### "Failed to upload to backend"

**Check:**
1. Is backend running? `curl http://localhost:5000/api/health`
2. Is port accessible from host?
3. Is the JSON valid? `nft -j list ruleset | jq .`

### "rules_loaded: 0"

**Possible causes:**
1. Empty ruleset (no rules configured)
2. Invalid JSON format
3. Parser error (check backend logs)

**Verify:**
```bash
# Check if you have rules
sudo nft list ruleset

# Check JSON export works
sudo nft -j list ruleset | jq .
```

### Cache not persisting across restarts

The default cache file is `/tmp/nft_ruleset_cache.json` which may be cleared on reboot.

**To persist:**
1. Upload ruleset after each backend restart
2. Or modify `NFTRulesetParser` cache_file path to permanent location

---

## Integration with Sessions

When you start a trace session, the backend automatically:

1. Checks for available ruleset (nft command or cache)
2. Loads rules into memory
3. Enriches all subsequent events

**Log output on session start:**
```
[DEBUG] Session trace_xyz created in FULL mode
[NFT Parser] WARNING: nft command not available and no cache found!
[NFT Parser] To enable rule text enrichment:
[NFT Parser]   1. Run on host: nft -j list ruleset > ruleset.json
[NFT Parser]   2. POST ruleset.json to /api/nft/upload
```

Or if cache exists:
```
[NFT Parser] Loaded 25 rules from cache: /tmp/nft_ruleset_cache.json
[DEBUG] Loaded 25 nftables rules for session
```

---

## Example Workflow

### Scenario: Running backend in Docker container

1. **Start backend in container:**
   ```bash
   docker run -it --privileged nft-tracer-backend
   ```

2. **On host, export and upload ruleset:**
   ```bash
   sudo nft -j list ruleset > /tmp/ruleset.json
   curl -X POST \
     -H "Content-Type: application/json" \
     -d @/tmp/ruleset.json \
     http://localhost:5000/api/nft/upload
   ```

3. **Start trace session:**
   ```bash
   curl -X POST http://localhost:5000/api/sessions \
     -H "Content-Type: application/json" \
     -d '{"mode": "full"}'
   ```

4. **Generate traffic and view traces:**
   ```bash
   # Generate traffic
   ping 8.8.8.8

   # View traces with enriched rule_text
   curl http://localhost:5000/api/traces/trace_xyz.json
   ```

5. **Verify rule enrichment:**
   ```bash
   curl http://localhost:5000/api/traces/trace_xyz.json | \
     jq '.traces[0].events[] | select(.rule_handle > 0) | {rule_handle, rule_text, rule_position}'
   ```

---

## Notes

- Upload is **idempotent** - you can upload multiple times
- Ruleset is **cached** to /tmp, survives backend restarts (until system reboot)
- Upload **does not modify** nftables rules, only loads for parsing
- Works for **any nftables version** that supports JSON output
