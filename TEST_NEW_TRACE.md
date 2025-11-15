# Test Rule Enrichment with New Trace

## Current Status

✅ **Parser is working** - Diagnostic shows parser loaded 30 rules successfully
✅ **Backend is running** - Process is active and enrichment code is running
✅ **Enrichment code is active** - You can see `[DEBUG] Rule handle 4100 not found` in logs

⚠️ **Why you don't see rule definitions:**
- Your old trace file has rule handle **4100**
- Current nftables ruleset has handles: **2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13...**
- Handle 4100 doesn't exist anymore (rules changed/reloaded)

## To See Rule Definitions: Capture NEW Trace

### Step 1: Check Backend Startup Logs (Optional)

Your backend is already running. To verify parser loaded, restart it and watch the VERY FIRST lines:

```bash
# Stop current backend
sudo pkill -9 -f "python.*app.py"

# Start fresh and watch startup
cd ~/Downloads/nft-tracer-app/backend
sudo python3 app.py 2>&1 | tee backend_full.log
```

**First 20 lines should show:**
```
======================================================================
KERNEL PACKET TRACER - FULL MODE + REALTIME VISUALIZATION
======================================================================
BCC: ✓
Realtime: ✓
NFT Parser: ✓                          ← Must be ✓
Kernel: 5.15.0
Hostname: sean-GF75-Thin-10SC
======================================================================
[*] Preloading NFT ruleset parser...   ← THIS LINE
[✓] NFT Parser ready: 30 rules loaded  ← THIS LINE
======================================================================
```

If you don't see these lines, the logs started too late. Use `head -30 backend_full.log` to see the beginning.

### Step 2: Find Current Rule Handles

Check what rule handles are currently in your nftables:

```bash
sudo nft -a list ruleset | grep "tcp dport 8888"
```

**Example output:**
```
tcp dport 8888 counter packets 48 bytes 2960 # handle 10
```

This shows handle **10** has the tcp dport 8888 rule.

### Step 3: Start NEW Trace Session

1. Open frontend: http://localhost:3000
2. Click "Start New Session"
3. Select "Full Trace" mode
4. Click "Start Session"

### Step 4: Generate Traffic

Generate traffic that hits the rule:

```bash
# This should hit rule with handle 10 (tcp dport 8888)
curl -X POST http://localhost:8888

# Or telnet
telnet localhost 8888
```

### Step 5: Stop Trace

1. Click "Stop Session" in frontend
2. Wait for trace to appear in "Packet Trace Analyze" section

### Step 6: View Packet Details

1. Click on a packet that shows "nft_do_chain" in events
2. Click "All Events" tab
3. Look for events with type "rule_eval"

**You should now see:**

✅ **Green box with rule definition:**
```
┌─────────────────────────────────────────┐
│ Rule Definition:                        │
│ tcp dport 8888 counter packets 48 bytes │
│ 2960 continue                           │
│                                         │
│ ip › filter › input                     │
└─────────────────────────────────────────┘
```

✅ **Backend logs should show:**
```
[DEBUG] Enriched rule handle 10: tcp dport 8888 counter packets 48 bytes 2960 continue
```

## If Still No Rule Text

### Check 1: Backend Logs During Trace

While tracing, watch backend terminal. You should see:
```
[SessionStats trace_XXX] Event #1: hook=0, func=ip_local_out
[SessionStats trace_XXX] Event #2: hook=0, func=nf_hook_slow
[SessionStats trace_XXX] Event #3: hook=0, func=nft_do_chain
```

And when packet hits a rule:
```
[DEBUG] Enriched rule handle 10: tcp dport 8888 counter packets X bytes Y continue
```

If you see:
```
[DEBUG] Rule handle 10 not found in ruleset
```

Then parser doesn't have handle 10. Run `sudo nft -a list ruleset` to see current handles.

### Check 2: Verify Packet Hit NFT Rules

Not all packets go through nftables. Make sure your test traffic:
- Matches a rule in your nftables config
- Goes through a chain with rules
- Has verdict other than "accept/drop" (like "continue")

Example good rule to test:
```bash
sudo nft add rule ip filter input tcp dport 9999 counter continue
curl http://localhost:9999
```

### Check 3: Frontend Shows Event

In packet detail, "All Events" tab, look for events with:
- **Trace Type**: rule_eval
- **Rule Handle**: (should be a number like 10, 12, 31, etc.)
- **Rule Text**: (THIS is where rule definition appears)

If "Rule Handle" is 0, the packet didn't hit a specific rule.

## Quick Test Command

Run this all-in-one test:

```bash
# Add a test rule
sudo nft add rule ip filter input tcp dport 9999 counter continue

# Get its handle
HANDLE=$(sudo nft -a list chain ip filter input | grep "tcp dport 9999" | grep -o "handle [0-9]*" | awk '{print $2}')
echo "Test rule handle: $HANDLE"

# Generate traffic
curl -X POST http://localhost:9999 &

# Wait and check backend logs
sleep 2
grep "Enriched rule handle $HANDLE" backend_full.log
```

If this prints the enriched line, your system is working!

## Summary

The problem was NOT with your code. The problem is:
- **Old trace files** have handles from previous nftables configuration
- **Current nftables** has different handles
- **Need NEW trace** to see current rule definitions

Once you capture a new trace after backend starts, you WILL see the rule definitions in the green box.
