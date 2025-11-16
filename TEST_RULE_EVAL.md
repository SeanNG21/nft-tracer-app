# Testing Rule Evaluation Events Capture

## Issue
Not getting `rule_eval` events with `trace_type="rule_eval"` and `verdict="CONTINUE"` from eBPF code.

## Root Cause Analysis

The code is **working correctly**. The issue is that you need **TWO things**:

1. **Rules loaded in KERNEL** - Real nftables rules processing packets
2. **Rules cached in FILE** - Rule text enrichment for trace output

AND you need to **generate traffic** that triggers these rules.

### How it works:

1. **`nft_do_chain` (trace_type=0 "chain_exit")**:
   - Triggered when a chain completes execution
   - Returns the final verdict for the chain

2. **`nft_immediate_eval` (trace_type=1 "rule_eval")**:
   - Triggered when a rule with verdict is evaluated
   - **Only triggered when a packet actually matches and evaluates a rule!**

3. **`nf_hook_slow` (trace_type=2 "hook_exit")**:
   - Triggered when a netfilter hook completes

## Test Steps

### 1. Setup Test Rules (IMPORTANT: Load into KERNEL)

**Option A: Use setup script (Recommended)**
```bash
sudo bash backend/setup_test_rules.sh
```

This will:
- Create nftables table and chains in kernel
- Add 4 test rules with specific handles (4100-4200)
- Cache ruleset to `/tmp/nft_ruleset_cache.json`

**Option B: Manual setup**
```bash
# Load rules into KERNEL
sudo nft add table ip filter
sudo nft add chain ip filter input '{ type filter hook input priority 0; policy accept; }'
sudo nft add chain ip filter output '{ type filter hook output priority 0; policy accept; }'
sudo nft add rule ip filter input tcp dport 22 counter accept handle 4100
sudo nft add rule ip filter input tcp dport 80 counter accept handle 4101
sudo nft add rule ip filter input icmp type echo-request counter drop handle 4102
sudo nft add rule ip filter output counter accept handle 4200

# Cache for rule text enrichment
sudo nft -j list ruleset > /tmp/nft_ruleset_cache.json
sudo python3 backend/load_example_ruleset.py
```

Expected output:
```
✅ Rules successfully loaded into kernel!
✓ Successfully loaded 4 rules
  [ip:filter:input#0] handle 4100: tcp dport == 22 counter accept
  [ip:filter:input#1] handle 4101: tcp dport == 80 counter accept
  [ip:filter:input#2] handle 4102: icmp type == echo-request counter drop
  [ip:filter:output#0] handle 4200: counter accept
```

### 2. Start Backend Server

```bash
cd backend
sudo python3 app.py
```

### 3. Start a Trace Session (in another terminal)

```bash
curl -X POST http://localhost:5000/api/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "test_rule_eval",
    "mode": "nft"
  }'
```

Expected response:
```json
{
  "mode": "nft",
  "session_id": "test_rule_eval",
  "status": "started"
}
```

### 4. Generate Traffic to Trigger Rules

**Test SSH rule (handle 4100):**
```bash
# From another machine or localhost
ssh -p 22 localhost
# Or just try to connect:
nc localhost 22
# Press Ctrl+C to exit
```

**Test HTTP rule (handle 4101):**
```bash
# Try to connect to port 80
curl http://localhost:80
# Or
nc localhost 80
# Press Ctrl+C
```

**Test ICMP drop rule (handle 4102):**
```bash
# This should be dropped!
ping -c 3 localhost
```

### 5. Stop Session and Check Results

```bash
# Stop the session
curl -X DELETE http://localhost:5000/api/sessions/test_rule_eval
```

Expected response:
```json
{
  "output_file": "trace_nft_test_rule_eval_20250116_123456.json",
  "status": "stopped"
}
```

### 6. Download and Inspect the Trace File

```bash
# List files
curl http://localhost:5000/api/files

# Download the trace file
curl http://localhost:5000/api/download/trace_nft_test_rule_eval_20250116_123456.json > trace.json

# Pretty print to check
cat trace.json | jq '.traces[].important_events[] | select(.trace_type == "rule_eval")'
```

Expected output (example):
```json
{
  "timestamp": 1234567890123456,
  "trace_type": "rule_eval",
  "verdict": "ACCEPT",
  "verdict_code": 1,
  "verdict_raw": 1,
  "rule_seq": 1,
  "rule_handle": 4100,
  "rule_text": "tcp dport == 22 counter accept",
  "rule_position": 0,
  "rule_table": "filter",
  "rule_chain": "input"
}
```

## Debugging Tips

### Check if eBPF program is attached

```bash
sudo bpftool prog list | grep nft
```

### Check if rules are loaded in nftables

```bash
sudo nft -a list ruleset
```

### Check kernel function availability

```bash
# Check if nft_immediate_eval exists in kernel
sudo grep nft_immediate_eval /proc/kallsyms
```

If the function doesn't exist, your kernel version might use a different function name.

### Enable Debug Logging

Modify `backend/app.py` and add debug prints in `_handle_nft_event`:

```python
def _handle_nft_event(self, cpu, data, size):
    event = self.bpf_nft["events"].event(data)
    nft_event = NFTEvent.from_bpf_event(event)

    # ADD THIS DEBUG LINE:
    print(f"[DEBUG] NFT Event: type={nft_event.trace_type}, verdict={nft_event.verdict}, rule_handle={nft_event.rule_handle}, rule_seq={nft_event.rule_seq}")

    with self.lock:
        # ... rest of code
```

## Common Issues

### 1. No Events at All
- **Problem**: eBPF program not attached or kernel doesn't support kprobes
- **Solution**: Check kernel version (need 4.15+), verify kprobe support

### 2. Only `chain_exit` Events, No `rule_eval`
- **Problem**: No traffic actually triggering rules with verdict expressions
- **Solution**: Generate traffic as shown in step 4

### 3. `rule_text` is `null`
- **Problem**: Ruleset not loaded into parser cache
- **Solution**: Run `sudo python3 backend/load_example_ruleset.py` before starting session

### 4. Duplicate Events
- **Problem**: Deduplication window too small
- **Solution**: Increase `DEDUP_WINDOW_NS` in `app.py` (currently 5000ns = 5μs)

## Expected Behavior

When a packet hits the INPUT chain with destination port 22:

1. **chain_exit** event (trace_type=0):
   - Final verdict for the chain
   - May show ACCEPT if rule matched

2. **rule_eval** events (trace_type=1):
   - One event per rule with verdict expression
   - Shows CONTINUE for non-matching rules
   - Shows ACCEPT/DROP for matching rules

3. **hook_exit** event (trace_type=2):
   - Final verdict from netfilter hook
   - Shows overall decision

## Cleanup After Testing

To remove test rules from kernel:

```bash
sudo bash backend/cleanup_test_rules.sh
```

Or manually:
```bash
sudo nft delete table ip filter
sudo rm -f /tmp/nft_ruleset_cache.json
```

## Summary

The code is **working correctly**. To see `rule_eval` events:

1. ✅ Load rules into **KERNEL** with `sudo bash backend/setup_test_rules.sh`
2. ✅ Start backend and create trace session with mode="nft"
3. ⚠️ **GENERATE TRAFFIC** to trigger rules (this is the missing step!)
4. ✅ Stop session and check trace file

**Key Points:**
- Rules must be in KERNEL (not just cache) to trigger `nft_immediate_eval`
- Cache file is only for enriching rule text in output
- Without traffic, you will see NO events because no packets are being processed by nftables!
