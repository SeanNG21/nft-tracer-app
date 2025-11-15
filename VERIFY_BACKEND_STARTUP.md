# Backend Startup Verification Guide

## Current Status

✅ **Code is correct and up-to-date**
- Latest commit: `f00e6158` - Add verbose logging for NFT parser
- All parser files exist and are properly structured
- app.py has parser preload code in `__main__` section
- Parser imports successfully

## The Issue

Your backend is not showing the NFT Parser initialization logs, which should look like:

```
======================================================================
KERNEL PACKET TRACER - FULL MODE + REALTIME VISUALIZATION
======================================================================
BCC: ✓
Realtime: ✓
NFT Parser: ✓
Kernel: 4.4.0
Hostname: [your hostname]
======================================================================
[*] Preloading NFT ruleset parser...
[✓] NFT Parser ready: 32 rules loaded      ← THIS LINE IS MISSING
======================================================================
```

## Step-by-Step Verification

### Step 1: Verify Code Version

Run this to confirm you have the latest code:

```bash
cd /home/user/nft-tracer-app
git log --oneline -1
```

**Expected output:**
```
f00e6158 Add verbose logging for NFT parser status and enrichment debugging
```

If you see a different commit, pull the latest code:
```bash
git pull origin claude/expand-packet-detail-info-013Ucz1ymCW8MB6xWden6qqu
```

### Step 2: Kill ALL Backend Processes

```bash
# Find all python processes running app.py
ps aux | grep python

# Kill them ALL (replace PID with actual process IDs)
sudo kill -9 [PID1] [PID2] ...

# Or use this to kill all at once:
sudo pkill -9 -f "python.*app.py"

# Verify nothing is running:
ps aux | grep python
```

**Expected:** No `app.py` processes should be listed.

### Step 3: Run Startup Test (Optional)

This verifies the parser can initialize:

```bash
cd /home/user/nft-tracer-app/backend
sudo python3 test_backend_startup.py
```

**Expected output:**
```
✓ NFT parser imported successfully
[*] Preloading NFT ruleset parser...
[✓] NFT Parser ready: X rules loaded
✓ Backend startup should work correctly
```

### Step 4: Start Backend with Full Logging

```bash
cd /home/user/nft-tracer-app/backend
sudo python3 app.py 2>&1 | tee backend_startup.log
```

**Watch for these EXACT lines in order:**

1. ✅ Banner should appear:
   ```
   ======================================================================
   KERNEL PACKET TRACER - FULL MODE + REALTIME VISUALIZATION
   ======================================================================
   ```

2. ✅ Component status should show:
   ```
   NFT Parser: ✓
   ```
   - If you see `NFT Parser: ✗` → Parser import failed
   - Check `backend_startup.log` for import errors

3. ✅ Parser preload should execute:
   ```
   [*] Preloading NFT ruleset parser...
   [✓] NFT Parser ready: 32 rules loaded
   ```
   - If missing → Backend is running OLD CODE or different Python environment

4. ✅ Flask startup:
   ```
   * Running on http://127.0.0.1:5000
   ```

### Step 5: Verify Environment

If Step 4 still doesn't show parser logs, check:

#### A. Python Environment
```bash
which python3
python3 --version
```

**Make sure you're using the same Python that has all dependencies.**

#### B. Working Directory
```bash
pwd
# Should output: /home/user/nft-tracer-app/backend
```

**Backend MUST be started from the `backend` directory.**

#### C. Parser File Exists
```bash
ls -l /home/user/nft-tracer-app/backend/nft_ruleset_parser.py
```

**Should show file with recent timestamp.**

#### D. Test Import
```bash
cd /home/user/nft-tracer-app/backend
python3 -c "from nft_ruleset_parser import get_ruleset_parser; print('OK')"
```

**Should print `OK` with no errors.**

## Common Problems

### Problem 1: "NFT Parser: ✗" appears

**Cause:** Parser failed to import

**Solution:**
```bash
cd /home/user/nft-tracer-app/backend
python3 -c "from nft_ruleset_parser import get_ruleset_parser"
```

This will show the exact import error.

### Problem 2: No parser preload logs appear

**Cause:** Backend is running old version of app.py

**Solution:**
1. Completely kill backend: `sudo pkill -9 -f python`
2. Verify file has the code:
   ```bash
   grep -A 5 "Preloading NFT ruleset parser" app.py
   ```
3. Should show:
   ```python
   print("[*] Preloading NFT ruleset parser...")
   parser = get_ruleset_parser()
   if parser._loaded:
       print(f"[✓] NFT Parser ready: {len(parser.rules)} rules loaded")
   ```
4. If missing → You're editing the wrong file or changes not saved
5. Start backend from correct directory: `cd backend && sudo python3 app.py`

### Problem 3: Parser loads but shows 0 rules

**Cause:** nftables has no rules

**Solution:**
```bash
sudo nft list ruleset
```

If empty, add some test rules or load your firewall config.

### Problem 4: Parser loads but events still don't have rule_text

**Cause:** Rule handles in trace don't match current ruleset

**This is NORMAL if:**
- Trace was captured before backend restart
- Rules changed after trace was captured
- Trace file has handle 4100 but current ruleset has different handles

**Solution:**
1. Start backend (parser loads current rules)
2. Capture NEW trace
3. New packets should have rule_text

**To verify enrichment is working:**
```bash
# Watch backend logs while tracing
# You should see:
[DEBUG] Enriched rule handle 31: tcp dport 8888 counter packets 5 bytes 300 continue
```

## Quick Restart Script

I've created a script that does all verification steps:

```bash
cd /home/user/nft-tracer-app
./backend/restart_backend.sh
```

This will:
- Check git status
- Kill old processes
- Verify files exist
- Start backend with full logging

## What Logs You Should See

When everything is working, your startup should look EXACTLY like this:

```
======================================================================
KERNEL PACKET TRACER - FULL MODE + REALTIME VISUALIZATION
======================================================================
BCC: ✓
Realtime: ✓
NFT Parser: ✓
Kernel: 4.4.0
Hostname: your-hostname
======================================================================
[*] Preloading NFT ruleset parser...
[✓] NFT Parser ready: 32 rules loaded
======================================================================
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

When you trace a packet, logs should show:

```
[DEBUG] Enriched rule handle 31: tcp dport 8888 counter packets 5 bytes 300 continue
```

When you load an old trace file:

```
[✓] Enriched 15 events with rule definitions
```

## Still Not Working?

If after following ALL steps above you still don't see parser logs, please provide:

1. Output of:
   ```bash
   cd /home/user/nft-tracer-app
   git log --oneline -1
   ```

2. Output of:
   ```bash
   cd /home/user/nft-tracer-app/backend
   grep -n "Preloading NFT ruleset parser" app.py
   ```

3. Full backend startup logs:
   ```bash
   cd /home/user/nft-tracer-app/backend
   sudo python3 app.py 2>&1 | head -30
   ```

This will help diagnose if there's a Python environment issue or other problem.
