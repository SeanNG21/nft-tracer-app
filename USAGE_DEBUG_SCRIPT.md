# Hướng Dẫn Sử Dụng debug_nft_duplicate.py

## Tổng quan

Script `debug_nft_duplicate.py` phân tích trace JSON để detect **TRUE duplicates** vs **multiple different expressions**.

**Mục đích:**
- ✅ Verify xem `nft_immediate_eval` có bị gọi duplicate không
- ✅ Phân biệt TRUE duplicate (bug) vs multiple rules (normal)
- ✅ Analyze verdict progression (CONTINUE vs DROP)
- ✅ Show timestamp delta giữa các events

---

## Cài đặt

Script không cần cài đặt thêm package, chỉ cần Python 3:

```bash
chmod +x debug_nft_duplicate.py
```

---

## Cách sử dụng

### 1. Basic usage

```bash
python3 debug_nft_duplicate.py <trace_file.json>
```

**Ví dụ:**
```bash
python3 debug_nft_duplicate.py backend/output/trace_full_test1_20241115_123456.json
```

### 2. Verbose mode (show raw JSON)

```bash
python3 debug_nft_duplicate.py <trace_file.json> -v
```

### 3. Analyze latest trace

```bash
python3 debug_nft_duplicate.py backend/output/trace_full_*.json
```

### 4. Test với example trace

```bash
python3 debug_nft_duplicate.py example_trace.json
```

---

## Output Format

### Header section

```
================================================================================
NFT_IMMEDIATE_EVAL DUPLICATE ANALYSIS
================================================================================
File: trace_file.json

Total packet traces: 1
```

### Trace details

```
--- TRACE #1 ---
SKB: 0xffff8dd9b14072e8
Protocol: TCP (6)
Flow: 127.0.0.1:55534 → 127.0.0.1:8888
Final verdict: STOLEN
Total rules evaluated: 4
```

### Event table

```
  Event Details:
  -------------------------------------------------------------------------
  #    rule_seq   verdict      verdict_raw  expr_addr            rule_handle  Δt(ns)
  -------------------------------------------------------------------------
  1    1          CONTINUE     -1           0xffff8dd9b1407100   4100         -
  2    2          CONTINUE     -1           0xffff8dd9b1407200   4100         +1257
  3    3          DROP         0            0xffff8dd9b1407300   4101         +3302
  4    4          DROP         0            0xffff8dd9b1407400   4101         +3927
```

**Columns:**
- `#`: Event number
- `rule_seq`: Rule sequence number (increment mỗi lần `nft_immediate_eval` được gọi)
- `verdict`: Verdict name (CONTINUE, DROP, ACCEPT, etc.)
- `verdict_raw`: Raw verdict value từ kernel (-1 = CONTINUE, 0 = DROP, etc.)
- `expr_addr`: **Expression address** (CRITICAL để detect duplicate!)
- `rule_handle`: Rule handle (unreliable, chỉ tham khảo)
- `Δt(ns)`: Timestamp delta so với event đầu tiên (nanoseconds)

**Color coding:**
- 🔵 CONTINUE = cyan
- 🔴 DROP = red
- 🟢 ACCEPT = green

### Analysis section

```
  Analysis:
  ----------------------------------------------------------------------------
  [✓] All 4 events have DIFFERENT expr_addr
      This is NORMAL - packet evaluated by 4 different expressions

  [i] Info: 2 events share rule_handle=4100
      → Different expr_addr - likely same rule with multiple expressions
```

**Hoặc nếu có duplicate:**

```
  [!!!] TRUE DUPLICATE DETECTED!
        Same expr_addr 0xffff8dd9b1407100 evaluated 2 times
        This is a BUG - same expression called multiple times!
        Events:
          - rule_seq=1, verdict=CONTINUE, Δt=0ns
          - rule_seq=2, verdict=CONTINUE, Δt=1257ns
```

### Verdict progression

```
  Verdict Progression:
    1. Rule seq=1: CONTINUE (raw=-1)
    2. Rule seq=2: CONTINUE (raw=-1)
    3. Rule seq=3: DROP (raw=0)
    4. Rule seq=4: DROP (raw=0)
```

**Warnings:**
```
  [!] WARNING: Terminal verdict 'DROP' at position 3, but 1 more events followed!
      Possible reasons:
      1. Verdict is actually CONTINUE (check verdict_raw=0)
      2. Jump/Goto to another chain
      3. Multiple expressions in same rule
```

### Summary

```
SUMMARY
--------------------------------------------------------------------------------
Total packet traces analyzed: 1
Total rule_eval events: 4
Total TRUE duplicates (same expr_addr): 0

[✓] NO TRUE DUPLICATES FOUND
    All nft_immediate_eval calls are for different expressions
    This is NORMAL behavior - packet evaluated by multiple expressions/rules
```

**Hoặc nếu có duplicate:**

```
[!!!] 2 TRUE DUPLICATES FOUND
      Same expression(s) evaluated multiple times
      This indicates a BUG in the tracer or nftables behavior
      Affected traces: [1, 3]

      RECOMMENDATION:
      1. Verify deduplication logic is enabled in backend/app.py
      2. Check if expr_addr extraction is correct
      3. Report this as a bug with trace file attached
```

---

## Interpretation Guide

### Scenario 1: NO TRUE DUPLICATES ✅

**Output:**
```
[✓] All 4 events have DIFFERENT expr_addr
    This is NORMAL - packet evaluated by 4 different expressions
```

**Meaning:**
- ✅ Mỗi event có expr_addr khác nhau
- ✅ Đây là hành vi ĐÚNG của nftables
- ✅ Packet được evaluate bởi 4 expressions/rules khác nhau
- ✅ KHÔNG CÓ BUG!

**Giải thích:**

Ruleset của bạn:
```nft
tcp dport 8888 counter continue  # Rule 1
tcp dport 8888 counter drop      # Rule 2
```

Có thể mỗi rule có 2 immediate expressions:
- Rule 1 → 2 expressions → expr_addr A, B
- Rule 2 → 2 expressions → expr_addr C, D

→ Total 4 events với 4 expr_addr khác nhau = NORMAL! ✅

### Scenario 2: TRUE DUPLICATE ⚠️

**Output:**
```
[!!!] TRUE DUPLICATE DETECTED!
      Same expr_addr 0xffff8dd9b1407100 evaluated 2 times
```

**Meaning:**
- ⚠️ Cùng expr_addr xuất hiện 2 lần
- ⚠️ Cùng expression được evaluate 2 lần
- ⚠️ **ĐÂY LÀ BUG!**

**Action:**
1. ✅ Deduplication logic trong `backend/app.py:278-291` sẽ tự động skip duplicate
2. ✅ Verify dedup đang hoạt động
3. ✅ Report bug với trace file

### Scenario 3: OLD TRACE FORMAT ⚠️

**Output:**
```
[!] WARNING: No expr_addr in events (old trace format)
    Cannot verify TRUE duplicates without expr_addr
    Please re-run trace with updated code to get expr_addr
```

**Meaning:**
- ⚠️ Trace từ code cũ (trước khi apply fix)
- ⚠️ Không có field `expr_addr`
- ⚠️ Không thể verify được TRUE duplicate

**Action:**
1. ✅ Pull code mới (đã có fix)
2. ✅ Restart backend
3. ✅ Chạy trace mới
4. ✅ Analyze lại với debug script

---

## Verdict Values Reference

### verdict_raw values

| verdict_raw | verdict_code | verdict_name | Description |
|-------------|--------------|--------------|-------------|
| `-1` | `10` | `CONTINUE` | Continue to next rule |
| `0` | `0` | `DROP` | Drop packet |
| `1` | `1` | `ACCEPT` | Accept packet |
| `2` | `2` | `STOLEN` | Packet consumed |
| `3` | `3` | `QUEUE` | Queue to userspace |
| `-2` | `11` | `RETURN` | Return from chain |
| `-3` | `12` | `JUMP` | Jump to chain |
| `-4` | `13` | `GOTO` | Goto chain |
| `-5` | `14` | `BREAK` | Break from loop |

**Critical:**
- `verdict_raw = -1` → CONTINUE (chain tiếp tục!)
- `verdict_raw = 0` → DROP (terminal verdict)

Nếu thấy verdict = "DROP" nhưng chain vẫn tiếp tục → check `verdict_raw`!

---

## FAQ

### Q1: Tại sao có 4 events cho 2 rule?

**A:** Mỗi rule có thể có nhiều immediate expressions:

```nft
tcp dport 8888 counter continue
```

Có thể compile thành:
1. Match expression: `tcp dport 8888`
2. Counter expression: `counter`
3. **Immediate expression 1**: Update verdict register (?)
4. **Immediate expression 2**: Set verdict `continue`

→ Mỗi rule → 2 immediate expressions → 2 lần `nft_immediate_eval`

→ 2 rule → 4 lần total

**Verify:** Check `expr_addr` - nếu 4 giá trị khác nhau → đúng!

### Q2: Tại sao cùng `rule_handle` mà khác `expr_addr`?

**A:** `rule_handle` extraction không đáng tin cậy!

File `nft_tracer.bpf.c:91-128` dùng **heuristic** để đoán rule_handle từ expression pointer. Có thể:
- Return chain handle thay vì rule handle
- Return giá trị random trong memory
- Tất cả expressions trong cùng chain có cùng "rule_handle"

→ **KHÔNG DÙNG** `rule_handle` để verify duplicate!

→ **CHỈ DÙNG** `expr_addr` để verify!

### Q3: Làm sao biết có TRUE duplicate?

**A:** Check `expr_addr`:

**NORMAL:**
```
expr_addr: 0xffff8dd9b1407100  ← Khác
expr_addr: 0xffff8dd9b1407200  ← Khác
expr_addr: 0xffff8dd9b1407300  ← Khác
expr_addr: 0xffff8dd9b1407400  ← Khác
```
→ ✅ 4 expressions khác nhau = NORMAL

**BUG:**
```
expr_addr: 0xffff8dd9b1407100  ← Expression A
expr_addr: 0xffff8dd9b1407100  ← Expression A (DUPLICATE!)
expr_addr: 0xffff8dd9b1407200  ← Expression B
expr_addr: 0xffff8dd9b1407200  ← Expression B (DUPLICATE!)
```
→ ⚠️ Cùng expression evaluate 2 lần = BUG!

### Q4: Nếu trace cũ không có `expr_addr`?

**A:** Chạy lại trace với code mới:

1. Pull code mới:
   ```bash
   git pull origin claude/debug-nft-immediate-eval-duplicate-01SkRbMZMuBYaHNJqowUwH3S
   ```

2. Restart backend:
   ```bash
   cd backend
   sudo python3 app.py
   ```

3. Tạo trace mới:
   ```bash
   curl -X POST http://localhost:5000/api/sessions \
     -H 'Content-Type: application/json' \
     -d '{"mode":"full","session_id":"test_new"}'

   nc localhost 8888

   curl -X DELETE http://localhost:5000/api/sessions/test_new
   ```

4. Download và analyze:
   ```bash
   python3 debug_nft_duplicate.py backend/output/trace_full_test_new_*.json
   ```

### Q5: Deduplication có hoạt động không?

**A:** Nếu có TRUE duplicate (cùng `expr_addr`), dedup logic sẽ skip:

**Code:** `backend/app.py:278-291`

```python
if event.expr_addr > 0:
    dedup_key = (event.skb_addr, event.expr_addr)

    if hasattr(self, '_last_expr_eval'):
        last_key, last_ts = self._last_expr_eval
        if (last_key == dedup_key and abs(event.timestamp - last_ts) < 1000):
            # DUPLICATE → SKIP
            return
```

**Verify:**
- Chạy trace với backend có fix
- Nếu vẫn thấy duplicate trong JSON → dedup không hoạt động
- Nếu không thấy duplicate → dedup đã skip thành công ✅

---

## Troubleshooting

### Issue: "No expr_addr in events"

**Cause:** Trace từ code cũ

**Fix:**
```bash
# Pull latest code
git pull

# Restart backend
cd backend && sudo python3 app.py

# Re-run trace
```

### Issue: "File not found"

**Cause:** Path không đúng

**Fix:**
```bash
# Check file exists
ls -la backend/output/trace_*.json

# Use full path
python3 debug_nft_duplicate.py /full/path/to/trace.json
```

### Issue: "Invalid JSON"

**Cause:** File bị corrupt hoặc chưa complete

**Fix:**
```bash
# Verify JSON
cat trace.json | python3 -m json.tool

# Re-download
curl http://localhost:5000/api/download/trace_*.json > trace_new.json
```

---

## Examples

### Example 1: Normal behavior (multiple expressions)

```bash
$ python3 debug_nft_duplicate.py example_trace.json

--- TRACE #1 ---
...
  [✓] All 4 events have DIFFERENT expr_addr
      This is NORMAL - packet evaluated by 4 different expressions

[✓] NO TRUE DUPLICATES FOUND
```

**Interpretation:** ✅ NORMAL - 4 different expressions

### Example 2: TRUE duplicate detected

```bash
$ python3 debug_nft_duplicate.py trace_with_bug.json

--- TRACE #1 ---
...
  [!!!] TRUE DUPLICATE DETECTED!
        Same expr_addr 0xffff8dd9b1407100 evaluated 2 times

[!!!] 2 TRUE DUPLICATES FOUND
      This indicates a BUG in the tracer or nftables behavior
```

**Interpretation:** ⚠️ BUG - Same expression evaluated twice

### Example 3: Old trace format

```bash
$ python3 debug_nft_duplicate.py old_trace.json

--- TRACE #1 ---
...
  [!] WARNING: No expr_addr in events (old trace format)
      Please re-run trace with updated code to get expr_addr
```

**Interpretation:** ⚠️ Need to re-run with new code

---

## Best Practices

1. ✅ **Always use latest code** để có `expr_addr`
2. ✅ **Check expr_addr** để verify duplicate (không dùng rule_handle)
3. ✅ **Check verdict_raw** để verify CONTINUE vs DROP
4. ✅ **Use verbose mode** `-v` nếu cần debug chi tiết
5. ✅ **Compare before/after** dedup để verify fix hoạt động

---

## Related Files

- `backend/app.py:275-305` - Deduplication logic
- `backend/nft_tracer.bpf.c:295-373` - nft_immediate_eval kprobe
- `backend/full_tracer.bpf.c:323-376` - nft_immediate_eval kprobe
- `ANALYSIS_NFT_IMMEDIATE_EVAL_DUPLICATE.md` - Phân tích chi tiết
- `FIX_DUPLICATE_NFT_IMMEDIATE_EVAL.md` - Fix documentation

---

**Author:** Claude Code
**Last Updated:** 2025-11-15
**Branch:** `claude/debug-nft-immediate-eval-duplicate-01SkRbMZMuBYaHNJqowUwH3S`
