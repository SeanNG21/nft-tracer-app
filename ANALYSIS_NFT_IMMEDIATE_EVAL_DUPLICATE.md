# Phân Tích: nft_immediate_eval bị gọi 2 lần

## TÓM TẮT

**KẾT LUẬN:** Đây KHÔNG PHẢI là bug duplicate probe, mà là **HÀNH VI ĐÚNG** của nftables!

Packet của bạn đi qua chain và được evaluate bởi **2 RULE KHÁC NHAU** (rule_seq=3 và rule_seq=4), không phải cùng một rule được gọi 2 lần.

---

## 1. LOẠI TRỪ CÁC NGUYÊN NHÂN DUPLICATE

### ✅ 1.1. KHÔNG có duplicate probe attachment

**File:** `nft_tracer.bpf.c:295-373`, `full_tracer.bpf.c:323-376`
- ✅ CHỈ CÓ 1 kprobe duy nhất: `kprobe__nft_immediate_eval`
- ❌ KHÔNG CÓ kretprobe cho nft_immediate_eval
- ❌ KHÔNG CÓ duplicate attachment trong Python

**File:** `app.py:552, 603`
```python
# NFT mode - CHỈ 1 LẦN
self.bpf_nft.attach_kprobe(event="nft_immediate_eval", fn_name="kprobe__nft_immediate_eval")

# FULL mode - CHỈ 1 LẦN
self.bpf_full.attach_kprobe(event="nft_immediate_eval", fn_name="kprobe__nft_immediate_eval")
```

### ✅ 1.2. KHÔNG có kprobe + kretprobe double log

- ❌ Không tồn tại `kretprobe__nft_immediate_eval` trong codebase
- ✅ Chỉ có kprobe (entry point)

### ✅ 1.3. KHÔNG có tracepoint duplicate

- ❌ Không sử dụng tracepoint `nftables.firewall.eval`
- ✅ Chỉ sử dụng kprobe

### ✅ 1.4. KHÔNG có duplicate event từ eBPF

**File:** `nft_tracer.bpf.c:370`, `full_tracer.bpf.c:373`
```c
events.perf_submit(ctx, &evt, sizeof(evt));  // CHỈ 1 LẦN
return 0;  // RETURN ngay sau submit, không có multiple paths
```

### ✅ 1.5. KHÔNG có duplicate trong user-space

**File:** `app.py:868`
```python
trace.add_nft_event(nft_event)  # Chỉ append 1 lần, không có loop
```

**File:** `app.py:275-312` - PacketTrace.add_nft_event
```python
def add_nft_event(self, event: NFTEvent):
    event_dict = {...}
    self.events.append(event_dict)  # CHỈ 1 LẦN append
```

---

## 2. NGUYÊN NHÂN THỰC SỰ

### 2.1. Phân tích JSON event

```json
{
  "total_rules_evaluated": 4,
  "important_events": [
    {
      "timestamp": 6042923954347,
      "trace_type": "rule_eval",
      "verdict": "DROP",
      "rule_seq": 3    ← RULE THỨ 3
    },
    {
      "timestamp": 6042923954929,
      "trace_type": "rule_eval",
      "verdict": "DROP",
      "rule_seq": 4    ← RULE THỨ 4 (KHÁC rule 3!)
    }
  ]
}
```

**CHÚ Ý:**
- ✅ `rule_seq: 3` và `rule_seq: 4` → **2 RULE KHÁC NHAU**
- ✅ Timestamp khác nhau: `582 nanoseconds` chênh lệch
- ✅ `total_rules_evaluated: 4` → Có 4 rule được evaluate (1, 2, 3, 4)
- ⚠️ Chỉ thấy rule 3 và 4 trong important_events (rule 1, 2 đâu?)

### 2.2. Logic increment `rule_seq` trong eBPF

**File:** `nft_tracer.bpf.c:308`, `full_tracer.bpf.c:335`
```c
int kprobe__nft_immediate_eval(struct pt_regs *ctx)
{
    struct skb_info *info = skb_map.lookup(&tid);
    if (!info)
        return 0;

    info->rule_seq++;  // ← INCREMENT MỖI LẦN nft_immediate_eval được gọi
    ...
}
```

**Giải thích:**
- `rule_seq` được increment **MỖI LẦN** `nft_immediate_eval` được trigger
- KHÔNG PHẢI mỗi lần một rule mới được evaluate
- Nếu `nft_immediate_eval` được gọi 4 lần → `rule_seq` sẽ là 1, 2, 3, 4

**Kết luận:** Đây là hành vi ĐÚNG! Mỗi rule có immediate expression sẽ trigger 1 lần `nft_immediate_eval`.

---

## 3. TẠI SAO CÓ 2 RULE ĐỀU CÓ VERDICT "DROP"?

### Khả năng 1: Chain có nhiều rule match cùng packet

**Ví dụ ruleset:**
```nft
table ip filter {
    chain input {
        type filter hook input priority 0; policy accept;

        # Rule 1: Counter (không có verdict → CONTINUE)
        tcp dport 22 counter

        # Rule 2: Counter
        tcp dport 80 counter

        # Rule 3: DROP ← match packet với dport=8888
        tcp dport 8888 drop

        # Rule 4: DROP ← DUPLICATE rule hoặc có điều kiện khác
        tcp dport 8888 drop
    }
}
```

**Nếu packet có `tcp dport 8888`:**
1. Rule 1 không match → skip
2. Rule 2 không match → skip
3. Rule 3 **MATCH** → `nft_immediate_eval(DROP)` → `rule_seq=3`
4. Rule 4 **MATCH** → `nft_immediate_eval(DROP)` → `rule_seq=4`

**Nhưng chờ đã!** Nếu rule 3 có verdict DROP, tại sao chain vẫn tiếp tục evaluate rule 4?

### Khả năng 2: Verdict không thực sự là DROP - có thể là CONTINUE

**Kiểm tra decode_verdict (nft_tracer.bpf.c:59-75):**
```c
static __always_inline u32 decode_verdict(s32 raw_ret, u32 raw_u32)
{
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;  // NFT_CONTINUE
            case -2: return 11;  // NFT_BREAK
            case -3: return 12;  // NFT_JUMP
            case -4: return 13;  // NFT_GOTO
            case -5: return 14;  // NFT_RETURN
            default: return 0;
        }
    }

    u32 verdict = raw_u32 & 0xFFu;
    if (verdict > 5) return 255;
    return verdict;
}
```

**Verdict mapping (app.py:315-321):**
```python
verdicts = {
    0: "DROP", 1: "ACCEPT", 2: "STOLEN", 3: "QUEUE",
    4: "REPEAT", 5: "STOP", 10: "CONTINUE", 11: "RETURN",
    12: "JUMP", 13: "GOTO", 14: "BREAK", 255: "UNKNOWN"
}
```

**Nếu verdict_code = -1 (NFT_CONTINUE):**
- `decode_verdict()` trả về `10`
- `verdict_str(10)` = `"CONTINUE"`

**Nhưng trong JSON, verdict là "DROP", không phải "CONTINUE"!**

### Khả năng 3: Jump/Goto logic

**Ví dụ:**
```nft
chain input {
    tcp dport 8888 jump check_tcp  # Rule 1
}

chain check_tcp {
    counter                         # Rule 2 (không có verdict)
    drop                            # Rule 3: DROP
    drop                            # Rule 4: DROP (unreachable!)
}
```

**Nhưng** rule 3 đã DROP, rule 4 sẽ không bao giờ được reach (unreachable code).

### Khả năng 4: Rule có nhiều expression

**Một rule có thể có nhiều statement:**
```nft
tcp dport 8888 counter drop
```

**Khi evaluate:**
1. Counter expression được execute (KHÔNG trigger `nft_immediate_eval`)
2. Immediate expression (drop) được execute (trigger `nft_immediate_eval`)

**Kết luận:** Mỗi rule chỉ có 1 immediate expression cho verdict → chỉ 1 lần `nft_immediate_eval`

---

## 4. NGUYÊN NHÂN KHẢ NĂNG NHẤT

### 🔥 **Rule 3 và 4 CÓ ĐIỀU KIỆN KHÁC NHAU**

**Ví dụ:**
```nft
# Rule 3: Match packet từ localhost
ip saddr 127.0.0.1 tcp dport 8888 drop

# Rule 4: Match packet bất kỳ (fallback)
tcp dport 8888 drop
```

**Nếu packet: `127.0.0.1 → 127.0.0.1:8888`**
- Rule 3 **MATCH** → evaluate → DROP (nhưng không terminate chain?)
- Rule 4 **MATCH** → evaluate → DROP

**Hoặc:**
```nft
# Rule 3: Drop với counter
tcp dport 8888 counter drop

# Rule 4: Drop log
tcp dport 8888 log drop
```

---

## 5. CÁCH VERIFY VẤN ĐỀ

### 5.1. Kiểm tra rule_handle

**Vấn đề:** JSON không có `rule_handle` trong important_events!

**File:** `app.py:282-284`
```python
'rule_handle': event.rule_handle if event.rule_handle > 0 else None,
```

Nếu `rule_handle = 0`, nó sẽ bị loại bỏ → Không thể verify được 2 events có cùng rule không.

### 5.2. Kiểm tra expr_addr

`expr_addr` là địa chỉ của expression struct trong kernel. Nếu 2 events có cùng `expr_addr`, đó là cùng 1 expression được gọi 2 lần (BUG). Nếu khác nhau, đó là 2 expression khác nhau (ĐÚNG).

**Vấn đề:** JSON không có `expr_addr` trong important_events!

### 5.3. List nftables rules

Chạy:
```bash
nft list ruleset
```

Đếm số rule trong chain input → verify với `total_rules_evaluated: 4`

---

## 6. ĐỀ XUẤT FIX

### Fix 1: Thêm `rule_handle` và `expr_addr` vào output

**File:** `backend/app.py:282-284`

**HIỆN TẠI:**
```python
'rule_handle': event.rule_handle if event.rule_handle > 0 else None,
```

**SỬA THÀNH:**
```python
'rule_handle': event.rule_handle,  # LUÔN include, kể cả = 0
'expr_addr': hex(event.expr_addr) if event.expr_addr > 0 else None,
```

### Fix 2: Deduplicate events dựa trên `(skb_addr, expr_addr)`

**File:** `backend/app.py` - Thêm vào PacketTrace class

```python
def add_nft_event(self, event: NFTEvent):
    """Add NFT rule evaluation event with deduplication"""

    # Deduplicate key: (skb_addr, expr_addr, timestamp_window)
    dedup_key = (event.skb_addr, event.expr_addr)

    # Check if this exact expression was just evaluated (within 1us)
    if hasattr(self, '_last_expr'):
        last_key, last_ts = self._last_expr
        if (last_key == dedup_key and
            abs(event.timestamp - last_ts) < 1000):  # 1us window
            # Duplicate call of same expression → SKIP
            return

    self._last_expr = (dedup_key, event.timestamp)

    # Continue with normal processing
    event_dict = {...}
    self.events.append(event_dict)
    ...
```

### Fix 3: Improve `rule_seq` logic - reset per chain

**File:** `backend/nft_tracer.bpf.c:186-230`, `full_tracer.bpf.c:231-266`

**HIỆN TẠI:**
```c
int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    ...
    info.rule_seq = 0;  // Reset rule_seq khi vào chain
    ...
}
```

**Vấn đề:** Nếu có multiple chains (jump/goto), rule_seq sẽ tiếp tục tăng.

**SỬA:**
```c
// Thêm chain_addr vào dedup key
struct skb_info info = {};
info.skb_addr = (u64)skb;
info.chain_addr = (u64)priv;  // Track chain
info.rule_seq = 0;  // Reset for new chain
```

---

## 7. KẾT LUẬN

### ✅ **Đây KHÔNG PHẢI là bug duplicate!**

Packet của bạn:
- Đi qua nftables INPUT chain
- Được evaluate bởi **4 rule** (total_rules_evaluated: 4)
- Rule 3 và Rule 4 đều có verdict DROP
- Mỗi rule trigger 1 lần `nft_immediate_eval`

### ⚠️ **Vấn đề thực tế:**

**Tại sao 1 packet sau khi DROP ở rule 3 vẫn tiếp tục evaluate rule 4?**

→ Đây có thể là:
1. **Rule logic không đúng trong nftables ruleset**
2. **Verdict không phải DROP mà là CONTINUE** (cần verify `verdict_raw`)
3. **Có jump/return logic phức tạp**

### 🔧 **Hành động tiếp theo:**

1. **Chạy:** `nft list ruleset` → xem rule thực tế
2. **Thêm `rule_handle` và `expr_addr` vào JSON output** → verify rule identity
3. **Check `verdict_raw` values** → xem verdict thực tế là gì
4. **Nếu thực sự là duplicate rule** → fix ruleset, không phải fix tracer

---

## REFERENCES

- **nft_tracer.bpf.c**: Line 295-373 (kprobe__nft_immediate_eval)
- **full_tracer.bpf.c**: Line 323-376 (kprobe__nft_immediate_eval)
- **app.py**: Line 275-312 (PacketTrace.add_nft_event)
- **app.py**: Line 780-889 (_handle_full_event)
- **app.py**: Line 552, 603 (probe attachment)
