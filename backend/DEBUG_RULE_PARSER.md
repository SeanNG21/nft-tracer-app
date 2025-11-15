# Debug Guide: NFT Rule Definition Not Showing

Nếu bạn không thấy rule definition trong Packet Detail view, hãy làm theo các bước debug sau:

## Bước 1: Kiểm tra NFT Parser hoạt động

Chạy test script để xem parser có đọc được ruleset không:

```bash
cd backend
sudo python3 test_nft_parser.py
```

### Kết quả mong đợi:

```
================================================================================
NFT Ruleset Parser Test
================================================================================
[✓] Loaded X rules
[✓] Loaded Y tables
[✓] Loaded Z chains

================================================================================
TABLES:
================================================================================
  ip:filter
  ip:nat

================================================================================
CHAINS:
================================================================================
  ip:filter:input
    Hook: input
  ip:filter:forward
  ...

================================================================================
RULES:
================================================================================

Handle 2:
  Family: ip
  Table:  filter
  Chain:  input
  Text:   tcp dport 8888 counter packets 1 bytes 60 continue
  ...
```

### Nếu thấy lỗi:

**"[!] 'nft' command not found"**
- Cài đặt nftables: `sudo apt install nftables`

**"[!] Failed to load nftables ruleset: Permission denied"**
- Chạy với sudo: `sudo python3 test_nft_parser.py`

**"[✓] Loaded 0 rules"**
- Ruleset đang rỗng, thêm rules vào nftables
- Kiểm tra: `sudo nft list ruleset`

## Bước 2: Kiểm tra Backend Logs

Khi chạy backend, xem logs để tìm:

### Log thành công:
```
[✓] Loaded 15 nftables rules
```

### Log debug khi trace:
```
[DEBUG] Rule handle 42 not found in ruleset
```
→ Nghĩa là BPF capture được handle=42 nhưng không có trong ruleset hiện tại
→ **Nguyên nhân**: Rules đã thay đổi sau khi start trace

### Log lỗi:
```
[!] Error enriching rule handle 42: ...
```
→ Có lỗi khi parse rule, xem stacktrace bên dưới

## Bước 3: So sánh Rule Handles

### 3.1 Lấy rule handles từ nftables:

```bash
sudo nft -a list ruleset
```

Kết quả:
```
table ip filter {
    chain input {
        tcp dport 8888 counter packets 1 bytes 60 continue # handle 2
        tcp dport 22 accept # handle 3
        drop # handle 4
    }
}
```

Ghi nhớ các handle numbers (2, 3, 4...).

### 3.2 Xem rule handles từ trace:

Trong backend logs hoặc trong Raw Event Data ở frontend, tìm `rule_handle`:

```json
{
  "rule_handle": 2,
  "rule_seq": 0,
  ...
}
```

### 3.3 So sánh:

- ✅ Nếu handle **MATCH** (ví dụ: cả 2 đều là handle=2) → Rule definition sẽ hiển thị
- ❌ Nếu handle **KHÔNG MATCH** → Kiểm tra xem:
  - Có reload nftables rules sau khi start trace không?
  - Có nhiều ruleset (ip/ip6/bridge) và BPF đang trace ruleset khác?

## Bước 4: Kiểm tra Frontend

Mở browser DevTools (F12) → Console tab, xem event data:

```javascript
// Click vào packet → All Events tab → Tìm event rule_eval
// Mở "Show Raw Event Data"
```

Kiểm tra xem có các fields sau không:

```json
{
  "trace_type": "rule_eval",
  "rule_handle": 2,
  "rule_text": "tcp dport 8888 counter packets 1 bytes 60 continue",  // ← Cần có field này
  "rule_table": "filter",
  "rule_chain": "input",
  "rule_family": "ip"
}
```

### Nếu không có `rule_text`:

1. Backend không enrich được → Xem backend logs
2. Parser không tìm thấy handle → Chạy test_nft_parser.py
3. Rules thay đổi sau khi trace → Restart trace session

## Bước 5: Common Issues

### Issue: "Rule handle X not found in ruleset"

**Nguyên nhân**: Rules đã thay đổi giữa lúc:
1. Backend load ruleset (khi start)
2. BPF trace packet (khi packet đi qua)

**Giải pháp**:
```bash
# Stop backend
# Reload nftables rules nếu cần
sudo nft -f /etc/nftables.conf

# Start backend lại
cd backend
sudo python3 app.py
```

### Issue: Parser fails với TypeError

**Đã fix** trong commit mới nhất. Pull code mới nhất:
```bash
git pull origin claude/expand-packet-detail-info-013Ucz1ymCW8MB6xWden6qqu
```

### Issue: Permission denied

Parser cần sudo để đọc nftables:
```bash
sudo python3 app.py
```

## Bước 6: Enable Verbose Debug

Để xem chi tiết parsing mỗi rule, edit `backend/nft_ruleset_parser.py`:

```python
# Dòng ~293 (cuối file)
def get_ruleset_parser() -> NFTRulesetParser:
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = NFTRulesetParser(debug=True)  # ← Thêm debug=True
        _parser_instance.load_ruleset()
    return _parser_instance
```

Restart backend, sẽ thấy:
```
[DEBUG] Parsed rule handle=2: tcp dport 8888 counter packets 1 bytes 60 continue
[DEBUG] Parsed rule handle=3: tcp dport 22 accept
...
```

## Tóm tắt Checklist

- [ ] `sudo nft list ruleset` có rules
- [ ] `sudo python3 test_nft_parser.py` hiển thị rules với handles
- [ ] Backend logs show `[✓] Loaded X nftables rules` với X > 0
- [ ] Rule handles từ trace match với handles từ `nft -a list ruleset`
- [ ] Backend không có error logs
- [ ] Frontend Raw Event Data có field `rule_text`

Nếu tất cả checklist đều pass mà vẫn không hiển thị, vui lòng gửi:
1. Output của `sudo python3 test_nft_parser.py`
2. Backend logs khi trace
3. Raw Event Data từ frontend (JSON)
