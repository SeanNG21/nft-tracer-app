# Fix: BPF Verifier Compatibility Issues

## Vấn Đề Phát Hiện

Sau khi triển khai cải tiến ban đầu, phát hiện các vấn đề:

### 1. BPF Verifier Rejection (Kernel 4.4.0)
```
ERROR: Không bắt được events từ nft_immediate_eval
NGUYÊN NHÂN: Vòng lặp search quá lớn (32-448 bytes = 53 iterations)
KẾT QUẢ: BPF verifier reject code → program không load được
```

### 2. Event Loss
```
TRIỆU CHỨNG:
- total_rules_evaluated = 0
- Chỉ có chain_exit events
- Không có nft_immediate_eval events
- rule_handle = 0, rule_seq = 0
```

## Nguyên Nhân Chi Tiết

### BPF Verifier Constraints trên Kernel 4.4.0

```c
// CODE CŨ (BỊ REJECT):
#pragma unroll
for (int search_offset = 32; search_offset <= 448; search_offset += 8) {
    // 53 iterations - QUÁ LỚN cho kernel cũ!
}
```

**Giới hạn BPF:**
- Kernel < 5.2: Số iterations giới hạn ~32-64
- Kernel 4.4.0: Rất strict về loop unrolling
- 53 iterations vượt quá limit → verifier reject

### Logic Rule Counting

```c
// CODE CŨ (GÂY MẤT EVENTS):
if (rule_handle != 0 && rule_handle != info->last_rule_handle) {
    info->rule_seq++;  // CHỈ tăng khi handle đổi
}
```

**Vấn đề:**
- Nếu không tìm thấy handle (= 0) → rule_seq không tăng
- Nếu handle giống lần trước → rule_seq không tăng
- Kết hợp với BPF reject → không có events nào được emit

## Giải Pháp

### Fix 1: Giảm Search Range

```c
// FIXED: Search range nhỏ hơn
#pragma unroll
for (int search_offset = 32; search_offset <= 192; search_offset += 8) {
    // 20 iterations - AN TOÀN cho kernel cũ
}
```

**Lý do chọn 192:**
- (192-32)/8 + 1 = 21 iterations
- Đủ để cover hầu hết cases
- An toàn với BPF verifier kernel 4.4.0
- Vẫn giữ method 2 làm fallback

### Fix 2: Restore Backward Compatible Counting

```c
// FIXED: Luôn tăng rule_seq
info->rule_seq++;  // Đếm mọi expression (như ban đầu)

// Vẫn lưu handle để userspace có thể analyze
u64 rule_handle = extract_rule_handle(expr);
info->last_rule_handle = rule_handle;
```

**Ưu điểm:**
- ✅ Đảm bảo events luôn được emit
- ✅ Backward compatible với code cũ
- ✅ Vẫn có rule_handle chính xác (nhờ improved extraction)
- ✅ Userspace có thể post-process để group theo rule

## So Sánh Behavior

### Trước Fix (BỊ LỖI):
```
nft_immediate_eval được gọi:
  - Expression 1: rule_seq KHÔNG tăng (handle = 0 hoặc không đổi)
  - Expression 2: rule_seq KHÔNG tăng
  - Expression 3: rule_seq KHÔNG tăng

→ Kết quả: rule_seq = 0, KHÔNG CÓ EVENTS (do BPF reject)
```

### Sau Fix (HOẠT ĐỘNG):
```
nft_immediate_eval được gọi:
  - Expression 1: rule_seq = 1, handle = H1 (improved extraction)
  - Expression 2: rule_seq = 2, handle = H2
  - Expression 3: rule_seq = 3, handle = H3

→ Kết quả: Events được emit, handle chính xác hơn
```

## Userspace Post-Processing

Mặc dù `rule_seq` đếm expressions, userspace có thể group theo `rule_handle`:

```python
# Group events by rule_handle to get actual rules
from collections import defaultdict

def group_events_by_rule(events):
    rules = defaultdict(list)

    for evt in events:
        if evt.rule_handle != 0:
            rules[evt.rule_handle].append(evt)

    # Now you have actual rules grouped
    for handle, rule_events in rules.items():
        print(f"Rule handle={handle}: {len(rule_events)} expressions")

    return rules

# Example output:
# Rule handle=10: 3 expressions  <- Rule 1
# Rule handle=11: 2 expressions  <- Rule 2
```

## Kết Luận

**Trade-off được chấp nhận:**
- ❌ `rule_seq` không phản ánh rule index (như mục tiêu ban đầu)
- ✅ `rule_handle` chính xác hơn (với improved extraction)
- ✅ Events được bắt đầy đủ (không bị mất)
- ✅ Tương thích với kernel cũ (4.4.0)
- ✅ Userspace có thể xử lý để lấy rule index thực tế

**Lý do:**
- Kernel 4.4.0 quá cũ, giới hạn BPF rất nghiêm ngặt
- Không thể vừa đếm rule index chính xác vừa tương thích kernel cũ trong eBPF
- Giải pháp tốt nhất: eBPF capture raw data, userspace xử lý logic phức tạp

## Các File Đã Sửa

1. **backend/nft_tracer.bpf.c**
   - Giảm search range: 32-192 bytes (20 iterations)
   - Restore rule_seq++ cho mọi expression
   - Vẫn extract và lưu rule_handle

2. **backend/full_tracer.bpf.c**
   - Cùng fixes như trên
   - Đảm bảo consistency

3. **docs/BPF_VERIFIER_FIX.md** (file này)
   - Giải thích vấn đề và giải pháp

## Khuyến Nghị

### Để Lấy Rule Index Thực Tế

**Option 1: Userspace Processing (Khuyến nghị)**
```python
# Parse nft rules để build mapping
import subprocess
import re

def build_rule_map():
    output = subprocess.check_output(['nft', '-a', 'list', 'ruleset'])
    rule_map = {}  # handle -> index

    current_chain = None
    rule_index = 0

    for line in output.decode().split('\n'):
        if 'chain' in line:
            rule_index = 0
            current_chain = line
        elif '# handle' in line:
            rule_index += 1
            match = re.search(r'# handle (\d+)', line)
            if match:
                handle = int(match.group(1))
                rule_map[handle] = rule_index

    return rule_map

# Use in event processing
rule_map = build_rule_map()
for evt in events:
    if evt.rule_handle in rule_map:
        actual_rule_index = rule_map[evt.rule_handle]
        print(f"Event from rule index {actual_rule_index}")
```

**Option 2: Upgrade Kernel (Nếu có thể)**
- Kernel >= 5.2: Giới hạn BPF lỏng hơn
- Có thể implement logic phức tạp hơn trong eBPF

**Option 3: Sử dụng BPF CO-RE (Nếu kernel hỗ trợ)**
- Compile Once, Run Everywhere
- Tự động adapt với kernel structures
- Cần libbpf và BTF support

## Testing

```bash
# Test compilation
cd /home/user/nft-tracer-app/backend
python3 -c "from bcc import BPF; BPF(src_file='nft_tracer.bpf.c')"

# Verify events are captured
# Should see:
# - nft_immediate_eval events ✓
# - rule_seq increments ✓
# - rule_handle values ✓
```

## Version History

- v1: Initial improvement (BROKEN on kernel 4.4.0)
- v2: Fixed for kernel compatibility (THIS VERSION)
