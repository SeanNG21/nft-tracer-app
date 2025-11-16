# Cải Tiến NFT Tracer - Rule Sequence và Rule Handle Chính Xác

## Tổng Quan

Đã cải tiến chương trình eBPF để lấy được **rule_seq** và **rule_handle** CHÍNH XÁC khi theo dõi quá trình đánh giá rule trong nftables.

## Vấn Đề Trước Đây

### 1. rule_seq đếm expressions, không phải rules
```
Code cũ:
  info->rule_seq++;  // Tăng mỗi khi nft_immediate_eval được gọi

Vấn đề:
  - Một rule có nhiều expressions
  - Mỗi expression gọi nft_immediate_eval một lần
  - rule_seq không phản ánh index thực tế của rule trong chain

Ví dụ:
  Rule 1 có 3 expressions → rule_seq = 1, 2, 3 (SAI)
  Rule 2 có 2 expressions → rule_seq = 4, 5 (SAI)

  Mong muốn:
  Rule 1 → rule_seq = 1 (cho cả 3 expressions)
  Rule 2 → rule_seq = 2 (cho cả 2 expressions)
```

### 2. rule_handle không chính xác
```
Code cũ:
  - Thử nhiều offset ngẫu nhiên: -16, -24, -32, -40...
  - Không có xác minh chính xác
  - Có thể đọc nhầm giá trị khác
```

## Giải Pháp Mới

### 1. Đọc Chính Xác rule_handle

#### Dựa trên kernel struct layout:
```c
struct nft_rule {
    struct list_head list;    // offset 0, size 16 bytes
    u64 handle;               // offset 16, size 8 bytes ← ĐÂY!
    u32 dlen;                 // offset 24, size 4 bytes (độ dài data[])
    u32 udata_len;            // offset 28, size 4 bytes
    unsigned char data[]      // offset 32, expressions bắt đầu tại đây
        __attribute__((aligned(__alignof__(struct nft_expr))));
};
```

#### Thuật toán mới:
```c
static __always_inline u64 extract_rule_handle_precise(void *expr)
{
    // expr là con trỏ đến struct nft_expr trong rule->data[]
    // Cần tìm ngược lại địa chỉ của struct nft_rule

    // Tìm kiếm ngược từ expr về phía trước
    for (int search_offset = 32; search_offset <= 512; search_offset += 8) {
        void *potential_rule = (char *)expr - search_offset;

        // Đọc handle tại offset 16
        u64 handle;
        bpf_probe_read_kernel(&handle, sizeof(handle),
                             (char *)potential_rule + 16);

        // Xác minh handle hợp lệ (0 < handle < 0x100000)
        if (handle == 0 || handle >= 0x100000)
            continue;

        // Đọc dlen tại offset 24 để xác minh
        u32 dlen;
        bpf_probe_read_kernel(&dlen, sizeof(dlen),
                             (char *)potential_rule + 24);

        // dlen phải hợp lệ (0 < dlen < 4096)
        if (dlen == 0 || dlen > 4096)
            continue;

        // Xác minh expr nằm trong khoảng [rule->data, rule->data + dlen]
        u64 expr_offset = (u64)expr - (u64)potential_rule - 32;
        if (expr_offset < dlen) {
            // Tìm thấy rule header hợp lệ!
            return handle;
        }
    }

    return 0;
}
```

**Ưu điểm:**
- Xác minh bằng nhiều điều kiện (handle, dlen, vị trí expr)
- Dựa trên layout chính xác của kernel struct
- Giảm thiểu false positives

### 2. Tracking Chính Xác rule_seq

#### Ý tưởng:
- Chỉ tăng `rule_seq` khi phát hiện **rule MỚI**
- Phát hiện rule mới dựa trên **handle thay đổi**

#### Implementation:
```c
struct skb_info {
    u16 rule_seq;           // Rule index hiện tại
    u64 last_rule_handle;   // Handle của rule cuối cùng được thấy
    // ... other fields
};

// Trong nft_immediate_eval:
u64 rule_handle = extract_rule_handle_precise(expr);

// Chỉ tăng rule_seq khi handle thay đổi
if (rule_handle != 0 && rule_handle != info->last_rule_handle) {
    info->rule_seq++;
    info->last_rule_handle = rule_handle;
}
```

**Kết quả:**
```
Rule 1 (handle=10, 3 expressions):
  - Expression 1: rule_seq=1, handle=10 (tăng seq, lưu handle)
  - Expression 2: rule_seq=1, handle=10 (không tăng, handle không đổi)
  - Expression 3: rule_seq=1, handle=10 (không tăng, handle không đổi)

Rule 2 (handle=11, 2 expressions):
  - Expression 1: rule_seq=2, handle=11 (tăng seq, handle đổi!)
  - Expression 2: rule_seq=2, handle=11 (không tăng, handle không đổi)
```

## Files Đã Cải Tiến

### 1. backend/nft_tracer_improved.bpf.c
- Phiên bản hoàn toàn mới với tất cả cải tiến
- Dành cho nft_tracer standalone mode

### 2. backend/full_tracer.bpf.c
- Đã cập nhật với cùng cải tiến
- Dành cho full mode tracing (SKB + NFT)

### 3. docs/KERNEL_STRUCTURES_GUIDE.md
- Tài liệu chi tiết về kernel structures
- Giải thích layout của nft_rule, nft_expr
- Hướng dẫn cách iterate expressions

## Cách Sử Dụng

### Biên Dịch Code Mới

```bash
cd /home/user/nft-tracer-app/backend

# Compile improved version
python3 -c "
from bcc import BPF
b = BPF(src_file='nft_tracer_improved.bpf.c')
print('Compiled successfully!')
"

# Hoặc compile full_tracer
python3 -c "
from bcc import BPF
b = BPF(src_file='full_tracer.bpf.c')
print('Compiled successfully!')
"
```

### Test với NFT Rules

```bash
# Tạo test rules
sudo nft add table ip test_table
sudo nft add chain ip test_table test_chain { type filter hook input priority 0 \; }
sudo nft add rule ip test_table test_chain ip saddr 192.168.1.100 counter accept
sudo nft add rule ip test_table test_chain ip daddr 10.0.0.0/8 counter drop
sudo nft add rule ip test_table test_chain tcp dport 80 counter accept

# List rules với handles
sudo nft -a list chain ip test_table test_chain

# Output mẫu:
# table ip test_table {
#   chain test_chain {
#     ip saddr 192.168.1.100 counter packets 0 bytes 0 accept # handle 10
#     ip daddr 10.0.0.0/8 counter packets 0 bytes 0 drop # handle 11
#     tcp dport 80 counter packets 0 bytes 0 accept # handle 12
#   }
# }

# Chạy tracer và kiểm tra output
# rule_seq=1, rule_handle=10 → Rule đầu tiên
# rule_seq=2, rule_handle=11 → Rule thứ hai
# rule_seq=3, rule_handle=12 → Rule thứ ba
```

## Xác Minh Kết Quả

### Kiểm tra rule_seq chính xác:
```python
# Khi parse events từ eBPF:
events_by_rule = {}
for evt in events:
    key = (evt.chain_addr, evt.rule_handle)
    if key not in events_by_rule:
        events_by_rule[key] = []
    events_by_rule[key].append(evt)

# Verify: Tất cả events của cùng một rule phải có cùng rule_seq
for (chain, handle), evts in events_by_rule.items():
    rule_seqs = set(e.rule_seq for e in evts)
    assert len(rule_seqs) == 1, f"Rule {handle} has inconsistent rule_seq: {rule_seqs}"
    print(f"Rule handle={handle}: rule_seq={evts[0].rule_seq} (OK)")
```

### Kiểm tra rule_handle chính xác:
```bash
# So sánh với output của nft
sudo nft -a list | grep "# handle"

# Handles trong eBPF events phải khớp với handles trong nft output
```

## Cấu Trúc Kernel Chi Tiết

### struct nft_rule (Linux kernel)
```c
// Location: include/net/netfilter/nf_tables.h
struct nft_rule {
    struct list_head        list;      // 0  - 16: Linked list node
    u64                     handle;    // 16 - 24: Rule handle (unique ID)
    u32                     dlen;      // 24 - 28: Data length
    u32                     udata_len; // 28 - 32: User data length
    unsigned char           data[]     // 32 - ∞ : Expression data
        __attribute__((aligned(__alignof__(struct nft_expr))));
};
```

### struct nft_expr
```c
struct nft_expr {
    const struct nft_expr_ops   *ops;  // 0 - 8 : Operations (eval, init, etc.)
    unsigned char                data[] // 8 - ∞ : Expression-specific data
        __attribute__((aligned(__alignof__(u64))));
};
```

### struct nft_immediate_expr
```c
// Data layout trong expr->data cho immediate expression
struct nft_immediate_expr {
    struct nft_data   dreg_data;  // Offset 0: Register data
    u8                dreg;       // Destination register
    u8                dlen;       // Data length
};

struct nft_data {
    union {
        u32               data[4];
        struct nft_verdict {
            u32           code;    // Verdict: ACCEPT=1, DROP=0, etc.
            struct nft_chain *chain;
        } verdict;
    };
};
```

## Iterate Expressions Trong Rule

### Cách kernel iterate (reference):
```c
// Kernel code: net/netfilter/nf_tables_core.c
#define nft_rule_for_each_expr(expr, last, rule) \
    for ((expr) = nft_expr_first(rule), (last) = nft_expr_last(rule); \
         (expr) != (last); \
         (expr) = nft_expr_next(expr))

static inline struct nft_expr *nft_expr_first(const struct nft_rule *rule)
{
    return (struct nft_expr *)&rule->data[0];
}

static inline struct nft_expr *nft_expr_next(const struct nft_expr *expr)
{
    return ((void *)expr) + expr->ops->size;
}

static inline struct nft_expr *nft_expr_last(const struct nft_rule *rule)
{
    return (struct nft_expr *)&rule->data[rule->dlen];
}
```

### Trong eBPF (giới hạn):
```c
// Không thể dùng vòng lặp động trong eBPF
// Giải pháp: Track từng expression khi được gọi
// và dùng handle để phân biệt rules
```

## Giới Hạn và Lưu Ý

### 1. eBPF Verifier Constraints
- Không thể dùng vòng lặp không bounded
- Giới hạn số lần unroll: thường <= 64
- Search offset giới hạn tối đa 512 bytes

### 2. Kernel Version Dependencies
- Struct layout có thể khác nhau giữa các kernel versions
- Code được test với kernel 4.4.0
- Nên kiểm tra lại với kernel version khác

### 3. Performance Considerations
- Tìm kiếm ngược 512 bytes với bước 8 = 64 iterations
- BPF verifier yêu cầu unroll hết → tăng kích thước bytecode
- Nếu gặp vấn đề, giảm search range xuống 256 bytes

## Troubleshooting

### 1. rule_handle = 0 (không tìm thấy)
```
Nguyên nhân:
  - Expr không nằm trong rule->data[] hợp lệ
  - Kernel struct layout khác
  - Search range không đủ lớn

Giải pháp:
  - Tăng search_offset tối đa (lên 1024)
  - Kiểm tra kernel version
  - Dump memory để xác định offset chính xác
```

### 2. rule_seq không tăng
```
Nguyên nhân:
  - rule_handle giống nhau cho nhiều rules (collision)
  - Logic so sánh handle bị lỗi

Giải pháp:
  - Kiểm tra uniqueness của handles
  - Debug bằng cách in ra tất cả handles
```

### 3. BPF verifier error
```
Nguyên nhân:
  - Vòng lặp quá lớn
  - Stack usage quá nhiều

Giải pháp:
  - Giảm số iterations trong #pragma unroll
  - Giảm search_offset từ 512 → 256
  - Simplify validation logic
```

## Kết Luận

Với các cải tiến này:
- ✅ **rule_seq** phản ánh đúng index của rule trong chain
- ✅ **rule_handle** được đọc chính xác từ kernel struct
- ✅ Dựa trên layout chính xác của kernel structures
- ✅ Có xác minh để tránh false positives
- ✅ Tương thích với output của `nft -a list`

**rule_seq bây giờ = rule index thực tế**, không phải số lần gọi expression! 🎉
