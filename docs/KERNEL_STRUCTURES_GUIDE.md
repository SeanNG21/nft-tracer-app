# Hướng Dẫn Kernel Structures cho NFTables Tracing

## 1. Tổng Quan Kernel Structures

### struct nft_rule
```c
struct nft_rule {
    struct list_head list;        // Offset 0: Linked list để traverse rules trong chain
    u64 handle;                   // Offset 16: Rule handle (ID duy nhất)
    u32 dlen;                     // Offset 24: Độ dài của data[] chứa expressions
    u32 udata_len;                // Offset 28: Độ dài user data
    unsigned char data[]          // Offset 32: Mảng chứa các expressions
        __attribute__((aligned(__alignof__(struct nft_expr))));
};
```

**Giải thích:**
- `list`: Con trỏ đến rule tiếp theo trong chain (doubly linked list)
- `handle`: ID duy nhất của rule, được gán bởi nftables (giá trị này xuất hiện khi chạy `nft -a list`)
- `dlen`: Tổng kích thước của tất cả expressions trong rule
- `data[]`: Mảng flexible chứa các `struct nft_expr` liên tiếp

### struct nft_expr
```c
struct nft_expr_ops;

struct nft_expr {
    const struct nft_expr_ops *ops;  // Offset 0: Con trỏ đến operations (ví dụ: nft_immediate_ops)
    unsigned char data[]              // Offset 8: Dữ liệu riêng của expression
        __attribute__((aligned(__alignof__(u64))));
};
```

**Giải thích:**
- `ops`: Con trỏ đến function table (chứa eval, init, destroy functions)
- `data[]`: Dữ liệu cụ thể của expression (ví dụ: verdict code cho immediate expression)

### struct nft_immediate_expr (data của nft_immediate)
```c
struct nft_immediate_expr {
    struct nft_data dreg_data;    // Offset 0 (trong expr->data)
    u8 dreg;                       // Destination register
    u8 dlen;                       // Data length
};

struct nft_data {
    union {
        u32 data[4];              // Generic data
        struct nft_verdict verdict; // Verdict data
    };
};

struct nft_verdict {
    u32 code;                     // Verdict code: NF_ACCEPT, NF_DROP, etc.
    struct nft_chain *chain;      // For jump/goto
};
```

## 2. Cách Iterate Expressions Trong Rule

### Phương Pháp 1: Từ expr quay lại rule (Khó - Không có con trỏ ngược)
```c
// KHÔNG KHẢ DỤNG: struct nft_expr KHÔNG chứa con trỏ ngược về struct nft_rule
// Cần phải tính toán offset dựa trên vị trí bộ nhớ
```

### Phương Pháp 2: Hook vào nft_do_chain và traverse rules
```c
// Trong nft_do_chain, ta có:
// - struct nft_pktinfo *pkt
// - const struct nft_chain *chain

// Chain chứa danh sách rules:
struct nft_chain {
    struct list_head rules;  // Danh sách các rules
    // ...
};

// Để iterate qua các rules:
struct nft_rule *rule;
u16 rule_index = 0;

list_for_each_entry(rule, &chain->rules, list) {
    rule_index++;
    // rule->handle chứa handle
    // rule_index chứa vị trí (1-based hoặc 0-based)
}
```

### Phương Pháp 3: Track rule hiện tại trong nft_do_chain loop
```c
// nft_do_chain có vòng lặp qua rules:
struct nft_jumpstack jumpstack[NFT_JUMP_STACK_SIZE];
struct nft_rule *const *rules;
const struct nft_rule *rule;

// Kernel code (simplified):
do_chain:
    rule = *rules;  // Current rule
    rules++;        // Move to next rule

    // Iterate through expressions in current rule
    nft_rule_for_each_expr(expr, last, rule) {
        expr->ops->eval(expr, regs, pkt);  // Call nft_immediate_eval
    }
} while (rule);
```

## 3. Vấn Đề Với Cách Tiếp Cận Hiện Tại

### Vấn đề 1: rule_seq đếm expressions, không phải rules
```c
// Code hiện tại (SAI):
info->rule_seq++;  // Mỗi lần nft_immediate_eval gọi → tăng

// Kết quả: Nếu rule có 3 expressions:
//   - Expression 1: rule_seq = 1
//   - Expression 2: rule_seq = 2
//   - Expression 3: rule_seq = 3
// Nhưng thực tế cả 3 đều thuộc rule_seq = 1 (cùng một rule)
```

### Vấn đề 2: extract_rule_handle() đoán offset
```c
// Code hiện tại thử nhiều offsets ngẫu nhiên:
s32 offsets[] = {-16, -24, -32, -40, ...};

// Vấn đề:
// - Không chắc chắn offset nào đúng
// - Phụ thuộc vào layout bộ nhớ kernel
// - Có thể đọc nhầm giá trị khác
```

## 4. Giải Pháp Đúng

### Phương Án A: Hook vào nft_do_chain để track rule pointer
```c
// Ý tưởng: Trong nft_do_chain, trước khi gọi các expr->eval(),
// kernel đã biết rule hiện tại là gì

// Cần hook vào điểm TRƯỚC khi evaluate expressions:
// 1. Hook nft_do_chain → lưu chain address
// 2. Hook điểm mới: right before evaluating each rule → lưu rule pointer
// 3. Hook nft_immediate_eval → đọc từ rule pointer đã lưu
```

### Phương Án B: Sử dụng kprobe để đọc rule từ stack/registers
```c
// Trong nft_immediate_eval, expr được truyền qua tham số
// Cần tìm cách từ expr tính ngược lại địa chỉ rule

// Công thức:
// rule_addr = expr_addr - offset_of_expr_in_data - offsetof(struct nft_rule, data)

// VẤN ĐỀ: offset_of_expr_in_data không biết trước (phụ thuộc vào vị trí expr trong rule)
```

### Phương Án C: Hook nft_rule_eval() (Nếu có trong kernel version)
```c
// Một số kernel version có hàm này:
// static inline void nft_rule_eval(const struct nft_rule *rule, ...)

// Nếu có, đây là điểm tốt nhất để track:
// - rule pointer
// - rule->handle
// - rule index (cần tính từ chain)
```

### Phương Án D: Đọc rule handle từ memory layout (Nâng cao)
```c
// Dựa vào kiến thức về memory layout:

// struct nft_expr nằm trong rule->data[]
// Vị trí: rule->data[some_offset]

// Để tìm rule từ expr:
// 1. expr_addr là địa chỉ của struct nft_expr
// 2. expr nằm trong khoảng [rule->data, rule->data + rule->dlen]
// 3. rule->data bắt đầu tại offset 32 của struct nft_rule
// 4. Vậy: rule_addr = ALIGN_DOWN(expr_addr, alignment) - tìm header có handle hợp lệ

static __always_inline u64 find_rule_handle_precise(void *expr) {
    // Thử align về các boundaries có thể
    for (int offset = 0; offset < 512; offset += 8) {
        void *potential_rule = (char *)expr - offset;

        // Đọc handle tại offset 16
        u64 handle = 0;
        if (bpf_probe_read_kernel(&handle, sizeof(handle),
                                   (char *)potential_rule + 16) == 0) {
            // Kiểm tra handle có hợp lệ không
            if (handle > 0 && handle < 0x100000) {
                // Xác minh thêm bằng cách đọc dlen
                u32 dlen = 0;
                bpf_probe_read_kernel(&dlen, sizeof(dlen),
                                     (char *)potential_rule + 24);
                if (dlen > 0 && dlen < 4096) {  // Reasonable dlen
                    return handle;
                }
            }
        }
    }
    return 0;
}
```

## 5. Giải Pháp Được Đề Xuất: Tracing Rule Sequence

### Cách 1: Hook vào internal rule evaluation
```c
// Cần tìm kernel symbol để hook vào vòng lặp rule evaluation
// Ví dụ: tracepoint hoặc kprobe vào điểm iterate rules

// Pseudocode:
kprobe__before_rule_eval(struct nft_rule *rule) {
    u64 tid = bpf_get_current_pid_tgid();

    // Đọc handle
    u64 handle = 0;
    bpf_probe_read_kernel(&handle, sizeof(handle),
                         (char *)rule + 16);

    // Lưu vào map
    rule_map.update(&tid, &handle);
}

kprobe__nft_immediate_eval() {
    // Đọc handle từ map
    u64 *handle = rule_map.lookup(&tid);
}
```

### Cách 2: Phân Tích Rule Sequence Từ Chain (Runtime)
```c
// Trong nft_do_chain entry, traverse chain->rules để xây dựng map
// rule_handle -> rule_index

struct rule_info {
    u64 handle;
    u16 index;
};

BPF_HASH(chain_rule_map, u64, struct rule_info, 1024);

kprobe__nft_do_chain(..., struct nft_chain *chain) {
    // Chưa khả thi với eBPF do giới hạn vòng lặp
}
```

### Cách 3: Build Map Từ Userspace
```c
// Giải pháp thực tế nhất:
// 1. Python script chạy `nft -a list` để lấy rule handles và indexes
// 2. Build map: handle -> index
// 3. eBPF chỉ cần lấy handle chính xác
// 4. Userspace lookup index từ handle

// eBPF chỉ cần focus vào việc đọc đúng rule->handle
```

## 6. Implementation Plan

### Bước 1: Cải thiện extract_rule_handle()
- Sử dụng thuật toán tìm kiếm thông minh hơn
- Xác minh handle bằng cách kiểm tra các trường liền kề (dlen, list pointers)

### Bước 2: Phân biệt rule vs expression
- Đếm rule dựa trên handle thay đổi, không phải mỗi lần eval

### Bước 3: Build rule metadata từ userspace
- Parse nft output để map handle -> index -> metadata

### Bước 4: Kết hợp eBPF + userspace
- eBPF: Capture handle chính xác
- Userspace: Enrich với index và metadata
