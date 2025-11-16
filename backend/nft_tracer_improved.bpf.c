// SPDX-License-Identifier: GPL-2.0
// nft_tracer_improved.bpf.c - IMPROVED VERSION with accurate rule_seq and rule_handle
//
// IMPROVEMENTS:
// 1. Precise rule_handle extraction based on struct nft_rule layout
// 2. Accurate rule_seq tracking (counts rules, not expressions)
// 3. Rule deduplication based on handle changes

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

struct nft_event {
    u64 timestamp;
    u32 cpu_id;
    u32 pid;
    u64 skb_addr;
    u64 chain_addr;
    u64 expr_addr;
    u64 regs_addr;
    u8 hook;
    u8 chain_depth;
    u8 trace_type;
    u8 pf;
    u32 verdict;
    s32 verdict_raw;
    u16 queue_num;
    u16 rule_seq;
    u8 has_queue_bypass;
    u8 protocol;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u64 rule_handle;
    char comm[16];
    u8 _pad[2];
};

struct skb_info {
    u64 skb_addr;
    u64 chain_addr;
    u8 hook;
    u8 pf;
    u16 rule_seq;           // Rule index (1-based)
    u64 last_rule_handle;   // Track last seen rule handle
    u8 protocol;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// BCC Macros for maps
BPF_PERF_OUTPUT(events);
BPF_HASH(skb_map, u64, struct skb_info, 10240);
BPF_HASH(depth_map, u64, u8, 10240);

// Helper functions
static __always_inline u32 decode_verdict(s32 raw_ret, u32 raw_u32)
{
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;
            case -2: return 11;
            case -3: return 12;
            case -4: return 13;
            case -5: return 14;
            default: return 0;
        }
    }

    u32 verdict = raw_u32 & 0xFFu;
    if (verdict > 5) return 255;
    return verdict;
}

static __always_inline void read_comm_safe(char *dest, u32 size)
{
    #pragma unroll
    for (int i = 0; i < 16 && i < size; i++) {
        dest[i] = 0;
    }

    long ret = bpf_get_current_comm(dest, size);
    if (ret != 0) {
        dest[0] = '?';
        dest[1] = 0;
    }
}

// ============================================
// IMPROVED: Precise rule_handle extraction
// ============================================
// Based on struct nft_rule layout:
//   struct nft_rule {
//       struct list_head list;    // offset 0, size 16
//       u64 handle;               // offset 16, size 8
//       u32 dlen;                 // offset 24, size 4
//       u32 udata_len;            // offset 28, size 4
//       unsigned char data[]      // offset 32, expressions start here
//   };
//
// The expr pointer points somewhere inside rule->data[]
// We need to search backwards to find the rule header

static __always_inline u64 extract_rule_handle_precise(void *expr)
{
    if (!expr)
        return 0;

    // Method 1: Try to find rule header by searching backwards
    // We search for a valid handle (non-zero, < 0x100000) at offset 16
    // and verify with dlen at offset 24

    #pragma unroll
    for (int search_offset = 32; search_offset <= 512; search_offset += 8) {
        void *potential_rule = (char *)expr - search_offset;

        u64 handle = 0;
        u32 dlen = 0;
        u32 udata_len = 0;

        // Read handle at offset 16 from potential_rule
        if (bpf_probe_read_kernel(&handle, sizeof(handle),
                                   (char *)potential_rule + 16) != 0)
            continue;

        // Validate handle: must be reasonable value
        if (handle == 0 || handle >= 0x100000 || handle == 0xFFFFFFFFFFFFFFFFULL)
            continue;

        // Read dlen at offset 24 to verify
        if (bpf_probe_read_kernel(&dlen, sizeof(dlen),
                                   (char *)potential_rule + 24) != 0)
            continue;

        // Validate dlen: should be reasonable (typically < 4096 bytes)
        if (dlen == 0 || dlen > 4096)
            continue;

        // Read udata_len at offset 28
        if (bpf_probe_read_kernel(&udata_len, sizeof(udata_len),
                                   (char *)potential_rule + 28) != 0)
            continue;

        // udata_len should be small or 0
        if (udata_len > 1024)
            continue;

        // Verify that expr is within [rule->data, rule->data + dlen]
        u64 expr_offset = (u64)expr - (u64)potential_rule - 32;
        if (expr_offset < dlen) {
            // Found valid rule!
            return handle;
        }
    }

    // Method 2: Fallback to old method for compatibility
    s32 offsets[] = {-16, -24, -32, -40, -48, -56, -64, -72, -80, -96, -112, -128};

    #pragma unroll
    for (int i = 0; i < 12; i++) {
        u64 potential_handle = 0;

        if (bpf_probe_read_kernel(&potential_handle, sizeof(potential_handle),
                                   (char *)expr + offsets[i]) == 0) {
            if (potential_handle > 0 &&
                potential_handle < 0x100000 &&
                potential_handle != 0xFFFFFFFFFFFFFFFFULL) {
                return potential_handle;
            }
        }
    }

    return 0;
}

static __always_inline void extract_packet_info(void *pkt, struct skb_info *info)
{
    if (!pkt)
        return;

    void *skb = NULL;
    bpf_probe_read_kernel(&skb, sizeof(skb), pkt);
    if (!skb)
        return;

    void *ip_header = NULL;
    bpf_probe_read_kernel(&ip_header, sizeof(ip_header), (char *)skb + 0xd0);

    if (!ip_header)
        return;

    u8 ihl_version = 0;
    u8 protocol = 0;
    u32 saddr = 0;
    u32 daddr = 0;

    bpf_probe_read_kernel(&ihl_version, sizeof(ihl_version), ip_header);
    u8 version = (ihl_version >> 4) & 0x0F;

    if (version != 4)
        return;

    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)ip_header + 9);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (char *)ip_header + 12);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (char *)ip_header + 16);

    if (protocol == 0 || protocol > 150)
        return;

    info->protocol = protocol;
    info->src_ip = saddr;
    info->dst_ip = daddr;

    if (protocol == 6 || protocol == 17) {
        u8 ihl = (ihl_version & 0x0F) * 4;
        void *trans_header = (char *)ip_header + ihl;

        u16 sport = 0;
        u16 dport = 0;

        bpf_probe_read_kernel(&sport, sizeof(sport), trans_header);
        bpf_probe_read_kernel(&dport, sizeof(dport), (char *)trans_header + 2);

        info->src_port = bpf_ntohs(sport);
        info->dst_port = bpf_ntohs(dport);
    }
}

// ============================================
// HOOK 1: nft_do_chain
// ============================================
int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *pkt = (void *)PT_REGS_PARM1(ctx);
    void *priv = (void *)PT_REGS_PARM2(ctx);
    void *skb = NULL;
    void *state = NULL;
    u8 hook = 255;
    u8 pf = 0;

    if (!pkt)
        return 0;

    bpf_probe_read_kernel(&skb, sizeof(skb), pkt);
    bpf_probe_read_kernel(&state, sizeof(state), (char *)pkt + 8);

    if (state) {
        bpf_probe_read_kernel(&hook, sizeof(hook), state);
        bpf_probe_read_kernel(&pf, sizeof(pf), (char *)state + 1);
    }

    u8 depth = 0;
    u8 *cur_depth = depth_map.lookup(&tid);
    if (cur_depth) {
        depth = *cur_depth + 1;
    }
    depth_map.update(&tid, &depth);

    struct skb_info info = {};
    info.skb_addr = (u64)skb;
    info.chain_addr = (u64)priv;
    info.hook = hook;
    info.pf = pf;
    info.rule_seq = 0;           // Reset rule counter
    info.last_rule_handle = 0;   // Reset last seen handle
    info.protocol = 0;
    info.src_ip = 0;
    info.dst_ip = 0;
    info.src_port = 0;
    info.dst_port = 0;

    extract_packet_info(pkt, &info);
    skb_map.update(&tid, &info);

    return 0;
}

int kretprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    struct skb_info *info = skb_map.lookup(&tid);
    if (!info)
        return 0;

    u8 *depth_ptr = depth_map.lookup(&tid);
    u32 verdict = decode_verdict(rax_s32, rax_u32);

    struct nft_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.skb_addr = info->skb_addr;
    evt.chain_addr = info->chain_addr;
    evt.expr_addr = 0;
    evt.regs_addr = 0;
    evt.hook = info->hook;
    evt.pf = info->pf;
    evt.chain_depth = depth_ptr ? *depth_ptr : 0;
    evt.trace_type = 0;
    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;
    evt.rule_seq = info->rule_seq;
    evt.rule_handle = 0;

    evt.protocol = info->protocol;
    evt.src_ip = info->src_ip;
    evt.dst_ip = info->dst_ip;
    evt.src_port = info->src_port;
    evt.dst_port = info->dst_port;

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    } else {
        evt.queue_num = 0;
        evt.has_queue_bypass = 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    if (depth_ptr && *depth_ptr > 0) {
        u8 new_depth = *depth_ptr - 1;
        depth_map.update(&tid, &new_depth);
    } else {
        skb_map.delete(&tid);
        depth_map.delete(&tid);
    }

    return 0;
}

// ============================================
// HOOK 2: nft_immediate_eval - IMPROVED
// ============================================
int kprobe__nft_immediate_eval(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *expr = (void *)PT_REGS_PARM1(ctx);
    void *regs = (void *)PT_REGS_PARM2(ctx);

    if (!expr)
        return 0;

    struct skb_info *info = skb_map.lookup(&tid);
    if (!info)
        return 0;

    // IMPROVEMENT: Extract rule handle first
    u64 rule_handle = extract_rule_handle_precise(expr);

    // IMPROVEMENT: Only increment rule_seq when we see a NEW rule
    // (i.e., when handle changes)
    if (rule_handle != 0 && rule_handle != info->last_rule_handle) {
        info->rule_seq++;
        info->last_rule_handle = rule_handle;
    }

    // Extract verdict code from expression
    s32 verdict_code = 0;
    int read_ok = 0;

    // Try multiple offsets for verdict code (struct nft_immediate_expr->dreg_data)
    if (bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 8) == 0) {
        if ((verdict_code >= -5 && verdict_code <= 5) ||
            (verdict_code >= 0x10000 && verdict_code <= 0x1FFFF)) {
            read_ok = 1;
        }
    }

    if (!read_ok) {
        if (bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 16) == 0) {
            if ((verdict_code >= -5 && verdict_code <= 5) ||
                (verdict_code >= 0x10000 && verdict_code <= 0x1FFFF)) {
                read_ok = 1;
            }
        }
    }

    if (!read_ok) {
        bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 24);
    }

    struct nft_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.skb_addr = info->skb_addr;
    evt.chain_addr = info->chain_addr;
    evt.expr_addr = (u64)expr;
    evt.regs_addr = (u64)regs;
    evt.hook = info->hook;
    evt.pf = info->pf;

    u8 *depth_ptr = depth_map.lookup(&tid);
    evt.chain_depth = depth_ptr ? *depth_ptr : 0;

    evt.trace_type = 1;
    evt.verdict_raw = verdict_code;
    evt.verdict = decode_verdict(verdict_code, (u32)verdict_code);
    evt.rule_seq = info->rule_seq;      // Now reflects actual rule index
    evt.rule_handle = rule_handle;      // Precise handle

    evt.protocol = info->protocol;
    evt.src_ip = info->src_ip;
    evt.dst_ip = info->dst_ip;
    evt.src_port = info->src_port;
    evt.dst_port = info->dst_port;

    if (evt.verdict == 3u) {
        evt.queue_num = ((u32)verdict_code >> 16) & 0xFFFFu;
        evt.has_queue_bypass = (((u32)verdict_code & 0x8000u) ? 1 : 0);
    } else {
        evt.queue_num = 0;
        evt.has_queue_bypass = 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// ============================================
// HOOK 3: nf_hook_slow
// ============================================
int kretprobe__nf_hook_slow(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    u32 verdict = decode_verdict(rax_s32, rax_u32);

    struct nft_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.trace_type = 2;
    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;
    evt.hook = 255;
    evt.pf = 0;
    evt.chain_depth = 0;
    evt.skb_addr = 0;
    evt.chain_addr = 0;
    evt.expr_addr = 0;
    evt.regs_addr = 0;
    evt.rule_seq = 0;
    evt.rule_handle = 0;
    evt.protocol = 0;
    evt.src_ip = 0;
    evt.dst_ip = 0;
    evt.src_port = 0;
    evt.dst_port = 0;

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    } else {
        evt.queue_num = 0;
        evt.has_queue_bypass = 0;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}
