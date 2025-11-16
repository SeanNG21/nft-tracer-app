// SPDX-License-Identifier: GPL-2.0
// Full Mode Tracer - Integrated SKB + NFT tracking
// Backend version - compatible with app.py
// FIXED: No duplicate chain_exit, Function IP tracking

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

// Event types for unified tracing
#define EVENT_TYPE_FUNCTION_CALL 0
#define EVENT_TYPE_NFT_CHAIN     1
#define EVENT_TYPE_NFT_RULE      2
#define EVENT_TYPE_NF_VERDICT    3

// Unified event structure matching backend expectations
struct trace_event {
    u64 timestamp;
    u64 skb_addr;
    u32 cpu_id;
    u32 pid;
    
    u8 event_type;
    u8 hook;
    u8 pf;
    u8 protocol;
    
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 length;
    
    // NFT specific fields
    u64 chain_addr;
    u64 expr_addr;
    u8 chain_depth;
    u16 rule_seq;
    u64 rule_handle;
    
    // Verdict info
    s32 verdict_raw;
    u32 verdict;
    u16 queue_num;
    u8 has_queue_bypass;
    
    // Function tracking
    u64 func_ip;  // NEW: Function instruction pointer for name lookup
    char function_name[64];
    char comm[16];

    // Rule metadata (from kernel)
    char chain_name[32];
    char table_name[32];
    char rule_comment[64];
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(skb_info_map, u64, struct trace_event, 10240);
BPF_HASH(depth_map, u64, u8, 10240);

// Helper: decode verdict
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

// Helper: read comm
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

// Helper: Extract chain name from nft_chain struct
// Simplified version to avoid BPF complexity limits
static __always_inline void extract_chain_name(void *chain, char *name_buf, u32 buf_size)
{
    #pragma unroll
    for (int i = 0; i < 32 && i < buf_size; i++) {
        name_buf[i] = 0;
    }

    if (!chain)
        return;

    // Try fewer offsets to reduce complexity
    s32 name_offsets[] = {48, 56, 64, 72, 80};

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        char temp_name[32] = {};

        if (bpf_probe_read_kernel(&temp_name, sizeof(temp_name),
                                   (char *)chain + name_offsets[i]) == 0) {
            // Simple validation: first char must be alphabetic
            // and second char must not be null (min 2 chars)
            if ((temp_name[0] >= 'A' && temp_name[0] <= 'Z') ||
                (temp_name[0] >= 'a' && temp_name[0] <= 'z')) {
                if (temp_name[1] != 0) {
                    // Copy to output
                    #pragma unroll
                    for (int j = 0; j < 31 && j < buf_size - 1; j++) {
                        name_buf[j] = temp_name[j];
                        if (temp_name[j] == 0)
                            break;
                    }
                    return;
                }
            }
        }
    }
}

// Helper: Extract table name from nft_table struct
// Simplified version to avoid BPF complexity limits
static __always_inline void extract_table_name(void *chain, char *name_buf, u32 buf_size)
{
    #pragma unroll
    for (int i = 0; i < 32 && i < buf_size; i++) {
        name_buf[i] = 0;
    }

    if (!chain)
        return;

    // Try fewer table pointer offsets
    s32 table_ptr_offsets[] = {24, 32, 40, 48};

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        void *table = NULL;

        if (bpf_probe_read_kernel(&table, sizeof(table),
                                   (char *)chain + table_ptr_offsets[i]) == 0 && table) {
            // Validate table pointer (should be kernel address)
            if ((u64)table < 0xffff000000000000ULL)
                continue;

            // Try fewer name offsets
            s32 name_offsets[] = {16, 24, 32, 40};

            #pragma unroll
            for (int j = 0; j < 4; j++) {
                char temp_name[32] = {};

                if (bpf_probe_read_kernel(&temp_name, sizeof(temp_name),
                                           (char *)table + name_offsets[j]) == 0) {
                    // Simple validation
                    if ((temp_name[0] >= 'A' && temp_name[0] <= 'Z') ||
                        (temp_name[0] >= 'a' && temp_name[0] <= 'z')) {
                        if (temp_name[1] != 0) {
                            #pragma unroll
                            for (int k = 0; k < 31 && k < buf_size - 1; k++) {
                                name_buf[k] = temp_name[k];
                                if (temp_name[k] == 0)
                                    break;
                            }
                            return;
                        }
                    }
                }
            }
        }
    }
}

// Helper: Extract rule comment/userdata
static __always_inline void extract_rule_comment(void *expr, char *comment_buf, u32 buf_size)
{
    #pragma unroll
    for (int i = 0; i < 64 && i < buf_size; i++) {
        comment_buf[i] = 0;
    }
    // Userdata extraction is complex, leave empty for now
}

// Helper: extract rule handle
static __always_inline u64 extract_rule_handle(void *expr)
{
    if (!expr)
        return 0;
    
    s32 offsets[] = {-16, -24, -32, -40, -48, -56, -64, -72, -80, -96};
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
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

// Helper: extract packet info from sk_buff
static __always_inline void extract_packet_info_from_skb(void *skb, struct trace_event *evt)
{
    if (!skb)
        return;
    
    evt->skb_addr = (u64)skb;
    
    // Get length
    u32 len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), (char *)skb + 0x88);
    evt->length = len;
    
    // Get IP header pointer
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
    
    evt->protocol = protocol;
    evt->src_ip = saddr;
    evt->dst_ip = daddr;
    
    // Extract ports
    if (protocol == 6 || protocol == 17) {
        u8 ihl = (ihl_version & 0x0F) * 4;
        void *trans_header = (char *)ip_header + ihl;
        
        u16 sport = 0;
        u16 dport = 0;
        
        bpf_probe_read_kernel(&sport, sizeof(sport), trans_header);
        bpf_probe_read_kernel(&dport, sizeof(dport), (char *)trans_header + 2);
        
        evt->src_port = bpf_ntohs(sport);
        evt->dst_port = bpf_ntohs(dport);
    }
}

// Helper: extract packet info from nft_pktinfo
static __always_inline void extract_packet_info_from_pkt(void *pkt, struct trace_event *evt)
{
    if (!pkt)
        return;
    
    void *skb = NULL;
    void *state = NULL;
    
    bpf_probe_read_kernel(&skb, sizeof(skb), pkt);
    bpf_probe_read_kernel(&state, sizeof(state), (char *)pkt + 8);
    
    if (skb) {
        extract_packet_info_from_skb(skb, evt);
    }
    
    if (state) {
        bpf_probe_read_kernel(&evt->hook, sizeof(evt->hook), state);
        bpf_probe_read_kernel(&evt->pf, sizeof(evt->pf), (char *)state + 1);
    }
}

// ==============================================
// GENERIC SKB FUNCTION TRACER
// ==============================================
int trace_skb_func(struct pt_regs *ctx, struct sk_buff *skb)
{
    u64 tid = bpf_get_current_pid_tgid();
    
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_FUNCTION_CALL;
    
    // CRITICAL: Get function IP for name lookup in userspace
    evt.func_ip = PT_REGS_IP(ctx);
    
    extract_packet_info_from_skb(skb, &evt);
    read_comm_safe(evt.comm, sizeof(evt.comm));
    
    // Store in map for NFT hooks using TID as key (consistent with kretprobe)
    if (evt.skb_addr != 0) {
        skb_info_map.update(&tid, &evt);
    }
    
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ==============================================
// NFT HOOKS
// ==============================================

int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *pkt = (void *)PT_REGS_PARM1(ctx);
    void *priv = (void *)PT_REGS_PARM2(ctx);

    if (!pkt)
        return 0;

    u8 depth = 0;
    u8 *cur_depth = depth_map.lookup(&tid);
    if (cur_depth) {
        depth = *cur_depth + 1;
    }
    depth_map.update(&tid, &depth);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_CHAIN;
    evt.chain_addr = (u64)priv;
    evt.chain_depth = depth;

    extract_packet_info_from_pkt(pkt, &evt);
    read_comm_safe(evt.comm, sizeof(evt.comm));

    // NEW: Extract chain and table names
    extract_chain_name(priv, evt.chain_name, sizeof(evt.chain_name));
    extract_table_name(priv, evt.table_name, sizeof(evt.table_name));

    // Store with TID as key for kretprobe to retrieve
    if (evt.skb_addr != 0) {
        skb_info_map.update(&tid, &evt);
    }
    
    // FIX #1: DO NOT emit event here - wait for kretprobe to emit chain_exit with verdict
    // This eliminates duplicate chain_exit events
    return 0;
}

int kretprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    
    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    struct trace_event *stored = skb_info_map.lookup(&tid);
    u8 *depth_ptr = depth_map.lookup(&tid);
    u32 verdict = decode_verdict(rax_s32, rax_u32);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_CHAIN;
    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;
    evt.chain_depth = depth_ptr ? *depth_ptr : 0;
    
    if (stored) {
        evt.skb_addr = stored->skb_addr;
        evt.chain_addr = stored->chain_addr;
        evt.hook = stored->hook;
        evt.pf = stored->pf;
        evt.protocol = stored->protocol;
        evt.src_ip = stored->src_ip;
        evt.dst_ip = stored->dst_ip;
        evt.src_port = stored->src_port;
        evt.dst_port = stored->dst_port;
        evt.length = stored->length;

        // NEW: Copy chain and table names
        #pragma unroll
        for (int i = 0; i < 31; i++) {
            evt.chain_name[i] = stored->chain_name[i];
            evt.table_name[i] = stored->table_name[i];
        }
    }

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    
    // FIX #1: Only emit ONE chain_exit event (from kretprobe with verdict)
    events.perf_submit(ctx, &evt, sizeof(evt));

    if (depth_ptr && *depth_ptr > 0) {
        u8 new_depth = *depth_ptr - 1;
        depth_map.update(&tid, &new_depth);
    } else {
        skb_info_map.delete(&tid);
        depth_map.delete(&tid);
    }

    return 0;
}

int kprobe__nft_immediate_eval(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *expr = (void *)PT_REGS_PARM1(ctx);

    if (!expr)
        return 0;

    struct trace_event *stored = skb_info_map.lookup(&tid);
    if (!stored)
        return 0;

    stored->rule_seq++;

    s32 verdict_code = 0;
    bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 8);
    
    u64 rule_handle = extract_rule_handle(expr);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_RULE;
    
    evt.skb_addr = stored->skb_addr;
    evt.chain_addr = stored->chain_addr;
    evt.expr_addr = (u64)expr;
    evt.hook = stored->hook;
    evt.pf = stored->pf;
    evt.chain_depth = stored->chain_depth;
    evt.rule_seq = stored->rule_seq;
    evt.rule_handle = rule_handle;
    
    evt.protocol = stored->protocol;
    evt.src_ip = stored->src_ip;
    evt.dst_ip = stored->dst_ip;
    evt.src_port = stored->src_port;
    evt.dst_port = stored->dst_port;
    evt.length = stored->length;

    // NEW: Copy chain and table names from stored info
    #pragma unroll
    for (int i = 0; i < 31; i++) {
        evt.chain_name[i] = stored->chain_name[i];
        evt.table_name[i] = stored->table_name[i];
    }

    // NEW: Try to extract rule comment
    extract_rule_comment(expr, evt.rule_comment, sizeof(evt.rule_comment));

    evt.verdict_raw = verdict_code;
    evt.verdict = decode_verdict(verdict_code, (u32)verdict_code);

    if (evt.verdict == 3u) {
        evt.queue_num = ((u32)verdict_code >> 16) & 0xFFFFu;
        evt.has_queue_bypass = (((u32)verdict_code & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

int kretprobe__nf_hook_slow(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    
    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    u32 verdict = decode_verdict(rax_s32, rax_u32);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NF_VERDICT;
    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}