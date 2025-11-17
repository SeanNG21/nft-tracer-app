// SPDX-License-Identifier: GPL-2.0
// Multi-Function NFT Tracer - Like pwru/cilium with NFT verdict tracking
// Traces ALL kernel functions handling sk_buff + NFT verdicts

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

// Event types
#define EVENT_FUNCTION  0  // Generic kernel function handling sk_buff
#define EVENT_NFT_CHAIN 1  // NFT chain entry/exit
#define EVENT_NFT_RULE  2  // NFT rule evaluation (nft_immediate_eval)
#define EVENT_NF_HOOK   3  // Netfilter hook verdict

// Unified trace event - captures everything
struct trace_event {
    u64 timestamp;
    u64 skb_addr;

    u32 cpu_id;
    u32 pid;

    u8 event_type;
    u8 hook;
    u8 pf;
    u8 protocol;

    // Packet info
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 length;

    // NFT specific
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
    u64 func_addr;  // Function address for symbol lookup
    char func_name[64];  // Will be populated by userspace

    char comm[16];
};

// Packet info storage per SKB
struct packet_info {
    u64 skb_addr;
    u64 first_seen;
    u32 function_count;  // How many functions this packet went through

    u8 protocol;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 length;

    // NFT context
    u64 chain_addr;
    u8 hook;
    u8 pf;
    u16 rule_seq;
    u8 chain_depth;
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(packet_map, u64, struct packet_info, 10240);  // SKB addr -> packet info
BPF_HASH(tid_map, u64, struct packet_info, 10240);      // TID -> packet info (for NFT hooks)
BPF_HASH(depth_map, u64, u8, 10240);                     // TID -> chain depth

// Helper: decode NFT verdict
static __always_inline u32 decode_verdict(s32 raw_ret, u32 raw_u32)
{
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;  // CONTINUE
            case -2: return 11;  // RETURN
            case -3: return 12;  // JUMP
            case -4: return 13;  // GOTO
            case -5: return 14;  // BREAK
            default: return 0;
        }
    }

    u32 verdict = raw_u32 & 0xFFu;
    if (verdict > 5) return 255;
    return verdict;
}

// Helper: safe comm read
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

// Helper: extract rule handle from NFT expr
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
static __always_inline void extract_packet_info(struct sk_buff *skb, struct packet_info *pkt)
{
    if (!skb)
        return;

    pkt->skb_addr = (u64)skb;

    // Get packet length
    u32 len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), (char *)skb + 0x88);
    pkt->length = len;

    // Get IP header
    void *ip_header = NULL;
    bpf_probe_read_kernel(&ip_header, sizeof(ip_header), (char *)skb + 0xd0);

    if (!ip_header)
        return;

    u8 ihl_version = 0;
    bpf_probe_read_kernel(&ihl_version, sizeof(ihl_version), ip_header);
    u8 version = (ihl_version >> 4) & 0x0F;

    if (version != 4)
        return;

    u8 protocol = 0;
    u32 saddr = 0;
    u32 daddr = 0;

    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)ip_header + 9);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (char *)ip_header + 12);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (char *)ip_header + 16);

    pkt->protocol = protocol;
    pkt->src_ip = saddr;
    pkt->dst_ip = daddr;

    // Extract ports for TCP/UDP
    if (protocol == 6 || protocol == 17) {
        u8 ihl = (ihl_version & 0x0F) * 4;
        void *trans_header = (char *)ip_header + ihl;

        u16 sport = 0;
        u16 dport = 0;

        bpf_probe_read_kernel(&sport, sizeof(sport), trans_header);
        bpf_probe_read_kernel(&dport, sizeof(dport), (char *)trans_header + 2);

        pkt->src_port = bpf_ntohs(sport);
        pkt->dst_port = bpf_ntohs(dport);
    }
}

// Helper: extract packet info from nft_pktinfo (for NFT hooks)
static __always_inline void extract_from_nft_pktinfo(void *pkt_ptr, struct packet_info *pkt)
{
    if (!pkt_ptr)
        return;

    void *skb = NULL;
    void *state = NULL;

    bpf_probe_read_kernel(&skb, sizeof(skb), pkt_ptr);
    bpf_probe_read_kernel(&state, sizeof(state), (char *)pkt_ptr + 8);

    if (skb) {
        extract_packet_info((struct sk_buff *)skb, pkt);
    }

    if (state) {
        bpf_probe_read_kernel(&pkt->hook, sizeof(pkt->hook), state);
        bpf_probe_read_kernel(&pkt->pf, sizeof(pkt->pf), (char *)state + 1);
    }
}

// =============================================================================
// GENERIC FUNCTION TRACER - Attaches to ALL kernel functions with sk_buff param
// =============================================================================
int trace_skb_function(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    // Get or create packet info
    struct packet_info *pkt = packet_map.lookup(&skb_addr);
    struct packet_info new_pkt = {};

    if (!pkt) {
        new_pkt.skb_addr = skb_addr;
        new_pkt.first_seen = bpf_ktime_get_ns();
        new_pkt.function_count = 0;
        extract_packet_info(skb, &new_pkt);
        packet_map.update(&skb_addr, &new_pkt);
        pkt = &new_pkt;
    }

    // Increment function counter
    pkt->function_count++;
    packet_map.update(&skb_addr, pkt);

    // Emit trace event
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.skb_addr = skb_addr;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_FUNCTION;

    // Get function address (for symbol lookup in userspace)
    evt.func_addr = PT_REGS_IP(ctx);

    // Copy packet info
    evt.protocol = pkt->protocol;
    evt.src_ip = pkt->src_ip;
    evt.dst_ip = pkt->dst_ip;
    evt.src_port = pkt->src_port;
    evt.dst_port = pkt->dst_port;
    evt.length = pkt->length;
    evt.hook = pkt->hook;
    evt.pf = pkt->pf;

    read_comm_safe(evt.comm, sizeof(evt.comm));

    events.perf_submit(ctx, &evt, sizeof(evt));

    // Store in tid_map for NFT hooks to use
    tid_map.update(&tid, pkt);

    return 0;
}

// =============================================================================
// NFT HOOKS - Specialized tracking for NFT chains and rules
// =============================================================================

int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *pkt_ptr = (void *)PT_REGS_PARM1(ctx);
    void *priv = (void *)PT_REGS_PARM2(ctx);

    if (!pkt_ptr)
        return 0;

    // Track chain depth
    u8 depth = 0;
    u8 *cur_depth = depth_map.lookup(&tid);
    if (cur_depth) {
        depth = *cur_depth + 1;
    }
    depth_map.update(&tid, &depth);

    // Get or create packet info
    struct packet_info *pkt = tid_map.lookup(&tid);
    struct packet_info new_pkt = {};

    if (!pkt) {
        extract_from_nft_pktinfo(pkt_ptr, &new_pkt);
        new_pkt.chain_addr = (u64)priv;
        new_pkt.chain_depth = depth;
        new_pkt.rule_seq = 0;
        tid_map.update(&tid, &new_pkt);
        pkt = &new_pkt;
    } else {
        pkt->chain_addr = (u64)priv;
        pkt->chain_depth = depth;
        tid_map.update(&tid, pkt);
    }

    // Emit NFT chain entry event
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.skb_addr = pkt->skb_addr;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_NFT_CHAIN;

    evt.chain_addr = (u64)priv;
    evt.chain_depth = depth;
    evt.hook = pkt->hook;
    evt.pf = pkt->pf;

    evt.protocol = pkt->protocol;
    evt.src_ip = pkt->src_ip;
    evt.dst_ip = pkt->dst_ip;
    evt.src_port = pkt->src_port;
    evt.dst_port = pkt->dst_port;
    evt.length = pkt->length;

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

int kretprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    struct packet_info *pkt = tid_map.lookup(&tid);
    if (!pkt)
        return 0;

    u8 *depth_ptr = depth_map.lookup(&tid);
    u32 verdict = decode_verdict(rax_s32, rax_u32);

    // Emit NFT chain exit event with verdict
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.skb_addr = pkt->skb_addr;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_NFT_CHAIN;

    evt.chain_addr = pkt->chain_addr;
    evt.chain_depth = depth_ptr ? *depth_ptr : 0;
    evt.hook = pkt->hook;
    evt.pf = pkt->pf;
    evt.rule_seq = pkt->rule_seq;

    evt.protocol = pkt->protocol;
    evt.src_ip = pkt->src_ip;
    evt.dst_ip = pkt->dst_ip;
    evt.src_port = pkt->src_port;
    evt.dst_port = pkt->dst_port;
    evt.length = pkt->length;

    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    // Update depth
    if (depth_ptr && *depth_ptr > 0) {
        u8 new_depth = *depth_ptr - 1;
        depth_map.update(&tid, &new_depth);
    } else {
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

    struct packet_info *pkt = tid_map.lookup(&tid);
    if (!pkt)
        return 0;

    pkt->rule_seq++;
    tid_map.update(&tid, pkt);

    // Read verdict from expr
    s32 verdict_code = 0;
    bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 8);

    u64 rule_handle = extract_rule_handle(expr);

    // Emit NFT rule event
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.skb_addr = pkt->skb_addr;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_NFT_RULE;

    evt.chain_addr = pkt->chain_addr;
    evt.expr_addr = (u64)expr;
    evt.chain_depth = pkt->chain_depth;
    evt.hook = pkt->hook;
    evt.pf = pkt->pf;
    evt.rule_seq = pkt->rule_seq;
    evt.rule_handle = rule_handle;

    evt.protocol = pkt->protocol;
    evt.src_ip = pkt->src_ip;
    evt.dst_ip = pkt->dst_ip;
    evt.src_port = pkt->src_port;
    evt.dst_port = pkt->dst_port;
    evt.length = pkt->length;

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

    struct packet_info *pkt = tid_map.lookup(&tid);

    // Emit NF hook verdict event
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_NF_HOOK;
    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;

    if (pkt) {
        evt.skb_addr = pkt->skb_addr;
        evt.hook = pkt->hook;
        evt.pf = pkt->pf;
        evt.protocol = pkt->protocol;
        evt.src_ip = pkt->src_ip;
        evt.dst_ip = pkt->dst_ip;
        evt.src_port = pkt->src_port;
        evt.dst_port = pkt->dst_port;
        evt.length = pkt->length;
    }

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Cleanup function for aged SKB entries (called periodically by userspace)
int cleanup_old_skbs(struct pt_regs *ctx)
{
    // This would be triggered by userspace timer
    // For now, we rely on map size limits and LRU eviction
    return 0;
}
