// SPDX-License-Identifier: GPL-2.0
// Multi-Kprobe SKB Tracer - pwru-style comprehensive tracing
// Supports tracing 100+ kernel functions handling sk_buff
// Uses macro-based approach for efficiency

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

// Event types
#define EVENT_TYPE_FUNCTION_CALL 0
#define EVENT_TYPE_NFT_CHAIN     1
#define EVENT_TYPE_NFT_RULE      2
#define EVENT_TYPE_NF_VERDICT    3
#define EVENT_TYPE_DROP          4

// Simplified event structure for high-volume tracing
struct trace_event {
    u64 timestamp;
    u64 skb_addr;
    u64 func_addr;  // Function address for name resolution in userspace

    u32 cpu_id;
    u32 pid;

    u8 event_type;
    u8 param_position;  // Which parameter position was sk_buff (1-5)
    u8 hook;
    u8 protocol;

    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 length;

    // NFT specific fields (only for NFT events)
    u64 chain_addr;
    u64 expr_addr;
    u8 chain_depth;
    u16 rule_seq;

    // Verdict info
    s32 verdict_raw;
    u32 verdict;

    char comm[16];
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(skb_map, u64, struct trace_event, 10240);  // Track SKBs across functions
BPF_HASH(depth_map, u64, u8, 10240);  // NFT chain depth tracking

// Configuration (set by userspace)
struct config {
    u32 track_drops;      // Track kfree_skb events
    u32 sample_rate;      // Sample 1 out of N packets (0 = all)
    u32 filter_proto;     // Filter by protocol (0 = all)
    u32 filter_port;      // Filter by port (0 = all)
};

BPF_HASH(config_map, u32, struct config, 1);

// Helper: decode NFT verdict
static __always_inline u32 decode_verdict(s32 raw_ret, u32 raw_u32)
{
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;  // NF_DROP
            case -2: return 11;  // NF_ACCEPT
            case -3: return 12;  // NF_STOLEN
            case -4: return 13;  // NF_QUEUE
            case -5: return 14;  // NF_REPEAT
            default: return 0;
        }
    }

    u32 verdict = raw_u32 & 0xFFu;
    if (verdict > 5) return 255;
    return verdict;
}

// Helper: read comm safely
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

// Helper: extract packet info from sk_buff
static __always_inline int extract_packet_info(struct sk_buff *skb, struct trace_event *evt)
{
    if (!skb)
        return -1;

    evt->skb_addr = (u64)skb;

    // Get packet length
    u32 len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), (char *)skb + 0x88);
    evt->length = len;

    // Get IP header
    void *ip_header = NULL;
    bpf_probe_read_kernel(&ip_header, sizeof(ip_header), (char *)skb + 0xd0);

    if (!ip_header)
        return 0;

    // Read IP header fields
    u8 ihl_version = 0;
    u8 protocol = 0;
    u32 saddr = 0;
    u32 daddr = 0;

    bpf_probe_read_kernel(&ihl_version, sizeof(ihl_version), ip_header);
    u8 version = (ihl_version >> 4) & 0x0F;

    if (version != 4)
        return 0;

    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)ip_header + 9);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (char *)ip_header + 12);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (char *)ip_header + 16);

    evt->protocol = protocol;
    evt->src_ip = saddr;
    evt->dst_ip = daddr;

    // Extract L4 ports (TCP/UDP)
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

    return 0;
}

// Helper: check if packet should be sampled
static __always_inline int should_sample(struct trace_event *evt)
{
    u32 cfg_key = 0;
    struct config *cfg = config_map.lookup(&cfg_key);

    if (!cfg)
        return 1;  // No config, trace everything

    // Filter by protocol
    if (cfg->filter_proto != 0 && evt->protocol != cfg->filter_proto)
        return 0;

    // Filter by port
    if (cfg->filter_port != 0) {
        if (evt->src_port != cfg->filter_port && evt->dst_port != cfg->filter_port)
            return 0;
    }

    // Sample rate
    if (cfg->sample_rate > 1) {
        u32 rand = bpf_get_prandom_u32();
        if ((rand % cfg->sample_rate) != 0)
            return 0;
    }

    return 1;
}

// =============================================================================
// GENERIC SKB TRACER - Handles multiple parameter positions (pwru-style)
// =============================================================================

// Macro to generate kprobe handlers for different parameter positions
// This allows us to attach to functions where sk_buff is in different positions

#define DEFINE_SKB_KPROBE(POS) \
int trace_skb_##POS(struct pt_regs *ctx) \
{ \
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##POS(ctx); \
    if (!skb) \
        return 0; \
    \
    struct trace_event evt = {}; \
    evt.timestamp = bpf_ktime_get_ns(); \
    evt.cpu_id = bpf_get_smp_processor_id(); \
    evt.pid = bpf_get_current_pid_tgid() >> 32; \
    evt.event_type = EVENT_TYPE_FUNCTION_CALL; \
    evt.param_position = POS; \
    evt.func_addr = PT_REGS_IP(ctx); \
    \
    if (extract_packet_info(skb, &evt) != 0) \
        return 0; \
    \
    if (!should_sample(&evt)) \
        return 0; \
    \
    read_comm_safe(evt.comm, sizeof(evt.comm)); \
    \
    /* Store in map for NFT correlation */ \
    u64 tid = bpf_get_current_pid_tgid(); \
    skb_map.update(&tid, &evt); \
    \
    events.perf_submit(ctx, &evt, sizeof(evt)); \
    return 0; \
}

// Generate handlers for parameter positions 1-5 (like pwru)
DEFINE_SKB_KPROBE(1)
DEFINE_SKB_KPROBE(2)
DEFINE_SKB_KPROBE(3)
DEFINE_SKB_KPROBE(4)
DEFINE_SKB_KPROBE(5)

// =============================================================================
// NFT-SPECIFIC HOOKS (Enhanced versions)
// =============================================================================

int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *pkt = (void *)PT_REGS_PARM1(ctx);
    void *priv = (void *)PT_REGS_PARM2(ctx);

    if (!pkt)
        return 0;

    // Track chain depth
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

    // Extract SKB from nft_pktinfo
    void *skb = NULL;
    void *state = NULL;

    bpf_probe_read_kernel(&skb, sizeof(skb), pkt);
    bpf_probe_read_kernel(&state, sizeof(state), (char *)pkt + 8);

    if (skb) {
        extract_packet_info(skb, &evt);
    }

    if (state) {
        bpf_probe_read_kernel(&evt.hook, sizeof(evt.hook), state);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));

    // Store for kretprobe
    skb_map.update(&tid, &evt);

    // Don't emit event here - wait for kretprobe with verdict
    return 0;
}

int kretprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    struct trace_event *stored = skb_map.lookup(&tid);
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
        evt.protocol = stored->protocol;
        evt.src_ip = stored->src_ip;
        evt.dst_ip = stored->dst_ip;
        evt.src_port = stored->src_port;
        evt.dst_port = stored->dst_port;
        evt.length = stored->length;
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));

    // Emit chain exit event with verdict
    events.perf_submit(ctx, &evt, sizeof(evt));

    // Decrease depth or cleanup
    if (depth_ptr && *depth_ptr > 0) {
        u8 new_depth = *depth_ptr - 1;
        depth_map.update(&tid, &new_depth);
    } else {
        skb_map.delete(&tid);
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

    struct trace_event *stored = skb_map.lookup(&tid);
    if (!stored)
        return 0;

    stored->rule_seq++;

    // Read verdict code from expression
    s32 verdict_code = 0;
    bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 8);

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_RULE;

    evt.skb_addr = stored->skb_addr;
    evt.chain_addr = stored->chain_addr;
    evt.expr_addr = (u64)expr;
    evt.hook = stored->hook;
    evt.chain_depth = stored->chain_depth;
    evt.rule_seq = stored->rule_seq;

    evt.protocol = stored->protocol;
    evt.src_ip = stored->src_ip;
    evt.dst_ip = stored->dst_ip;
    evt.src_port = stored->src_port;
    evt.dst_port = stored->dst_port;
    evt.length = stored->length;

    evt.verdict_raw = verdict_code;
    evt.verdict = decode_verdict(verdict_code, (u32)verdict_code);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// =============================================================================
// DROP TRACKING (kfree_skb_reason)
// =============================================================================

int kprobe__kfree_skb_reason(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    u32 reason = (u32) PT_REGS_PARM2(ctx);  // Drop reason (kernel >= 5.17)

    if (!skb)
        return 0;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.event_type = EVENT_TYPE_DROP;
    evt.verdict = reason;  // Store drop reason in verdict field
    evt.func_addr = PT_REGS_IP(ctx);

    extract_packet_info(skb, &evt);
    read_comm_safe(evt.comm, sizeof(evt.comm));

    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Legacy kfree_skb (for older kernels)
int kprobe__kfree_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);

    if (!skb)
        return 0;

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.event_type = EVENT_TYPE_DROP;
    evt.func_addr = PT_REGS_IP(ctx);

    extract_packet_info(skb, &evt);
    read_comm_safe(evt.comm, sizeof(evt.comm));

    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}
