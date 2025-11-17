// SPDX-License-Identifier: GPL-2.0
// Multi-Function Tracer - Comprehensive network stack + NFT tracking
// Inspired by pwru/cilium but with integrated NFT verdict tracking
// Supports tracing 1000+ kernel functions + nftables rules

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/sock.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;
typedef signed long long s64;

// Event types
#define EVENT_TYPE_FUNCTION_CALL 0
#define EVENT_TYPE_NFT_CHAIN     1
#define EVENT_TYPE_NFT_RULE      2
#define EVENT_TYPE_NF_VERDICT    3

// Filtering configuration (populated by userspace)
struct filter_config {
    u32 filter_src_ip;      // 0 = no filter
    u32 filter_dst_ip;
    u16 filter_src_port;
    u16 filter_dst_port;
    u8  filter_protocol;    // 0 = no filter
    u8  track_skb_clones;   // Track SKB clones/copies
    u8  capture_stack;      // Capture stack traces
    u8  reserved;
};

// Packet metadata extracted from SKB
struct packet_meta {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;
    u8  hook;
    u8  pf;
    u8  flags;
    u32 length;
    u32 mark;
    u32 ifindex;
};

// Unified event structure
struct trace_event {
    u64 timestamp;
    u64 skb_addr;
    u32 cpu_id;
    u32 pid;

    u8 event_type;
    struct packet_meta meta;

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

    // Function tracking (for EVENT_TYPE_FUNCTION_CALL)
    u64 func_ip;          // Instruction pointer
    s64 stack_id;         // Stack trace ID (-1 if disabled)
    u64 param_second;     // Second parameter (for context)

    char comm[16];
};

// Context stored across kprobe/kretprobe pairs
struct func_context {
    u64 skb_addr;
    u64 func_ip;
    u64 enter_ts;
    struct packet_meta meta;
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(skb_info_map, u64, struct func_context, 10240);
BPF_HASH(depth_map, u64, u8, 10240);
BPF_HASH(filter_map, u32, struct filter_config, 1);  // Key 0 = global config
BPF_STACK_TRACE(stack_traces, 1024);

// Per-CPU scratch buffer for packet parsing (avoid eBPF stack limits)
BPF_PERCPU_ARRAY(scratch_buffer, struct trace_event, 1);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static __always_inline struct filter_config* get_filter_config()
{
    u32 key = 0;
    return filter_map.lookup(&key);
}

static __always_inline u32 decode_verdict(s32 raw_ret, u32 raw_u32)
{
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;  // NFT_CONTINUE
            case -2: return 11;  // NFT_BREAK
            case -3: return 12;  // NFT_DROP (critical!)
            case -4: return 13;  // NFT_RETURN
            case -5: return 14;  // NFT_JUMP
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

// Extract packet metadata from sk_buff
static __always_inline int extract_packet_meta_from_skb(struct sk_buff *skb, struct packet_meta *meta)
{
    if (!skb || !meta)
        return -1;

    // Initialize all fields
    __builtin_memset(meta, 0, sizeof(*meta));

    // Read SKB fields
    u16 protocol = 0;
    u32 len = 0;
    u32 mark = 0;

    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
    bpf_probe_read_kernel(&mark, sizeof(mark), &skb->mark);

    meta->length = len;
    meta->mark = mark;
    meta->protocol = (protocol >> 8) & 0xFF;  // Network to host order

    // Extract network device info
    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev) {
        u32 ifindex = 0;
        bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
        meta->ifindex = ifindex;
    }

    // Parse L3/L4 headers
    u8 *head = NULL;
    u16 mac_header = 0;
    u16 network_header = 0;

    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);

    if (!head || network_header == (u16)~0U)
        return 0;  // No network header

    void *nh = head + network_header;

    // Parse IP header
    if (meta->protocol == 0x08) {  // IPv4
        struct iphdr iph;
        bpf_probe_read_kernel(&iph, sizeof(iph), nh);

        meta->src_ip = __builtin_bswap32(iph.saddr);
        meta->dst_ip = __builtin_bswap32(iph.daddr);
        meta->protocol = iph.protocol;

        void *l4 = nh + (iph.ihl * 4);

        // Parse TCP/UDP
        if (iph.protocol == 6) {  // TCP
            struct tcphdr tcph;
            bpf_probe_read_kernel(&tcph, sizeof(tcph), l4);
            meta->src_port = __builtin_bswap16(tcph.source);
            meta->dst_port = __builtin_bswap16(tcph.dest);
            meta->flags = 0;  // Could extract TCP flags if needed
        } else if (iph.protocol == 17) {  // UDP
            struct udphdr udph;
            bpf_probe_read_kernel(&udph, sizeof(udph), l4);
            meta->src_port = __builtin_bswap16(udph.source);
            meta->dst_port = __builtin_bswap16(udph.dest);
        }
    }

    return 0;
}

// Check if packet matches filter criteria
static __always_inline bool packet_matches_filter(struct packet_meta *meta, struct filter_config *cfg)
{
    if (!cfg)
        return true;  // No filter = accept all

    // IP filtering
    if (cfg->filter_src_ip != 0 && meta->src_ip != cfg->filter_src_ip)
        return false;

    if (cfg->filter_dst_ip != 0 && meta->dst_ip != cfg->filter_dst_ip)
        return false;

    // Port filtering
    if (cfg->filter_src_port != 0 && meta->src_port != cfg->filter_src_port)
        return false;

    if (cfg->filter_dst_port != 0 && meta->dst_port != cfg->filter_dst_port)
        return false;

    // Protocol filtering
    if (cfg->filter_protocol != 0 && meta->protocol != cfg->filter_protocol)
        return false;

    return true;
}

// Extract rule handle from nft expression (heuristic)
static __always_inline u64 extract_rule_handle(void *expr)
{
    if (!expr)
        return 0;

    // Try common offsets where rule handle might be stored
    s32 offsets[] = {-16, -24, -32, -40, -48, -56, -64, -72, -80, -96};

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        u64 handle = 0;
        long ret = bpf_probe_read_kernel(&handle, sizeof(handle), expr + offsets[i]);
        if (ret == 0 && handle > 0 && handle < 0x100000) {
            return handle;
        }
    }

    return 0;
}

// ============================================================================
// GENERIC FUNCTION TRACER (Attachable to ANY SKB function)
// ============================================================================

// Generic kprobe handler - attached to all discovered SKB functions
// Supports up to 5 parameter positions (like pwru)
static __always_inline int trace_skb_generic(struct pt_regs *ctx, int param_pos)
{
    struct sk_buff *skb = NULL;

    // Read SKB from specified parameter position
    switch (param_pos) {
        case 1: skb = (struct sk_buff *)PT_REGS_PARM1(ctx); break;
        case 2: skb = (struct sk_buff *)PT_REGS_PARM2(ctx); break;
        case 3: skb = (struct sk_buff *)PT_REGS_PARM3(ctx); break;
        case 4: skb = (struct sk_buff *)PT_REGS_PARM4(ctx); break;
        case 5: skb = (struct sk_buff *)PT_REGS_PARM5(ctx); break;
        default: return 0;
    }

    if (!skb)
        return 0;

    u64 skb_addr = (u64)skb;

    // Extract packet metadata
    struct packet_meta meta = {};
    extract_packet_meta_from_skb(skb, &meta);

    // Apply filters
    struct filter_config *cfg = get_filter_config();
    if (!packet_matches_filter(&meta, cfg))
        return 0;

    // Get scratch buffer (per-CPU to avoid stack overflow)
    u32 zero = 0;
    struct trace_event *evt = scratch_buffer.lookup(&zero);
    if (!evt)
        return 0;

    // Fill event
    evt->timestamp = bpf_ktime_get_ns();
    evt->skb_addr = skb_addr;
    evt->cpu_id = bpf_get_smp_processor_id();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->event_type = EVENT_TYPE_FUNCTION_CALL;
    evt->func_ip = PT_REGS_IP(ctx);  // Instruction pointer for symbol lookup
    evt->stack_id = -1;
    evt->param_second = PT_REGS_PARM2(ctx);  // Capture 2nd param for context

    __builtin_memcpy(&evt->meta, &meta, sizeof(meta));
    read_comm_safe(evt->comm, sizeof(evt->comm));

    // Capture stack trace if enabled
    if (cfg && cfg->capture_stack) {
        evt->stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    }

    // Store context for potential kretprobe
    struct func_context fctx = {
        .skb_addr = skb_addr,
        .func_ip = evt->func_ip,
        .enter_ts = evt->timestamp,
    };
    __builtin_memcpy(&fctx.meta, &meta, sizeof(meta));
    skb_info_map.update(&skb_addr, &fctx);

    // Submit event
    events.perf_submit(ctx, evt, sizeof(*evt));

    return 0;
}

// Multiple kprobe entry points for different parameter positions
SEC("kprobe/skb_1")
int kprobe_skb_1(struct pt_regs *ctx) {
    return trace_skb_generic(ctx, 1);
}

SEC("kprobe/skb_2")
int kprobe_skb_2(struct pt_regs *ctx) {
    return trace_skb_generic(ctx, 2);
}

SEC("kprobe/skb_3")
int kprobe_skb_3(struct pt_regs *ctx) {
    return trace_skb_generic(ctx, 3);
}

SEC("kprobe/skb_4")
int kprobe_skb_4(struct pt_regs *ctx) {
    return trace_skb_generic(ctx, 4);
}

SEC("kprobe/skb_5")
int kprobe_skb_5(struct pt_regs *ctx) {
    return trace_skb_generic(ctx, 5);
}

// ============================================================================
// NFT-SPECIFIC TRACERS (Integrated verdict tracking)
// ============================================================================

// Trace nft_do_chain - Chain entry/exit with verdict
int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    void *pkt = (void *)PT_REGS_PARM1(ctx);
    if (!pkt)
        return 0;

    // Read sk_buff from nft_pktinfo.skb (offset 0)
    struct sk_buff *skb = NULL;
    bpf_probe_read_kernel(&skb, sizeof(skb), pkt);
    if (!skb)
        return 0;

    u64 skb_addr = (u64)skb;
    u64 tid = bpf_get_current_pid_tgid();

    // Extract packet metadata
    struct packet_meta meta = {};
    extract_packet_meta_from_skb(skb, &meta);

    // Apply filters
    struct filter_config *cfg = get_filter_config();
    if (!packet_matches_filter(&meta, cfg))
        return 0;

    // Store context for kretprobe
    struct func_context fctx = {
        .skb_addr = skb_addr,
        .func_ip = PT_REGS_IP(ctx),
        .enter_ts = bpf_ktime_get_ns(),
    };
    __builtin_memcpy(&fctx.meta, &meta, sizeof(meta));
    skb_info_map.update(&skb_addr, &fctx);

    // Track chain nesting depth
    u8 depth = 0;
    u8 *depth_ptr = depth_map.lookup(&tid);
    if (depth_ptr) {
        depth = *depth_ptr + 1;
    }
    depth_map.update(&tid, &depth);

    return 0;
}

int kretprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    // Decrement depth
    u8 *depth_ptr = depth_map.lookup(&tid);
    if (depth_ptr && *depth_ptr > 0) {
        u8 new_depth = *depth_ptr - 1;
        depth_map.update(&tid, &new_depth);
    }

    // Get stored context
    // Note: We need to find the SKB address from stored contexts
    // This is simplified - real implementation would need better tracking
    return 0;
}

// Trace nft_immediate_eval - Individual rule verdicts
int kprobe__nft_immediate_eval(struct pt_regs *ctx)
{
    void *expr = (void *)PT_REGS_PARM1(ctx);
    void *regs = (void *)PT_REGS_PARM2(ctx);
    if (!expr || !regs)
        return 0;

    // Read nft_pktinfo from regs->pktinfo
    void *pktinfo = NULL;
    bpf_probe_read_kernel(&pktinfo, sizeof(pktinfo), regs + 0);  // Offset 0
    if (!pktinfo)
        return 0;

    // Read sk_buff from pktinfo
    struct sk_buff *skb = NULL;
    bpf_probe_read_kernel(&skb, sizeof(skb), pktinfo);
    if (!skb)
        return 0;

    u64 skb_addr = (u64)skb;

    // Get stored context (if any)
    struct func_context *fctx = skb_info_map.lookup(&skb_addr);

    // Extract packet metadata
    struct packet_meta meta = {};
    if (fctx) {
        __builtin_memcpy(&meta, &fctx->meta, sizeof(meta));
    } else {
        extract_packet_meta_from_skb(skb, &meta);
    }

    // Apply filters
    struct filter_config *cfg = get_filter_config();
    if (!packet_matches_filter(&meta, cfg))
        return 0;

    // Get scratch buffer
    u32 zero = 0;
    struct trace_event *evt = scratch_buffer.lookup(&zero);
    if (!evt)
        return 0;

    // Read verdict from expression at various offsets
    u32 verdict_raw = 0;
    s32 verdict_s32 = 0;

    s32 verdict_offsets[] = {8, 16, 24};
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        bpf_probe_read_kernel(&verdict_s32, sizeof(verdict_s32), expr + verdict_offsets[i]);
        if (verdict_s32 != 0) {
            verdict_raw = verdict_s32;
            break;
        }
    }

    // Extract rule handle
    u64 rule_handle = extract_rule_handle(expr);

    // Fill event
    evt->timestamp = bpf_ktime_get_ns();
    evt->skb_addr = skb_addr;
    evt->cpu_id = bpf_get_smp_processor_id();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->event_type = EVENT_TYPE_NFT_RULE;
    evt->expr_addr = (u64)expr;
    evt->verdict_raw = verdict_raw;
    evt->verdict = decode_verdict(verdict_raw, verdict_raw);
    evt->rule_handle = rule_handle;
    evt->rule_seq = 0;  // Userspace will increment
    evt->stack_id = -1;

    __builtin_memcpy(&evt->meta, &meta, sizeof(meta));
    read_comm_safe(evt->comm, sizeof(evt->comm));

    // Submit event
    events.perf_submit(ctx, evt, sizeof(*evt));

    return 0;
}

// Trace nf_hook_slow - Final netfilter verdict
int kretprobe__nf_hook_slow(struct pt_regs *ctx)
{
    s32 verdict = (s32)PT_REGS_RC(ctx);

    // We'd need to correlate this with the SKB
    // This is simplified - real implementation would track SKB through hook

    return 0;
}

// ============================================================================
// FILTER CONFIGURATION (Called from userspace)
// ============================================================================

// Initialize filter configuration
int set_filter_config(struct pt_regs *ctx)
{
    // This is a placeholder - actual config is set via map update from userspace
    return 0;
}
