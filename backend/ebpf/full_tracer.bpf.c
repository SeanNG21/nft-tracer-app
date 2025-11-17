// SPDX-License-Identifier: GPL-2.0
// Full Network Stack Tracer with NFT Integration
// Traces complete packet journey through Linux network stack

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

// Event types
#define EVENT_TYPE_FUNCTION 0
#define EVENT_TYPE_NFT_RULE 1
#define EVENT_TYPE_NFT_CHAIN 2

// Combined event structure for both function and NFT events
struct full_trace_event {
    u64 timestamp;
    u64 skb_addr;
    u32 cpu_id;
    u32 pid;

    u8 event_type;
    u8 protocol;
    u16 _pad1;

    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;

    // Function-specific
    u64 func_ip;
    char function_name[64];

    // NFT-specific
    u64 chain_addr;
    u64 expr_addr;
    u8 hook;
    u8 pf;
    u8 chain_depth;
    u8 trace_type;
    u16 rule_seq;
    u16 queue_num;
    u64 rule_handle;
    s32 verdict_raw;
    u32 verdict_code;
    u8 has_queue_bypass;

    char comm[16];
    u8 _pad2[3];
};

// Internal tracking structure
struct skb_tracking {
    u64 skb_addr;
    u64 chain_addr;
    u8 hook;
    u8 pf;
    u16 rule_seq;
    u8 protocol;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(skb_map, u64, struct skb_tracking, 10240);
BPF_HASH(depth_map, u64, u8, 10240);

// ==============================================
// HELPER FUNCTIONS
// ==============================================

static __always_inline u32 decode_verdict(s32 raw_ret, u32 raw_u32)
{
    if (raw_ret < 0) {
        switch (raw_ret) {
            case -1: return 10;  // CONTINUE
            case -2: return 11;  // RETURN
            case -3: return 12;  // GOTO
            case -4: return 13;  // JUMP
            case -5: return 14;  // BREAK
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

static __always_inline u64 extract_rule_handle(void *expr)
{
    if (!expr)
        return 0;

    s32 offsets[] = {-16, -24, -32, -40, -48, -56, -64, -72, -80, -96, -112, -128, -144, -160};

    #pragma unroll
    for (int i = 0; i < 14; i++) {
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

static __always_inline void extract_packet_info_from_skb(void *skb, struct full_trace_event *evt)
{
    if (!skb)
        return;

    evt->skb_addr = (u64)skb;

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

    // Extract ports for TCP/UDP
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

static __always_inline void extract_packet_info_from_pkt(void *pkt, struct skb_tracking *info)
{
    if (!pkt)
        return;

    void *skb = NULL;
    void *state = NULL;

    bpf_probe_read_kernel(&skb, sizeof(skb), pkt);
    bpf_probe_read_kernel(&state, sizeof(state), (char *)pkt + 8);

    if (!skb)
        return;

    info->skb_addr = (u64)skb;

    if (state) {
        bpf_probe_read_kernel(&info->hook, sizeof(info->hook), state);
        bpf_probe_read_kernel(&info->pf, sizeof(info->pf), (char *)state + 1);
    }

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

    info->protocol = protocol;
    info->src_ip = saddr;
    info->dst_ip = daddr;

    // Extract ports for TCP/UDP
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

// ==============================================
// GENERIC FUNCTION TRACER FOR ALL NETWORK STACK FUNCTIONS
// ==============================================
static __always_inline int trace_network_function(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();

    struct full_trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_FUNCTION;
    evt.func_ip = PT_REGS_IP(ctx);

    extract_packet_info_from_skb(skb, &evt);
    read_comm_safe(evt.comm, sizeof(evt.comm));

    // Filter out app ports to avoid tracing our own traffic
    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ==============================================
// NIC LAYER
// ==============================================
int kprobe__e1000_clean_rx_irq(struct pt_regs *ctx, void *rx_ring, int budget) {
    // This doesn't get sk_buff directly, skip for now
    return 0;
}

int kprobe__ixgbe_clean_rx_irq(struct pt_regs *ctx, void *q_vector, void *rx_ring, int budget) {
    // This doesn't get sk_buff directly, skip for now
    return 0;
}

int kprobe__mlx5e_poll_rx_cq(struct pt_regs *ctx, void *cq, int budget) {
    // This doesn't get sk_buff directly, skip for now
    return 0;
}

// ==============================================
// DRIVER (NAPI) LAYER
// ==============================================
int kprobe____napi_poll(struct pt_regs *ctx) {
    // Doesn't have skb parameter
    return 0;
}

int kprobe__netif_receive_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__netif_receive_skb_list(struct pt_regs *ctx) {
    // List function - would need special handling
    return 0;
}

int kprobe__netif_receive_skb_list_internal(struct pt_regs *ctx) {
    // List function - would need special handling
    return 0;
}

// ==============================================
// GRO LAYER
// ==============================================
int kprobe__napi_gro_receive(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__dev_gro_receive(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__inet_gro_receive(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__tcp_gro_receive(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

// ==============================================
// TC INGRESS LAYER
// ==============================================
int kprobe__sch_handle_ingress(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__tcf_classify(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__tcf_exts_exec(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__cls_bpf_classify(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

// ==============================================
// CONNTRACK LAYER
// ==============================================
int kprobe__nf_conntrack_in(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__nf_confirm(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__nf_conntrack_tcp_packet(struct pt_regs *ctx) {
    // Complex signature, skip
    return 0;
}

int kprobe__nf_conntrack_handle_packet(struct pt_regs *ctx) {
    // May not exist in all kernels
    return 0;
}

// ==============================================
// NAT LAYER
// ==============================================
int kprobe__nf_nat_ipv4_in(struct pt_regs *ctx) {
    // Complex signature with state
    return 0;
}

int kprobe__nf_nat_packet(struct pt_regs *ctx) {
    // Complex signature
    return 0;
}

int kprobe__nf_nat_inet_fn(struct pt_regs *ctx) {
    // Complex signature
    return 0;
}

// ==============================================
// ROUTING DECISION LAYER
// ==============================================
int kprobe__ip_route_input_slow(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__ip_route_input_noref(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__fib_validate_source(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__fib_table_lookup(struct pt_regs *ctx) {
    // Doesn't have skb parameter
    return 0;
}

// ==============================================
// LOCAL DELIVERY LAYER
// ==============================================
int kprobe__ip_local_deliver(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__tcp_v4_rcv(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__udp_rcv(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__udp_unicast_rcv_skb(struct pt_regs *ctx) {
    // Second parameter is skb
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__tcp_v4_do_rcv(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__sock_queue_rcv_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

// ==============================================
// FORWARD/TX LAYER
// ==============================================
int kprobe__dev_queue_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe____dev_queue_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__sch_direct_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

// ==============================================
// OUTBOUND APPLICATION LAYER
// ==============================================
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    // First param is socket, not skb
    return 0;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx) {
    // First param is socket, not skb
    return 0;
}

int kprobe__tcp_write_xmit(struct pt_regs *ctx) {
    // First param is socket, not skb
    return 0;
}

int kprobe__tcp_transmit_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__udp_send_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__ip_route_output_flow(struct pt_regs *ctx) {
    // Routing function, no skb
    return 0;
}

int kprobe__ip_route_output_key_hash(struct pt_regs *ctx) {
    // Routing function, no skb
    return 0;
}

// ==============================================
// TC EGRESS LAYER
// ==============================================
int kprobe__sch_handle_egress(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

// ==============================================
// NIC TX LAYER
// ==============================================
int kprobe__ixgbe_xmit_frame(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__e1000_xmit_frame(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_network_function(ctx, skb);
}

int kprobe__mlx5e_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return trace_network_function(ctx, skb);
}

// ==============================================
// NFT INTEGRATION (replaces Netfilter tracing)
// ==============================================

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

    // Extract and store packet info
    struct skb_tracking info = {};
    info.chain_addr = (u64)priv;
    info.rule_seq = 0;

    extract_packet_info_from_pkt(pkt, &info);

    // Filter out app ports
    if (info.src_port == 3000 || info.dst_port == 3000 ||
        info.src_port == 5000 || info.dst_port == 5000) {
        if (cur_depth && *cur_depth > 0) {
            u8 new_depth = *cur_depth - 1;
            depth_map.update(&tid, &new_depth);
        } else {
            depth_map.delete(&tid);
        }
        return 0;
    }

    skb_map.update(&tid, &info);
    return 0;
}

int kretprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();

    u64 rax_u64 = PT_REGS_RC(ctx);
    s32 rax_s32 = (s32)rax_u64;
    u32 rax_u32 = (u32)rax_u64;

    struct skb_tracking *info = skb_map.lookup(&tid);
    if (!info)
        return 0;

    u8 *depth_ptr = depth_map.lookup(&tid);
    u32 verdict = decode_verdict(rax_s32, rax_u32);

    struct full_trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_CHAIN;
    evt.trace_type = 0;  // chain_exit

    evt.skb_addr = info->skb_addr;
    evt.chain_addr = info->chain_addr;
    evt.hook = info->hook;
    evt.pf = info->pf;
    evt.protocol = info->protocol;
    evt.src_ip = info->src_ip;
    evt.dst_ip = info->dst_ip;
    evt.src_port = info->src_port;
    evt.dst_port = info->dst_port;

    evt.chain_depth = depth_ptr ? *depth_ptr : 0;
    evt.verdict_raw = rax_s32;
    evt.verdict_code = verdict;
    evt.rule_seq = info->rule_seq;

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    // Cleanup depth tracking
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

    struct skb_tracking *info = skb_map.lookup(&tid);
    if (!info)
        return 0;

    info->rule_seq++;

    // Extract verdict from expression
    s32 verdict_code = 0;
    int read_ok = 0;

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

    u64 rule_handle = extract_rule_handle(expr);

    struct full_trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_NFT_RULE;
    evt.trace_type = 1;  // rule_eval

    evt.skb_addr = info->skb_addr;
    evt.chain_addr = info->chain_addr;
    evt.expr_addr = (u64)expr;
    evt.hook = info->hook;
    evt.pf = info->pf;

    u8 *depth_ptr = depth_map.lookup(&tid);
    evt.chain_depth = depth_ptr ? *depth_ptr : 0;

    evt.rule_seq = info->rule_seq;
    evt.rule_handle = rule_handle;
    evt.verdict_raw = verdict_code;
    evt.verdict_code = decode_verdict(verdict_code, (u32)verdict_code);

    evt.protocol = info->protocol;
    evt.src_ip = info->src_ip;
    evt.dst_ip = info->dst_ip;
    evt.src_port = info->src_port;
    evt.dst_port = info->dst_port;

    if (evt.verdict_code == 3u) {
        evt.queue_num = ((u32)verdict_code >> 16) & 0xFFFFu;
        evt.has_queue_bypass = (((u32)verdict_code & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}
