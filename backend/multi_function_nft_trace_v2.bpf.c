// SPDX-License-Identifier: GPL-2.0
// Multi-Function NFT Tracer V2 - Fixed symbol resolution
// Uses function metadata map instead of runtime address lookup

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

// Event types
#define EVENT_FUNCTION  0
#define EVENT_NFT_CHAIN 1
#define EVENT_NFT_RULE  2
#define EVENT_NF_HOOK   3

// Function metadata for lookup
struct func_metadata {
    char name[64];
    char layer[16];
    u8 priority;
};

// Unified trace event
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

    u64 chain_addr;
    u64 expr_addr;
    u8 chain_depth;
    u16 rule_seq;
    u64 rule_handle;

    s32 verdict_raw;
    u32 verdict;
    u16 queue_num;
    u8 has_queue_bypass;

    // New fields for better packet parsing
    u8 is_non_ip;        // 1 if not IP packet
    u8 parse_failed;     // 1 if parsing failed
    u16 eth_protocol;    // Ethernet protocol (0x0800, 0x86DD, etc.)
    u8 ip_version;       // 4 or 6

    char func_name[64];
    char layer[16];
    char comm[16];
};

struct packet_info {
    u64 skb_addr;
    u64 first_seen;
    u32 function_count;

    u8 protocol;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 length;

    u64 chain_addr;
    u8 hook;
    u8 pf;
    u16 rule_seq;
    u8 chain_depth;

    // New fields for better packet parsing
    u8 is_non_ip;        // 1 if not IP packet
    u8 parse_failed;     // 1 if parsing failed
    u16 eth_protocol;    // Ethernet protocol (0x0800, 0x86DD, etc.)
    u8 ip_version;       // 4 or 6
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(packet_map, u64, struct packet_info, 10240);
BPF_HASH(tid_map, u64, struct packet_info, 10240);
BPF_HASH(depth_map, u64, u8, 10240);

// NEW: Function metadata map - populated by Python
// Key: function index (0, 1, 2, ...), Value: metadata
BPF_ARRAY(func_meta, struct func_metadata, 256);

// Helper: decode NFT verdict
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

// Ethernet protocol types
#define ETH_P_IP    0x0800    // Internet Protocol packet
#define ETH_P_IPV6  0x86DD    // IPv6 over bluebook
#define ETH_P_ARP   0x0806    // Address Resolution packet

// Protocol families
#define PF_UNSPEC   0
#define PF_INET     2
#define PF_INET6    10

static __always_inline void extract_packet_info(struct sk_buff *skb, struct packet_info *pkt)
{
    if (!skb)
        return;

    pkt->skb_addr = (u64)skb;
    pkt->is_non_ip = 0;
    pkt->parse_failed = 0;
    pkt->eth_protocol = 0;
    pkt->ip_version = 0;

    // Read packet length (offset 0x88 is common across kernel versions)
    u32 len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), (char *)skb + 0x88);
    pkt->length = len;

    // Read skb->protocol (Ethernet protocol type) - offset ~0x7c, big-endian u16
    u16 protocol_be = 0;
    s32 offsets[] = {0x7c, 0x74, 0x76, 0x78, 0x80};

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        u16 proto_test = 0;
        if (bpf_probe_read_kernel(&proto_test, sizeof(proto_test), (char *)skb + offsets[i]) == 0) {
            // Convert big-endian to host byte order
            u16 proto = bpf_ntohs(proto_test);
            // Check if it looks like a valid Ethernet protocol
            if (proto == ETH_P_IP || proto == ETH_P_IPV6 || proto == ETH_P_ARP ||
                proto == 0x8100 || proto == 0x8864) {
                protocol_be = proto;
                pkt->eth_protocol = proto;
                break;
            }
        }
    }

    // If protocol is not IP or IPv6, mark as non-IP and return
    if (protocol_be != ETH_P_IP && protocol_be != ETH_P_IPV6) {
        pkt->is_non_ip = 1;
        return;
    }

    // Now try to read IP header
    void *ip_header = NULL;

    // Method 1: Try skb->data (most reliable for packets that have been parsed)
    // Offset ~0xd8-0xe0 depending on kernel version
    s32 data_offsets[] = {0xd8, 0xd0, 0xe0, 0xc8};

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        void *data_ptr = NULL;
        if (bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (char *)skb + data_offsets[i]) == 0) {
            if (data_ptr) {
                ip_header = data_ptr;
                break;
            }
        }
    }

    // Method 2: If data pointer failed, try skb->head + skb->network_header
    if (!ip_header) {
        void *head = NULL;
        u16 network_header = 0;

        // Try to read head (offset ~0xc0-0xc8)
        s32 head_offsets[] = {0xc0, 0xc8, 0xb8};
        #pragma unroll
        for (int i = 0; i < 3; i++) {
            void *h = NULL;
            if (bpf_probe_read_kernel(&h, sizeof(h), (char *)skb + head_offsets[i]) == 0) {
                if (h) {
                    head = h;
                    break;
                }
            }
        }

        // Try to read network_header (offset ~0xca-0xd0)
        if (head) {
            s32 nh_offsets[] = {0xca, 0xcc, 0xce, 0xd0};
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                u16 nh = 0;
                if (bpf_probe_read_kernel(&nh, sizeof(nh), (char *)skb + nh_offsets[i]) == 0) {
                    if (nh < 0xFFFF && nh < 1500) {  // Reasonable header offset
                        network_header = nh;
                        ip_header = (char *)head + nh;
                        break;
                    }
                }
            }
        }
    }

    if (!ip_header) {
        pkt->parse_failed = 1;
        return;
    }

    // Read and validate IP version
    u8 ihl_version = 0;
    if (bpf_probe_read_kernel(&ihl_version, sizeof(ihl_version), ip_header) != 0) {
        pkt->parse_failed = 1;
        return;
    }

    u8 version = (ihl_version >> 4) & 0x0F;
    pkt->ip_version = version;

    // Only support IPv4 for now
    if (version != 4) {
        if (version == 6) {
            // IPv6 detected but not fully parsed yet
            pkt->parse_failed = 0;  // Not a failure, just unsupported
        } else {
            pkt->parse_failed = 1;
        }
        return;
    }

    // Parse IPv4 header
    u8 protocol = 0;
    u32 saddr = 0;
    u32 daddr = 0;

    bpf_probe_read_kernel(&protocol, sizeof(protocol), (char *)ip_header + 9);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (char *)ip_header + 12);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (char *)ip_header + 16);

    pkt->protocol = protocol;
    pkt->src_ip = saddr;
    pkt->dst_ip = daddr;

    // Parse transport layer for TCP/UDP
    if (protocol == 6 || protocol == 17) {
        u8 ihl = (ihl_version & 0x0F) * 4;

        // Validate IHL
        if (ihl < 20 || ihl > 60) {
            return;
        }

        void *trans_header = (char *)ip_header + ihl;

        u16 sport = 0;
        u16 dport = 0;

        if (bpf_probe_read_kernel(&sport, sizeof(sport), trans_header) == 0 &&
            bpf_probe_read_kernel(&dport, sizeof(dport), (char *)trans_header + 2) == 0) {
            pkt->src_port = bpf_ntohs(sport);
            pkt->dst_port = bpf_ntohs(dport);
        }
    }
}

static __always_inline void extract_from_nft_pktinfo(void *pkt_ptr, struct packet_info *pkt)
{
    if (!pkt_ptr)
        return;

    void *skb = NULL;
    void *state = NULL;

    bpf_probe_read_kernel(&skb, sizeof(skb), pkt_ptr);
    bpf_probe_read_kernel(&state, sizeof(state), (char *)pkt_ptr + 8);

    // Read hook and protocol family first
    if (state) {
        bpf_probe_read_kernel(&pkt->hook, sizeof(pkt->hook), state);
        bpf_probe_read_kernel(&pkt->pf, sizeof(pkt->pf), (char *)state + 1);
    }

    // Only parse packet info if we have an IP protocol family
    // pf == PF_INET (2) or PF_INET6 (10)
    if (skb) {
        if (pkt->pf == PF_INET || pkt->pf == PF_INET6) {
            // This is an IP packet, try to parse it
            extract_packet_info((struct sk_buff *)skb, pkt);
        } else if (pkt->pf == PF_UNSPEC || pkt->pf == 7) {  // PF_UNSPEC or PF_BRIDGE
            // Non-IP packet (ARP, bridge traffic, etc.)
            // Still read basic info but mark as non-IP
            pkt->skb_addr = (u64)skb;
            pkt->is_non_ip = 1;

            // Try to read length anyway
            u32 len = 0;
            bpf_probe_read_kernel(&len, sizeof(len), (char *)skb + 0x88);
            pkt->length = len;

            // Try to read Ethernet protocol for debugging
            u16 protocol_be = 0;
            s32 offsets[] = {0x7c, 0x74, 0x76, 0x78};
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                u16 proto_test = 0;
                if (bpf_probe_read_kernel(&proto_test, sizeof(proto_test), (char *)skb + offsets[i]) == 0) {
                    u16 proto = bpf_ntohs(proto_test);
                    if (proto == ETH_P_ARP || proto == 0x8100 || proto == 0x8864 ||
                        proto == ETH_P_IP || proto == ETH_P_IPV6) {
                        pkt->eth_protocol = proto;
                        break;
                    }
                }
            }
        }
    }
}

// Helper to copy string safely
static __always_inline void copy_string(char *dest, const char *src, u32 max_len)
{
    #pragma unroll
    for (int i = 0; i < 64 && i < max_len; i++) {
        dest[i] = src[i];
        if (src[i] == 0)
            break;
    }
}

// =============================================================================
// GENERIC FUNCTION TRACER with metadata lookup
// =============================================================================
static __always_inline int trace_skb_generic(struct pt_regs *ctx, struct sk_buff *skb, u32 func_id)
{
    if (!skb)
        return 0;

    u64 tid = bpf_get_current_pid_tgid();
    u64 skb_addr = (u64)skb;

    // Lookup function metadata
    struct func_metadata *meta = func_meta.lookup(&func_id);
    if (!meta)
        return 0;

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

    pkt->function_count++;
    packet_map.update(&skb_addr, pkt);

    // Emit event
    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.skb_addr = skb_addr;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_FUNCTION;

    // Copy function metadata
    copy_string(evt.func_name, meta->name, sizeof(evt.func_name));
    copy_string(evt.layer, meta->layer, sizeof(evt.layer));

    evt.protocol = pkt->protocol;
    evt.src_ip = pkt->src_ip;
    evt.dst_ip = pkt->dst_ip;
    evt.src_port = pkt->src_port;
    evt.dst_port = pkt->dst_port;
    evt.length = pkt->length;
    evt.hook = pkt->hook;
    evt.pf = pkt->pf;

    // New packet parsing fields
    evt.is_non_ip = pkt->is_non_ip;
    evt.parse_failed = pkt->parse_failed;
    evt.eth_protocol = pkt->eth_protocol;
    evt.ip_version = pkt->ip_version;

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    tid_map.update(&tid, pkt);

    return 0;
}

// =============================================================================
// NFT HOOKS
// =============================================================================

int kprobe__nft_do_chain(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    void *pkt_ptr = (void *)PT_REGS_PARM1(ctx);
    void *priv = (void *)PT_REGS_PARM2(ctx);

    if (!pkt_ptr)
        return 0;

    u8 depth = 0;
    u8 *cur_depth = depth_map.lookup(&tid);
    if (cur_depth) {
        depth = *cur_depth + 1;
    }
    depth_map.update(&tid, &depth);

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

    // New packet parsing fields
    evt.is_non_ip = pkt->is_non_ip;
    evt.parse_failed = pkt->parse_failed;
    evt.eth_protocol = pkt->eth_protocol;
    evt.ip_version = pkt->ip_version;

    copy_string(evt.func_name, "nft_do_chain", sizeof(evt.func_name));
    copy_string(evt.layer, "Netfilter", sizeof(evt.layer));

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

    // New packet parsing fields
    evt.is_non_ip = pkt->is_non_ip;
    evt.parse_failed = pkt->parse_failed;
    evt.eth_protocol = pkt->eth_protocol;
    evt.ip_version = pkt->ip_version;

    evt.verdict_raw = rax_s32;
    evt.verdict = verdict;

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    copy_string(evt.func_name, "nft_do_chain_exit", sizeof(evt.func_name));
    copy_string(evt.layer, "Netfilter", sizeof(evt.layer));

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

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

    s32 verdict_code = 0;
    bpf_probe_read_kernel(&verdict_code, sizeof(verdict_code), (char *)expr + 8);

    u64 rule_handle = extract_rule_handle(expr);

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

    // New packet parsing fields
    evt.is_non_ip = pkt->is_non_ip;
    evt.parse_failed = pkt->parse_failed;
    evt.eth_protocol = pkt->eth_protocol;
    evt.ip_version = pkt->ip_version;

    evt.verdict_raw = verdict_code;
    evt.verdict = decode_verdict(verdict_code, (u32)verdict_code);

    if (evt.verdict == 3u) {
        evt.queue_num = ((u32)verdict_code >> 16) & 0xFFFFu;
        evt.has_queue_bypass = (((u32)verdict_code & 0x8000u) ? 1 : 0);
    }

    copy_string(evt.func_name, "nft_immediate_eval", sizeof(evt.func_name));
    copy_string(evt.layer, "Netfilter", sizeof(evt.layer));

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Track hook state when entering nf_hook_slow
// nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, ...)
int kprobe__nf_hook_slow(struct pt_regs *ctx)
{
    void *skb = (void *)PT_REGS_PARM1(ctx);
    void *state = (void *)PT_REGS_PARM2(ctx);

    if (!skb || !state)
        return 0;

    u64 skb_addr = (u64)skb;

    // Extract hook and pf from nf_hook_state
    u8 hook = 255;
    u8 pf = 0;
    bpf_probe_read_kernel(&hook, sizeof(hook), state);          // offset 0
    bpf_probe_read_kernel(&pf, sizeof(pf), (char *)state + 1);  // offset 1

    // Get or create packet info
    struct packet_info *pkt = packet_map.lookup(&skb_addr);
    struct packet_info new_pkt = {};

    if (!pkt) {
        new_pkt.skb_addr = skb_addr;
        new_pkt.first_seen = bpf_ktime_get_ns();
        new_pkt.function_count = 0;
        extract_packet_info((struct sk_buff *)skb, &new_pkt);
        pkt = &new_pkt;
    }

    // Update hook state
    pkt->hook = hook;
    pkt->pf = pf;
    packet_map.update(&skb_addr, pkt);

    // Also save to tid_map for kretprobe
    u64 tid = bpf_get_current_pid_tgid();
    tid_map.update(&tid, pkt);

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

        // New packet parsing fields
        evt.is_non_ip = pkt->is_non_ip;
        evt.parse_failed = pkt->parse_failed;
        evt.eth_protocol = pkt->eth_protocol;
        evt.ip_version = pkt->ip_version;
    }

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    copy_string(evt.func_name, "nf_hook_slow", sizeof(evt.func_name));
    copy_string(evt.layer, "Netfilter", sizeof(evt.layer));

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}
