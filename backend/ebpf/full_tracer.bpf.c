#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

#define EVENT_TYPE_FUNCTION_CALL 0
#define EVENT_TYPE_NFT_CHAIN     1
#define EVENT_TYPE_NFT_RULE      2
#define EVENT_TYPE_NF_VERDICT    3

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

    u64 func_ip;
    char function_name[64];
    char comm[16];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(skb_info_map, u64, struct trace_event, 10240);
BPF_HASH(depth_map, u64, u8, 10240);
struct hook_state {
    u8 hook;
    u8 pf;
};
BPF_HASH(hook_map, u64, struct hook_state, 10240);

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

static __always_inline void extract_packet_info_from_skb(void *skb, struct trace_event *evt)
{
    if (!skb)
        return;
    
    evt->skb_addr = (u64)skb;

    u32 len = 0;
    bpf_probe_read_kernel(&len, sizeof(len), (char *)skb + 0x88);
    evt->length = len;

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

int trace_skb_func(struct pt_regs *ctx, struct sk_buff *skb)
{
    u64 tid = bpf_get_current_pid_tgid();

    struct trace_event evt = {};
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32)(tid >> 32);
    evt.event_type = EVENT_TYPE_FUNCTION_CALL;

    evt.func_ip = PT_REGS_IP(ctx);

    extract_packet_info_from_skb(skb, &evt);
    read_comm_safe(evt.comm, sizeof(evt.comm));

    if (evt.skb_addr != 0) {
        struct hook_state *hs = hook_map.lookup(&evt.skb_addr);
        if (hs) {
            evt.hook = hs->hook;
            evt.pf = hs->pf;
        }
    }

    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        return 0;
    }

    if (evt.skb_addr != 0) {
        skb_info_map.update(&tid, &evt);
    }

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

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

    if (evt.src_port == 3000 || evt.dst_port == 3000 ||
        evt.src_port == 5000 || evt.dst_port == 5000) {
        if (cur_depth && *cur_depth > 0) {
            u8 new_depth = *cur_depth - 1;
            depth_map.update(&tid, &new_depth);
        } else {
            depth_map.delete(&tid);
        }
        return 0;
    }

    if (evt.skb_addr != 0) {
        skb_info_map.update(&tid, &evt);
    }

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
    }

    if (verdict == 3u) {
        evt.queue_num = (rax_u32 >> 16) & 0xFFFFu;
        evt.has_queue_bypass = ((rax_u32 & 0x8000u) ? 1 : 0);
    }

    read_comm_safe(evt.comm, sizeof(evt.comm));

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

    evt.verdict_raw = verdict_code;
    evt.verdict = decode_verdict(verdict_code, (u32)verdict_code);

    if (evt.verdict == 3u) {
        evt.queue_num = ((u32)verdict_code >> 16) & 0xFFFFu;
        evt.has_queue_bypass = (((u32)verdict_code & 0x8000u) ? 1 : 0);
    }

    // CRITICAL FIX: Set func_ip so Python backend can identify this as nft_immediate_eval
    // This ensures verdict is counted correctly for the Netfilter hook
    evt.func_ip = PT_REGS_IP(ctx);

    read_comm_safe(evt.comm, sizeof(evt.comm));
    events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

int kprobe__nf_hook_slow(struct pt_regs *ctx)
{
    void *skb = (void *)PT_REGS_PARM1(ctx);
    void *state = (void *)PT_REGS_PARM2(ctx);

    if (!skb || !state)
        return 0;

    u64 skb_addr = (u64)skb;

    struct hook_state hs = {};
    bpf_probe_read_kernel(&hs.hook, sizeof(hs.hook), state);
    bpf_probe_read_kernel(&hs.pf, sizeof(hs.pf), (char *)state + 1);

    hook_map.update(&skb_addr, &hs);

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