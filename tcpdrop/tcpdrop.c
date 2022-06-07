
// +build ignore

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <asm/errno.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpdrop.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct tcp_drop_event {
    __u32 pid;
    char comm[128];
    __u32 upstream_addr_v4;
    __u8 upstream_addr_v6[16];
    __u32 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
    __u8 downstream_addr_v6[16];
    __u32 downstream_port;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 4096);
} events SEC(".maps");

SEC("kprobe/tcp_drop")
int tcp_drop(struct pt_regs *ctx) {
    struct sock *s = (void *)PT_REGS_PARM1(ctx);
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    struct tcp_drop_event event = {};
    event.pid = tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    short unsigned int skc_family;
    __u16 port;
    BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
    if (skc_family == AF_INET) {
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
        event.downstream_port = port;
        BPF_CORE_READ_INTO(&event.downstream_addr_v4, s, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&event, s, __sk_common.skc_dport);
        event.upstream_port = port;
        BPF_CORE_READ_INTO(&event.upstream_addr_v4, s, __sk_common.skc_daddr);
        bpf_printk("tcp v4 drop: from: %d:%d\n", event.downstream_addr_v4, event.downstream_port);
    } else if (skc_family == AF_INET6) {
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
        event.downstream_port = port;
        BPF_CORE_READ_INTO(&event.downstream_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
        event.upstream_port = port;
        BPF_CORE_READ_INTO(&event.upstream_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        bpf_printk("tcp v6 drop: from: %s:%d\n", event.downstream_addr_v4, event.downstream_port);
    } else {
        bpf_printk("now ip drop so ignore: %d\n", skc_family);
        return 0;
    }
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
