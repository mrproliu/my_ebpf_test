// +build ignore

#include <stddef.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "skb.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    __u32 pid;
    __u32 tid;
    char name[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("cgroup_skb/egress")
int bpf_sockmap(struct __sk_buff *buff)
{
    struct sock* s;
    BPF_CORE_READ_INTO(&s, buff, sk);

    short unsigned int skc_family = 0;
    BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
    __u32 local_port = 0;
    __u32 remote_port = 0;
    __u16 port = 0;

    if (skc_family == AF_INET) {
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
        local_port = port;
//        BPF_CORE_READ_INTO(&con.local_addr_v4, s, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
        remote_port = bpf_ntohs(port);
//        BPF_CORE_READ_INTO(&con.remote_addr_v4, s, __sk_common.skc_daddr);
    } else if (skc_family == AF_INET6) {
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
        local_port = port;
//        BPF_CORE_READ_INTO(&con.local_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
        remote_port = bpf_ntohs(port);
//        BPF_CORE_READ_INTO(&con.remote_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
   }
	bpf_printk("local port: %d, remote_port: %d\n", local_port, remote_port);
	return 1;
}
