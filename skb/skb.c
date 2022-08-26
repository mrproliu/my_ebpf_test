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
//    struct sock* s;
//    BPF_CORE_READ_INTO(&s, buff, sk);
//    bpf_printk("sock addr: %p", s);

//    short unsigned int skc_family = 0;
//    BPF_CORE_READ_INTO(&skc_family, buff, family);
//    __u32 local_port = 0;
//    __u32 remote_port = 0;
//    __u16 port = 0;
//
//    BPF_CORE_READ_INTO(&port, buff, local_port);
//    local_port = port;
//    BPF_CORE_READ_INTO(&port, buff, remote_port);
//    remote_port = bpf_ntohs(port);
	bpf_printk("family: %d, local port: %d, remote_port: %d\n", buff->family, buff->local_port, buff->remote_port);
	return 1;
}
