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

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/writev")
int sys_writev(struct pt_regs* ctx) {
    bpf_printk("sys writev enter");
    return 0;
}

SEC("kretprobe/writev")
int sys_writev_ret(struct pt_regs* ctx) {
    bpf_printk("sys writev exit");
    return 0;
}


//SEC("cgroup_skb/egress")
//int bpf_sockmap(struct __sk_buff *buff)
//{
////    struct sock* s;
////    BPF_CORE_READ_INTO(&s, buff, sk);
////    bpf_printk("sock addr: %p", s);
//
////    short unsigned int skc_family = 0;
////    BPF_CORE_READ_INTO(&skc_family, buff, family);
////    __u32 local_port = 0;
////    __u32 remote_port = 0;
////    __u16 port = 0;
////
////    BPF_CORE_READ_INTO(&port, buff, local_port);
////    local_port = port;
////    BPF_CORE_READ_INTO(&port, buff, remote_port);
////    remote_port = bpf_ntohs(port);
//    __u32 remote_port = buff->remote_port;
//    remote_port = __bpf_ntohs(buff->remote_port);
//	bpf_printk("family: %d, local port: %d, remote_port: %d\n", buff->family, buff->local_port, remote_port);
//	return 1;
//}
