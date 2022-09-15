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

struct key_t {
    __u32 name[50];
    int kernel_stack_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 100 * sizeof(__u64));
    __uint(max_entries, 10000);
} stacks SEC(".maps");

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


SEC("cgroup_skb/egress")
int bpf_sockmap(struct __sk_buff *ctx)
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

    // create map key
    struct key_t key = {};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
//    __u32 remote_port = buff->remote_port;
//    remote_port = __bpf_ntohs(buff->remote_port);
//	bpf_printk("family: %d, local port: %d, remote_port: %d\n", buff->family, buff->local_port, remote_port);
	return 1;
}
