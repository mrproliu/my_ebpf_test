

// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u64));
	__uint(value_size, sizeof(struct sock));
    __uint(max_entries, 10000);
} connect_socks SEC(".maps");

SEC("kprobe/tcp_connect")
int bpf_tcp_v4_connect(struct pt_regs *ctx) {
//    struct sockaddr *uaddr = (void *)PT_REGS_PARM2(ctx);
////    struct sockaddr *addr = (void *)PT_REGS_PARM2(ctx);
//    __u64 pid = bpf_get_current_pid_tgid();
//    __u64 family = _(uaddr->sa_family);
//    bpf_printk("connect before, family: %d, pid: %d", family, pid);
//    bpf_map_update_elem(&connect_socks, &pid, sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_connect")
int bpf_tcp_v4_connect_ret(struct pt_regs *ctx) {
//    __u64 pid = bpf_get_current_pid_tgid();
//    struct sock *sk;

    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
//    if (sk == NULL) {
//        return 0;        // missed start or filtered
//    }

//    __u16 skc_daddr = BPF_CORE_READ(sk, __sk_common.skc_num);
//    __be16 skc_rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_dport);
//	bpf_printk("send tcp v4 connect return: %d, %d\n", skc_daddr, skc_rcv_saddr);
    __u32 skc_rcv_saddr = _(sk->__sk_common.skc_rcv_saddr);
    __u32 skc_daddr = _(sk->__sk_common.skc_daddr);
    bpf_printk("connect after: %d, %d", skc_rcv_saddr, skc_daddr);
	return 0;
}
