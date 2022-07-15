

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

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

SEC("kprobe/security_socket_sendmsg")
int security_socket_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 tgid = (__u32)(id >> 32);
    if (tgid == 9341) {
        bpf_printk("9118 send msg");
    }
    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int security_socket_recvmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 tgid = (__u32)(id >> 32);
    if (tgid == 9341) {
        bpf_printk("9118 recv msg");
    }
    return 0;
}