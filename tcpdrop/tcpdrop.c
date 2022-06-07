
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

SEC("kprobe:tcp_drop")
int tcp_drop(struct pt_regs *ctx) {
//    struct sock *sk = PT_REGS_PARM1(ctx);
    bpf_printk("detect tcp drop\n");
    return 0;
}
