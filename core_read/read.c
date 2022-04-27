// +build ignore

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/sys_execve")
int do_perf_event(struct pt_regs *ctx) {
    char arg[128];
    bpf_probe_read(&arg, sizeof(arg), (void *)ctx->rdi);
    bpf_printk("executing , %s\n", *arg);
    return 0;
}