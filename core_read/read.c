// +build ignore

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PT_REGS_PARM1(x) ((x)->rdi)

SEC("kprobe/sys_execve")
int do_perf_event(struct pt_regs *ctx) {
    const char* buf = (const char*)PT_REGS_PARM1(ctx);
//    char arg[128];
//    bpf_probe_read(&arg, sizeof(arg), (void *)ctx->rdi);
    bpf_printk("executing , %s\n", *buf);
    return 0;
}