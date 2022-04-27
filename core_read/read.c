// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/sys_execve")
int do_perf_event(struct pt_regs *ctx) {
    char filename[100];
    bpf_probe_read(&filename, sizeof(filename),
                       (void *)(long)PT_REGS_PARM1(ctx));
    bpf_trace_printk("executing , %s\n", filename);
    return 0;
}

