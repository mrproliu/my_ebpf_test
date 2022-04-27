// +build ignore

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/sys_execve")
int do_perf_event(struct pt_regs *ctx, const char *filename) {
    bpf_printk("executing , %d\n", &filename);
    return 0;
}
