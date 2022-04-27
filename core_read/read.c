// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    char name[100];
    char comm[100];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("kprobe/sys_execve")
int do_perf_event(struct pt_regs *ctx) {
    char filename[100];
    bpf_probe_read(&filename, sizeof(filename),
                       (void *)(long)PT_REGS_PARM1(ctx));
    bpf_trace_printk("executing , %s\n", filename);

    struct key_t key = {.name = filename};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

