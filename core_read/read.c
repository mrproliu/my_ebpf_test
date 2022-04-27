// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    char name[256];
    char comm[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("kprobe/do_sys_open")
int do_sys_open(struct pt_regs *ctx) {
    struct key_t key = {};
    bpf_probe_read_user_str(&key.name, sizeof(key.name),
                       (void *)(long)PT_REGS_PARM1(ctx));
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

