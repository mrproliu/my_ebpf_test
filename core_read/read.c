// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    char name[256];
    char comm[128];
    long res;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("kprobe/sys_execve")
int do_sys_execve(struct pt_regs *ctx) {
    struct key_t key = {};
//    CO-RE way to read
//    long ad = BPF_CORE_READ(ctx, rdi);
//    bpf_probe_read_user_str(&key.name, sizeof(key.name),
//                       (void *)(long)ad);
    const char *fp = (char *)PT_REGS_PARM1(ctx);
    long res = bpf_probe_read_user_str(&key.name, sizeof(key.name), fp);
//    bpf_probe_read_user_str(&key.name, sizeof(key.name),
//                    (void *)(long)PT_REGS_PARM1(ctx));
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.res = res;

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

