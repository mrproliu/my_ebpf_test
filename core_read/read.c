// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    int pid;
    char name[256];
    char comm[128];
};

typedef int pid_t;
struct task_struct {
	int pid;
    int tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("kprobe/sys_execve")
int do_sys_execve(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    int pid = task->pid;
    struct key_t key = {.pid = pid};
    bpf_probe_read_user_str(&key.name, sizeof(key.name),
                    (void *)(long)PT_REGS_PARM1(ctx));
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}