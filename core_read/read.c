// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    __u32 pid;
    __u32 tgid;
    char name[256];
    char comm[128];
};

typedef int pid_t;
struct task_struct {
    int pid;
    char comm[16];
    struct task_struct *group_leader;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("kprobe/sys_execve")
int do_sys_execve(struct pt_regs *ctx) {
    struct task_struct *t = (void *)bpf_get_current_task();
    struct key_t key = {};
    int pid = BPF_CORE_READ(t, pid);
    key.pid = pid;
//    bpf_probe_read_user_str(&key.name, sizeof(key.name),
//                       (void *)(long)ad);
//    bpf_probe_read(&(key.pid), sizeof(key.pid), &(task->pid));
//    bpf_probe_read(&(key.tgid), sizeof(key.pid), &(task->tgid));
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}