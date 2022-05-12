// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    __u64 prevPid;
    __u64 prevTgid;
    __u64 currPid;
    __u64 currTgid;
    __u64 ts;
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct task_struct {
	int pid;
    int tgid;
};

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct key_t key = {};
    struct task_struct *prev = (struct task_struct *) PT_REGS_PARM1(ctx);
    bpf_probe_read(&key.prevTgid, sizeof(key.prevTgid), &prev->tgid);
    bpf_probe_read(&key.prevPid, sizeof(key.prevPid), &prev->pid);
    struct task_struct *curr = (struct task_struct *) bpf_get_current_task();
    bpf_probe_read(&key.currTgid, sizeof(key.currTgid), &curr->tgid);
    bpf_probe_read(&key.currPid, sizeof(key.currPid), &curr->pid);
//    __u32 pid = 0;
    __u64 ts = bpf_ktime_get_ns();

	// create map key
//    struct key_t key = {};
//    key.pid = pid;
    key.ts = ts;

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
