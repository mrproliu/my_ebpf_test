// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    __u32 pid;
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
    struct task_struct *task = (struct task_struct *) PT_REGS_PARM1(ctx);
    struct key_t key = {};
    bpf_probe_read(&key.pid, sizeof(key.pid), &task->tgid);
//    __u32 pid = 0;
    __u64 ts = 0;

	// create map key
//    struct key_t key = {};
//    key.pid = pid;
    key.ts = ts;

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
