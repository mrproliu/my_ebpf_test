// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    u32 pid;
    u64 ts;
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
int do_finish_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u64 ts = 0;

//    if (pid == 2795) {
        ts = bpf_ktime_get_ns();
//    }

	// create map key
    struct key_t key = {};
    key.pid = pid;
    key.ts = ts;

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
