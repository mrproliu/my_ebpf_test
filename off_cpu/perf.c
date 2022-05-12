// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    u32 pid;
    u32 tid;
    int user_stack_id;
    int kernel_stack_id;
    char name[128];
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 100 * sizeof(u64));
    __uint(max_entries, 10000);
} stacks SEC(".maps");

struct task_struct {
	int pid;
    int tgid;
};

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts = 0;

    if (tgid == 2798) {
        ts = bpf_ktime_get_ns();
    }

    u64 id = bpf_get_current_pid_tgid();
    tgid = id >> 32;
    u32 tid = id;

	// create map key
    struct key_t key = {.pid = tgid};
    key.tid = tid;
    key.tid = pid;
    key.tid = tgid;
    key.tid = ts;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0 | (1ULL << 9));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
