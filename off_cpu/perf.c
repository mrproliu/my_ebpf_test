// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    u32 tid;
    int user_stack_id;
    int kernel_stack_id;
    u32 t;
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

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
    __uint(max_entries, 10000);
} starts SEC(".maps");

struct task_struct {
	int pid;
    int tgid;
};

SEC("kprobe/finish_task_switch")
int do_stack_switch(struct pt_regs *ctx, struct task_struct *prev) {
    // should change the pid value
    int mustPid = 2798;

    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts, *tsp;

    if (tgid == mustPid) {
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);
    }

    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = bpf_map_lookup_elem(&starts, &pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate current thread's delta time
    u64 t_start = *tsp;
    u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&starts, &pid);
    if (t_start > t_end) {
        return 0;
    }

    u64 delta = t_end - t_start;
	// create map key
    struct key_t key = {};
    key.tid = pid;
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));
    key.t = delta;

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));

    return 0;
}
