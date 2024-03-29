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

SEC("perf_event")
int do_perf_event(struct pt_regs *ctx) {
    // should change the pid value
    int monitor_pid;
    asm("%0 = MONITOR_PID ll" : "=r"(monitor_pid));

    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 tid = id;

    if (tgid != monitor_pid) {
        return 0;
    }

	// create map key
    struct key_t key = {.pid = tgid};
    key.tid = tid;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    // get stacks
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));

    return 0;
}
