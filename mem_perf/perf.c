// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    int user_stack_id;
    int kernel_stack_id;
    u64 size;
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//	__uint(max_entries, 10);
//} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 100 * sizeof(u64));
    __uint(max_entries, 10000);
} stacks SEC(".maps");

SEC("uprobe/malloc_enter")
int malloc_enter(struct pt_regs *ctx) {
    struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
	task_info->user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));

	bpf_ringbuf_submit(task_info, 0);


//    struct key_t key = {};
//    // get stacks
//    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
//    key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));
//
//    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));

    return 0;
}
