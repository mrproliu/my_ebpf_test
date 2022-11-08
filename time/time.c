// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

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

SEC("uprobe/perf_event")
int do_perf_event(struct pt_regs *ctx) {
    __u64 time = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &time, sizeof(time));
    return 0;
}
