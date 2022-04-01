// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    int user_stack_id;
    int kernel_stack_id;
    u64 size;
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 100 * sizeof(u64));
    __uint(max_entries, 10000);
} stacks SEC(".maps");

SEC("uprobe/malloc_enter")
int malloc_enter(struct pt_regs *ctx) {
    struct key_t *key;
    key = bpf_ringbuf_reserve(&counts, sizeof(struct key_t), 0);
	if (!key) {
		return 0;
	}

    // get stacks
    key->kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key->user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));

	bpf_ringbuf_submit(key, 0);

    return 0;
}
