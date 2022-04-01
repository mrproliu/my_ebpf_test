// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    int user_stack_id;
    int kernel_stack_id;
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
    __uint(max_entries, 10000);
} stack_count_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 100 * sizeof(u64));
    __uint(max_entries, 10000);
} stacks SEC(".maps");

SEC("uprobe/malloc_enter")
int malloc_enter(struct pt_regs *ctx) {
    // get stacks
    u32 id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));
    u64 initval = 1, *valp;

    bpf_printk("recieve event123\n");
    valp = bpf_map_lookup_elem(&stack_count_map, &id);
    if (!valp) {
         bpf_printk("add new data\n");
         bpf_map_update_elem(&stack_count_map, &id, &initval, BPF_ANY);
         return 0;
    }
    bpf_printk("update data, %d\n", &valp);
    __sync_fetch_and_add(valp, 1);

    return 0;
}
