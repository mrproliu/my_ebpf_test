// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct statics {
    int count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct statics));
    __uint(max_entries, 10000);
} test_map SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    u32 kZero = 0;
    struct statics *statics_value = bpf_map_lookup_elem(&test_map, &kZero);
    if (!statics_value) {
        struct statics tmp = {.count = 1};
        bpf_map_update_elem(&test_map, &kZero, &tmp, BPF_ANY);
        statics_value = bpf_map_lookup_elem(&test_map, &kZero);
        return 0;
    }

    statics_value->count += 1;
    bpf_printk("total count: %d", statics_value->count);
    return 0;
}
