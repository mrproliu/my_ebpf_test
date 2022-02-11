// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    u32 pid;
    u32 tid;
    char name[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("sockops")
int bpf_sockmap(struct pt_regs *ctx) {
    bpf_printk("hello\n");
    return 0;
}
