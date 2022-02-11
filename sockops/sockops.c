// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    u32 pid;
    u32 tid;
    char name[128];
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

//SEC("sockops")
//int sockops(struct pt_regs *ctx) {
//SEC("kprobe/sys_execve")
//int kprobe_execve(struct pt_regs *ctx) {
SEC("sockops")
int bpf_sockmap(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 tid = id;

	// create map key
    struct key_t key = {.pid = tgid};
    key.tid = tid;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
