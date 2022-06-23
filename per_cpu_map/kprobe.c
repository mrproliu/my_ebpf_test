// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    u32 pid;
    u32 random;
    char name[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct key_t);
    __uint(max_entries, 1);
} per_cpu_key_map SEC(".maps");
static __inline struct key_t* create_key() {
    __u32 kZero = 0;
    struct key_t* event = bpf_map_lookup_elem(&per_cpu_key_map, &kZero);
    if (event == NULL) {
        return NULL;
    }
    return event;
}

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

	// create map key
	struct key_t *key = create_key();
    key->pid = tgid;
    bpf_get_current_comm(&key->name, sizeof(key->name));
    key->random = bpf_get_prandom_u32();

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
