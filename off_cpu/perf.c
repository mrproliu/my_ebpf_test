// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    __u64 prevPid;
    __u64 prevTgid;
    __u64 currPid;
    __u64 currTgid;
    __u64 ts;
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct task_struct {
	int pid;
    int tgid;
};

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val = 0;                                             \
		bpf_probe_read_user(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct key_t key = {};
    __u64 id = bpf_get_current_pid_tgid();
    struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
    __u32 pid;
    pid = _(p->pid);
    bpf_printk("hello: test: %d:%d\n", id, pid);

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
