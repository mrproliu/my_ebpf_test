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
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct key_t key = {};
//    struct task_struct *prev = (struct task_struct *) PT_REGS_PARM1(ctx);
//    bpf_probe_read_user(&key.prevTgid, sizeof(key.prevTgid), &prev->tgid);
//    bpf_probe_read_user(&key.prevPid, sizeof(key.prevPid), &prev->pid);
//    struct task_struct *curr = (struct task_struct *) bpf_get_current_task();
//    bpf_probe_read_user(&key.currTgid, sizeof(key.currTgid), &curr->tgid);
//    bpf_probe_read_user(&key.currPid, sizeof(key.currPid), &curr->pid);
//    __u32 pid = 0;
    __u64 ts = bpf_ktime_get_ns();

    __u64 id = bpf_get_current_pid_tgid();
//    __u32 tgid = id >> 32;

    struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
    __u32 pid;
    pid = _(p->pid);
//    void* prevTaskV = (void*)PT_REGS_PARM1(ctx);
//    struct task_struct prevTask;
//    bpf_probe_read_user(&prevTask, sizeof(prevTask), prevTaskV);
//    bpf_probe_read(&key.prevPid, sizeof(key.prevPid), &prevTask.pid);
    bpf_printk("hello: test: %d:%d\n", id, pid);
	// create map key
//    struct key_t key = {};
//    key.pid = pid;
    key.ts = ts;

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
