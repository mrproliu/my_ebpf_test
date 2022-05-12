// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES	10000

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
    __u64 id = bpf_get_current_pid_tgid();
    struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
    __u32 pid = 0;
    bpf_probe_read_user(&pid, sizeof(pid), &(p->pid));
    bpf_printk("hello: test: %d:%d\n", id, pid);
    return 0;
}
