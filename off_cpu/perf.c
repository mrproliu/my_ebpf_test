// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES	10000

struct task_struct {
	__u32 pid;
    __u32 tgid;
};

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct task_struct *p = (void *) bpf_get_current_task();
    /* record previous thread sleep time */
    __u32 pid = _(p->pid);
//    struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
//    __u32 pid = 0;
//    bpf_probe_read_user(&pid, sizeof(pid), &(p->pid));
    bpf_printk("hello: test: %d:%d\n", id, pid);
    return 0;
}
