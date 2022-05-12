// +build ignore

#include "api.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_ENTRIES	10000

struct task_struct {
	__u32 pid;
    __u32 tgid;
};

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
    __u32 pid = 0;
    bpf_probe_read(&pid, sizeof(pid), &(p->pid));
    bpf_printk("prev pid: %d\n", pid);
    return 0;
}
