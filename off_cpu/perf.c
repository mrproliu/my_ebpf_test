// +build ignore

#include <stddef.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct thread_info {
	long unsigned int flags;
	long unsigned int syscall_work;
	__u32 status;
};

struct task_struct {
	struct thread_info thread_info;
};

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct task_struct *p;
    struct thread_info *t;
    bpf_probe_read(&p, sizeof(p), (void *) PT_REGS_PARM1(ctx));
    bpf_probe_read(&t, sizeof(t), &(p->thread_info));
    __u32 status;
    long unsigned int syscall_work;
    bpf_probe_read(&status, sizeof(status), &(t->status));
    bpf_probe_read(&syscall_work, sizeof(syscall_work), &(t->syscall_work));
//    __u32 pid = 0;
//    bpf_probe_read(&pid, sizeof(pid), &(p->pid));
    bpf_printk("prev status: %d->%d\n", status, syscall_work);
    return 0;
}
