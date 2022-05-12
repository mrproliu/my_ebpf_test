// +build ignore

#include <stddef.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct task_struct {
	__u32 pid;
    __u32 tgid;
};

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct task_struct *p = (void *) PT_REGS_PARM1(ctx);
    __u32 pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &p);
    bpf_printk("prev pid: %d\n", pid);
    return 0;
}
