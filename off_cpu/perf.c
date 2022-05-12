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

typedef struct {
	int counter;
} atomic_t;

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct task_struct {
	int pid;
} __attribute__((preserve_access_index));

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct task_struct *p = (void *)PT_REGS_PARM1_CORE(ctx);
    int pid = BPF_CORE_READ(p, pid);
    bpf_printk("prev status: %d\n", pid);
    return 0;
}
