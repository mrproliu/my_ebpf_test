// +build ignore

#include <stddef.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct task_struct {
	int pid;
} __attribute__((preserve_access_index));

struct key_t {
    __u32 pid;
    __u32 tgid;
    char name[256];
    char comm[128];
};

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    struct task_struct *p = (struct task_struct *) PT_REGS_PARM1(ctx);
    struct key_t key = {};
    bpf_core_read(&key.pid, sizeof(key.pid), &p->pid);
    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    bpf_printk("hello:%d\n", key.pid);
    return 0;
}
