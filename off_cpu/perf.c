// +build ignore

#include <stddef.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    __u32 tid;
    int user_stack_id;
    int kernel_stack_id;
    __u64 t;
};

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 100 * sizeof(__u64));
    __uint(max_entries, 10000);
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
    __uint(max_entries, 10000);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct task_struct {
	__u32 pid;
    __u32 tgid;
};

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    __u32 pid;
    __u64 ts, *tsp;

    struct task_struct *prev = (void *) PT_REGS_PARM1(ctx);
    bpf_probe_read(&pid, sizeof(pid), &(prev->pid));
    bpf_printk("prev pid: %d", pid);

    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);

    struct task_struct *current = (void *)bpf_get_current_task();
    bpf_probe_read(&pid, sizeof(pid), &(current->pid));
    bpf_printk("current pid: %d", pid);
    tsp = bpf_map_lookup_elem(&starts, &pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    bpf_printk("current pid11111: %d", pid);
    __u64 t_start = *tsp;
    __u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&starts, &pid);
    if (t_start > t_end) {
        return 0;
    }

    bpf_printk("start: %d, end: %d", t_end, t_start);
    __u64 delta = t_end - t_start;
    // create map key
    struct key_t key = {};
    key.tid = pid;
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));
    key.t = delta;
    bpf_printk("aaaa pid: %d", pid);

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}
