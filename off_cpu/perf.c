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
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, __u64);
	__uint(max_entries, 10000);
} counts SEC(".maps");

struct task_struct {
	__u32 pid;
    __u32 tgid;
}  __attribute__((preserve_access_index));

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

SEC("kprobe/finish_task_switch")
int do_finish_task_switch(struct pt_regs *ctx) {
    int monitor_pid;
    asm("%0 = MONITOR_PID ll" : "=r"(monitor_pid));

    __u32 pid;
    __u64 ts, *tsp, *val, zero = 0;

    struct task_struct *prev = (void *) PT_REGS_PARM1(ctx);
    pid = _(prev->pid);

    if (pid == monitor_pid) {
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);
    }

    __u64 id = bpf_get_current_pid_tgid();
    pid = id;
    tsp = bpf_map_lookup_elem(&starts, &pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    __u64 t_start = *tsp;
    __u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&starts, &pid);
    if (t_start > t_end) {
        return 0;
    }

//    __u64 delta = t_end - t_start;
    // create map key
    struct key_t key = {};
    key.tid = pid;
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));

    val = bpf_map_lookup_elem(&counts, &key);
    if (!val) {
         bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);
         val = bpf_map_lookup_elem(&counts, &key);
         if (!val)
             return 0;
    }
    (*val) += 1;
    return 0;
}