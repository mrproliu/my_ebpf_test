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

struct value_t {
    __u64 counts;
    __u64 deltas;
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
	__type(value, struct value_t);
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

    __u32 pid, tgid;
    __u64 ts, *tsp;

    struct task_struct *prev = (void *) PT_REGS_PARM1(ctx);
    pid = _(prev->pid);
    tgid = _(prev->tgid);

    __u64 curid = bpf_get_current_pid_tgid();
    __u32 curpid = curid;
    __u32 curtgid = curid >> 32;
    if (curtgid == monitor_pid || tgid == monitor_pid) {
        bpf_printk("prev %d:%d\n", pid, tgid);
        bpf_printk("current: %d:%d\n", curpid, curtgid);
    }

    if (tgid == monitor_pid) {
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

    struct value_t *val;
    val = bpf_map_lookup_elem(&counts, &key);
    if (!val) {
        struct value_t value = {};
         bpf_map_update_elem(&counts, &key, &value, BPF_NOEXIST);
         val = bpf_map_lookup_elem(&counts, &key);
         if (!val)
             return 0;
    }
    (*val).counts += 1;
    (*val).deltas += t_end - t_start;
    return 0;
}