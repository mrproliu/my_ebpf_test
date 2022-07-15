

// +build ignore

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <asm/errno.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

struct key_t {
    __u32 pid;
    __u32 tid;
    int user_stack_id;
    int kernel_stack_id;
    char name[128];
};


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 100 * sizeof(__u64));
    __uint(max_entries, 10000);
} stacks SEC(".maps");

SEC("kprobe/security_socket_sendmsg")
int security_socket_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 tgid = (__u32)(id >> 32);
    if (tgid == 9341) {
        // create map key
        struct key_t key = {.pid = tgid};
        bpf_get_current_comm(&key.name, sizeof(key.name));

        // get stacks
        key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
        key.user_stack_id = bpf_get_stackid(ctx, &stacks, (1ULL << 8));

        bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
        bpf_printk("9118 send msg\n");
    }
    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int security_socket_recvmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 tgid = (__u32)(id >> 32);
    if (tgid == 9341) {
        bpf_printk("9118 recv msg\n");
    }
    return 0;
}