

// +build ignore

#include <stddef.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcptrace.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

struct key_t {
    __u32 from_addr_v4;
    __u32 dist_addr_v4;
    __u8  from_addr_v6[16];
    __u8  dist_addr_v6[16];
    __u16 from_port;
    __u16 dist_port;
    __u16 ip_ver;
    char comm[128];
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

struct in6_addr_redefine {
	union {
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
} __attribute__((preserve_access_index));

typedef __u32 __portpair;
typedef __u64 __addrpair;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

struct sock_common {
	union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;
			__be32	skc_rcv_saddr;
		} __attribute__((preserve_access_index));
	};
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;
			__u16	skc_num;
		} __attribute__((preserve_access_index));
	};
	struct in6_addr_redefine		skc_v6_daddr;
    struct in6_addr_redefine		skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct file {
	struct inode		*f_inode;	/* cached value */
}  __attribute__((preserve_access_index));

struct socket {
	struct file		*file;
	struct sock		*sk;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common	__sk_common;
	struct socket		*sk_socket;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} socketaddrs SEC(".maps");

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;

	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret, int ip_ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;

	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp)
		return 0;
	bpf_map_delete_elem(&sockets, &tid);

	sk = *skpp;

    struct key_t key = {};
    key.ip_ver = ip_ver;
	BPF_CORE_READ_INTO(&key.from_port, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&key.dist_port, sk, __sk_common.skc_dport);
	if (ip_ver == 4) {
	    BPF_CORE_READ_INTO(&key.from_addr_v4, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&key.dist_addr_v4, sk, __sk_common.skc_daddr);
	} else {
	    BPF_CORE_READ_INTO(&key.from_addr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&key.dist_addr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}

	bpf_get_current_comm(&key.comm, sizeof(key.comm));

    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));

	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int bpf_tcp_v4_connect(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int bpf_tcp_v4_connect_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    bpf_printk("say v4 connnect\n");
    return exit_tcp_connect(ctx, ret, 4);
}

SEC("kprobe/tcp_v6_connect")
int bpf_tcp_v6_connect(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int bpf_tcp_v6_connect_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    return exit_tcp_connect(ctx, ret, 6);
}

struct trace_event_raw_sys_enter {
	long int id;
	long unsigned int args[6];
	char __data[0];
} __attribute__((preserve_access_index));

SEC("kprobe/__sys_connect")
int BPF_KPROBE(__sys_connect, __u32 fd, struct sockaddr *addr) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Stash arguments.
    struct connect_args_t connect_args = {};
    connect_args.fd = fd;
    connect_args.addr = addr;
    bpf_map_update_elem(&socketaddrs, &id, &connect_args, 0);
    bpf_printk("con before: %d\n", connect_args.fd);
	return 0;
}

SEC("kretprobe/__sys_connect")
int sys_connect_ret(struct pt_regs *ctx, int ret) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = bpf_map_lookup_elem(&socketaddrs, &id);
    if (connect_args) {
        __u32 fd = connect_args->fd;
        union sockaddr_t addr = *((union sockaddr_t*)connect_args->addr);
        __be16 sin_port;
        sin_port = addr.in4.sin_port;
        bpf_printk("con after: %d->%d\n", fd, sin_port);
    }

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall__probe_entry_write(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    int len = ctx->args[2];
    bpf_printk("heelo write: %d->%d\n", fd, len);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int syscall__probe_entry_writev(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    int len = ctx->args[2];
    bpf_printk("heelo writev: %d->%d\n", fd, len);
    return 0;
}