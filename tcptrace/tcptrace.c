

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
} connect_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} socketaddrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, struct accept_sock_t);
} accept_socks SEC(".maps");

struct sockinfo {
    __u16 family;
    __u32 addr;
    __u16 port;
};

static __always_inline struct sockinfo
get_sock_info(struct sockaddr *addr)
{
    struct sockinfo s = {};
    bpf_probe_read(&s.family, sizeof(s.family), &(addr->sa_family));
    struct sockaddr_in *daddr = (struct sockaddr_in *)addr;
    bpf_probe_read(&s.addr, sizeof(s.addr), &daddr->sin_addr.s_addr);
    bpf_probe_read(&s.port, sizeof(s.port), &daddr->sin_port);
    return s;
}

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;

	bpf_map_update_elem(&connect_sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret, int ip_ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;

	skpp = bpf_map_lookup_elem(&connect_sockets, &tid);
	if (!skpp)
		return 0;
	bpf_map_delete_elem(&connect_sockets, &tid);

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

	bpf_map_delete_elem(&connect_sockets, &tid);
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

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_connect(struct trace_event_raw_sys_enter *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Stash arguments.
    struct connect_args_t connect_args = {};
    connect_args.fd = (__u32)ctx->args[0];
    connect_args.addr = (void *)ctx->args[1];
    bpf_map_update_elem(&socketaddrs, &id, &connect_args, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_connect_ret(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = bpf_map_lookup_elem(&socketaddrs, &id);
    if (connect_args) {
        __u32 fd = connect_args->fd;
        struct sockaddr_in *addr_in = (struct sockaddr_in *)connect_args->addr;

        __u16 family;
        bpf_probe_read(&family, sizeof(family), &(addr_in->sin_family));
        __u32 daddrv;
        struct sockaddr_in *daddr = (struct sockaddr_in *)addr_in;
        bpf_probe_read(&daddrv, sizeof(daddrv), &daddr->sin_addr.s_addr);
        __u16 dport = 0;
        bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
        bpf_printk("con: %d, family: %d\n", fd, family);
        bpf_printk("con: addr: %d:%d\n", daddrv, dport);
    }

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int syscall__probe_entry_write(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    struct sockaddr_in *addr_in = (struct sockaddr_in *)ctx->args[4];
    __u16 family;
    bpf_probe_read(&family, sizeof(family), &(addr_in->sin_family));
    __u32 daddrv;
    struct sockaddr_in *daddr = (struct sockaddr_in *)addr_in;
    bpf_probe_read(&daddrv, sizeof(daddrv), &daddr->sin_addr.s_addr);
    __u16 dport = 0;
    bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
    bpf_printk("write: %d, family: %d\n", fd, family);
    bpf_printk("write: addr: %d:%d\n", daddrv, dport);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int syscall__probe_entry_writev(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    int len = ctx->args[2];
    bpf_printk("heelo writev: %d->%d\n", fd, len);
    return 0;
}

SEC("kprobe/__sys_accpet")
int sys_accept(struct pt_regs *ctx) {
    int fd = PT_REGS_PARM1(ctx);
    struct sockaddr *addr = (void *)PT_REGS_PARM2(ctx);
    struct sockinfo s = get_sock_info(addr);
    bpf_printk("socket accept: fd: %d\n", fd);
    bpf_printk("socket accept: socket: %d->%d:%d\n", s.family, s.addr, s.port);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_sock_t sock = {};
    sock.fd = fd;
    bpf_map_update_elem(&accept_socks, &pid_tgid, &sock, 0);
    return 0;
}

SEC("kretprobe/__sys_accpet")
int sys_accept_ret(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_sock_t *accept_sock;
    accept_sock = bpf_map_lookup_elem(&accept_socks, &pid_tgid);
    if (accept_sock) {
        int fd = PT_REGS_RC(ctx);
        __u32 fromfd = accept_sock->fd;
//        struct socket* sot = accept_sock->socket;
//        struct sock* s;
//        BPF_CORE_READ_INTO(&s, sot, sk);
//        struct key_t key = {};
//        BPF_CORE_READ_INTO(&key.from_port, s, __sk_common.skc_num);
//        BPF_CORE_READ_INTO(&key.dist_port, s, __sk_common.skc_dport);
//        BPF_CORE_READ_INTO(&key.from_addr_v4, s, __sk_common.skc_rcv_saddr);
//        BPF_CORE_READ_INTO(&key.dist_addr_v4, s, __sk_common.skc_daddr);

        bpf_printk("socket accept ret: %d, from fd: %d\n", fd, fromfd);
//        bpf_printk("socket accept ret: dist sock: %d:%d\n", key.dist_addr_v4, key.dist_port);
    }
    return 0;
}

SEC("kretprobe/sock_alloc")
int sock_alloc_ret(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_sock_t *accept_sock;
    accept_sock = bpf_map_lookup_elem(&accept_socks, &pid_tgid);
    if (accept_sock) {
        struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
        accept_sock->socket = sock;
        bpf_printk("detect sock alloc from fd: %d\n", accept_sock->fd);
//        bpf_map_update_elem(&accept_socks, &pid_tgid, accept_sock, 0);
    }
    return 0;
}