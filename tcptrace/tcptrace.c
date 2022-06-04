

// +build ignore

#include <stddef.h>
#include <stdlib.h>
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
#include "tcptrace.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

static __inline void submit_new_connection(struct pt_regs* ctx, __u32 from_type, __u32 tgid, __u32 fd,
                                            struct sockaddr* addr, const struct socket* socket) {
    struct sock_opts_event opts_event = {};
    opts_event.type = from_type;
    opts_event.pid = tgid;
    bpf_get_current_comm(&opts_event.comm, sizeof(opts_event.comm));
    opts_event.sockfd = fd;
    if (addr != NULL) {
        // TODO support ipv4 for now
        struct sockaddr_in *daddr = (struct sockaddr_in *)addr;
        __u16 sin_port;
        bpf_probe_read(&opts_event.upstream_addr_v4, sizeof(opts_event.upstream_addr_v4), &daddr->sin_addr.s_addr);
        bpf_probe_read(&sin_port, sizeof(sin_port), &daddr->sin_port);
        opts_event.upstream_port = __bpf_ntohs(sin_port);

        opts_event.downstream_addr_v4 = opts_event.upstream_addr_v4;
    }

    bpf_perf_event_output(ctx, &socket_opts_events_queue, BPF_F_CURRENT_CPU, &opts_event, sizeof(opts_event));
}

static __inline void process_connect(struct pt_regs* ctx, __u64 id, struct connect_args_t *connect_args) {
    int ret = PT_REGS_RC(ctx);
    if (ret < 0 && ret != -EINPROGRESS) {
        return;
    }
    if (connect_args->fd < 0) {
        return;
    }
    __u32 pid = id >> 32;


    submit_new_connection(ctx, SOCKET_OPTS_TYPE_CONNECT, pid, connect_args->fd, connect_args->addr, NULL);
}

SEC("kprobe/__sys_connect")
int sys_connect(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Stash arguments.
    struct connect_args_t connect_args = {};
    connect_args.fd = PT_REGS_PARM1(ctx);
    connect_args.addr = (void *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
	return 0;
}

SEC("kretprobe/__sys_connect")
int sys_connect_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args) {
        process_connect(ctx, id, connect_args);
    }

    bpf_map_delete_elem(&conecting_args, &id);
	return 0;
}

//SEC("tracepoint/syscalls/sys_enter_write")
//int syscall__probe_entry_write(struct trace_event_raw_sys_enter *ctx) {
//    int fd = ctx->args[0];
//    struct sockaddr_in *addr_in = (struct sockaddr_in *)ctx->args[4];
//    __u16 family;
//    bpf_probe_read(&family, sizeof(family), &(addr_in->sin_family));
//    __u32 daddrv;
//    struct sockaddr_in *daddr = (struct sockaddr_in *)addr_in;
//    bpf_probe_read(&daddrv, sizeof(daddrv), &daddr->sin_addr.s_addr);
//    __u16 dport = 0;
//    bpf_probe_read(&dport, sizeof(dport), &daddr->sin_port);
//    bpf_printk("write: %d, family: %d\n", fd, family);
//    bpf_printk("write: addr: %d:%d\n", daddrv, dport);
//    return 0;
//}
//
//SEC("tracepoint/syscalls/sys_enter_writev")
//int syscall__probe_entry_writev(struct trace_event_raw_sys_enter *ctx) {
//    int fd = ctx->args[0];
//    int len = ctx->args[2];
//    bpf_printk("heelo writev: %d->%d\n", fd, len);
//    return 0;
//}
//
//SEC("kprobe/__sys_accpet")
//int sys_accept(struct pt_regs *ctx) {
//    int fd = PT_REGS_PARM1(ctx);
//    struct sockaddr *addr = (void *)PT_REGS_PARM2(ctx);
//    struct sockinfo s = get_sock_info(addr);
//    bpf_printk("socket accept: fd: %d\n", fd);
//    bpf_printk("socket accept: socket: %d->%d:%d\n", s.family, s.addr, s.port);
//    __u64 pid_tgid = bpf_get_current_pid_tgid();
//    struct accept_sock_t sock = {};
//    sock.fd = fd;
//    bpf_map_update_elem(&accept_socks, &pid_tgid, &sock, 0);
//    return 0;
//}
//
//SEC("kretprobe/__sys_accpet")
//int sys_accept_ret(struct pt_regs *ctx) {
//    __u64 pid_tgid = bpf_get_current_pid_tgid();
//    struct accept_sock_t *accept_sock;
//    accept_sock = bpf_map_lookup_elem(&accept_socks, &pid_tgid);
//    if (accept_sock) {
//        int fd = PT_REGS_RC(ctx);
//        __u32 fromfd = accept_sock->fd;
//        struct socket* sot = accept_sock->socket;
//        struct sock* s;
//        BPF_CORE_READ_INTO(&s, sot, sk);
//        struct key_t key = {};
//        BPF_CORE_READ_INTO(&key.from_port, s, __sk_common.skc_num);
//        BPF_CORE_READ_INTO(&key.dist_port, s, __sk_common.skc_dport);
//        BPF_CORE_READ_INTO(&key.from_addr_v4, s, __sk_common.skc_rcv_saddr);
//        BPF_CORE_READ_INTO(&key.dist_addr_v4, s, __sk_common.skc_daddr);
//
//        bpf_printk("socket accept ret: %d, from fd: %d\n", fd, fromfd);
//        // no need to transform the port
//        bpf_printk("socket accept ret: from sock: %d:%d\n", key.dist_addr_v4, key.dist_port);
//        bpf_printk("socket accept ret: dist sock: %d:%d\n", key.from_addr_v4, key.from_port);
//    }
//    return 0;
//}
//
//SEC("kretprobe/sock_alloc")
//int sock_alloc_ret(struct pt_regs *ctx) {
//    __u64 pid_tgid = bpf_get_current_pid_tgid();
//    struct accept_sock_t *accept_sock;
//    accept_sock = bpf_map_lookup_elem(&accept_socks, &pid_tgid);
//    if (accept_sock) {
//        struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
//        accept_sock->socket = sock;
//        bpf_printk("detect sock alloc from fd: %d\n", accept_sock->fd);
//    }
//    return 0;
//}