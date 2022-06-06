

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
#include "tcptrace.h"
#include "protocol_analyze.h"
#include "socket.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

static __inline void submit_close_connection(struct pt_regs* ctx, __u32 tgid, __u32 fd) {
    __u64 conid = gen_tgid_fd(tgid, fd);
    struct active_connection_t* con = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (con == NULL) {
//        bpf_printk("could not found active connection when close sock, pid: %d, sockfd: %d\n", tgid, fd);
        return;
    }
    // event send
    struct sock_opts_event opts_event = {};
    opts_event.type = SOCKET_OPTS_TYPE_CLOSE;
    opts_event.pid = tgid;
    bpf_get_current_comm(&opts_event.comm, sizeof(opts_event.comm));
    opts_event.sockfd = fd;
    bpf_perf_event_output(ctx, &socket_opts_events_queue, BPF_F_CURRENT_CPU, &opts_event, sizeof(opts_event));

    bpf_map_delete_elem(&active_connection_map, &conid);
}

static __always_inline void submit_new_connection(struct pt_regs* ctx, __u32 from_type, __u32 tgid, __u32 fd,
                                            struct sockaddr* addr, const struct socket* socket) {
    // event send
    struct sock_opts_event opts_event = {};
    opts_event.type = from_type;
    opts_event.pid = tgid;
    bpf_get_current_comm(&opts_event.comm, sizeof(opts_event.comm));
    opts_event.sockfd = fd;
    // TODO support ipv4 for now
    if (addr != NULL) {
        struct sockaddr_in *daddr = (struct sockaddr_in *)addr;
        bpf_probe_read(&opts_event.upstream_addr_v4, sizeof(opts_event.upstream_addr_v4), &daddr->sin_addr.s_addr);
        bpf_probe_read(&opts_event.upstream_port, sizeof(opts_event.upstream_port), &daddr->sin_port);
        opts_event.upstream_port = bpf_ntohs(opts_event.upstream_port);
    }
    if (socket != NULL) {
        // only get from accept function(server side)
        struct sock* s;
        BPF_CORE_READ_INTO(&s, socket, sk);

        BPF_CORE_READ_INTO(&opts_event.upstream_port, s, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&opts_event.upstream_addr_v4, s, __sk_common.skc_rcv_saddr);

        BPF_CORE_READ_INTO(&opts_event.downstream_port, s, __sk_common.skc_dport);
        BPF_CORE_READ_INTO(&opts_event.downstream_addr_v4, s, __sk_common.skc_daddr);
//        opts_event.upstream_port = bpf_ntohs(bpf_ntohs(opts_event.upstream_port));
//        opts_event.downstream_port = bpf_ntohs(bpf_ntohs(opts_event.downstream_port));
    }

    bpf_perf_event_output(ctx, &socket_opts_events_queue, BPF_F_CURRENT_CPU, &opts_event, sizeof(opts_event));

    // active connection save
    struct active_connection_t con = {};
    con.pid = tgid;
//    strcpy(con.comm, opts_event.comm);
    con.sockfd = fd;
    con.role = CONNECTION_ROLE_TYPE_CLIENT;
    con.upstream_addr_v4 = opts_event.upstream_addr_v4;
    memcpy(con.upstream_addr_v6, opts_event.upstream_addr_v6, 16*sizeof(__u8));
    con.upstream_port = opts_event.upstream_port;
    con.downstream_addr_v4 = opts_event.downstream_addr_v4;
//    strcpy(con.downstream_addr_v6, opts_event.downstream_addr_v6);
    con.downstream_port = opts_event.downstream_port;
    __u64 conid = gen_tgid_fd(tgid, fd);
    bpf_map_update_elem(&active_connection_map, &conid, &con, 0);
}

static __inline void process_connect(struct pt_regs* ctx, __u64 id, struct connect_args_t *connect_args) {
    int ret = PT_REGS_RC(ctx);
    if (ret < 0 && ret != -EINPROGRESS) {
        return;
    }
    if (connect_args->fd < 0) {
        return;
    }
    __u32 tgid = id >> 32;

    struct sock *sock = connect_args->sock;
    struct socket *s = _(sock->sk_socket);
    submit_new_connection(ctx, SOCKET_OPTS_TYPE_CONNECT, tgid, connect_args->fd, connect_args->addr, s);
}

SEC("kprobe/__sys_connect")
int sys_connect(struct pt_regs *ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct connect_args_t connect_args = {};
    connect_args.fd = PT_REGS_PARM1(ctx);
    connect_args.addr = (void *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&conecting_args, &id, &connect_args, 0);
    bpf_printk("enter sys connect--: %d\n", id);
	return 0;
}

SEC("kretprobe/__sys_connect")
int sys_connect_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;
    bpf_printk("exit sys connect--: %d\n", id);

    connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args) {
        __u32 tgid = id >> 32;
        bpf_printk("connect to ret: pid: %d, fd: %d\n", tgid, connect_args->fd);
        process_connect(ctx, id, connect_args);
    }

    bpf_map_delete_elem(&conecting_args, &id);
	return 0;
}

SEC("kprobe/tcp_v4_v6_connect")
int tcp_v4_v6_connect(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct connect_args_t *connect_args;

    connect_args = bpf_map_lookup_elem(&conecting_args, &id);
    if (connect_args) {
        connect_args->sock = (void *)PT_REGS_PARM1(ctx);
        bpf_printk("detected tcp connect hook\n");
    }
    return 0;
}

SEC("kprobe/__sys_sendto")
int sys_sendto(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct sock_data_args_t data_args = {};
    data_args.func = SOCK_DATA_FUNC_SENDTO;
    data_args.fd = PT_REGS_PARM1(ctx);
    data_args.buf = (void *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&writing_args, &id, &data_args, 0);
//    __u32 tgid = id >> 32;
//    bpf_printk("send to: pid: %d, fd: %d\n", tgid, data_args.fd);
    return 0;
}

static __inline void process_write_data(struct pt_regs* ctx, __u64 id, struct sock_data_args_t *args, ssize_t bytes_count, __u32 data_direction) {
    __u32 tgid = (__u32)(id >> 32);
    if (args->buf == NULL) {
        return;
    }
    if (args->fd < 0) {
        return;
    }
    if (bytes_count <= 0) {
        return;
    }

    __u32 data_len = bytes_count < MAX_DATA_SIZE_BUF ? (bytes_count & MAX_DATA_SIZE_BUF - 1) : MAX_DATA_SIZE_BUF;
    struct sock_data_event_t* data = create_sock_data();
    if (data == NULL) {
        return;
    }

    data->sockfd = args->fd;
    data->pid = tgid;
    data->data_direction = data_direction;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    const char* buf;
    bpf_probe_read(&buf, sizeof(const char*), &args->buf);
    bpf_probe_read(data->buf, data_len, buf);
    data->buf_size = data_len;
//
    char *p = data->buf;
    sock_data_analyze_protocol(p, data_len, data);
    __u64 conid = gen_tgid_fd(tgid, args->fd);
    struct active_connection_t* con = bpf_map_lookup_elem(&active_connection_map, &conid);
    if (con == NULL) {
//        bpf_printk("could not found active connection, pid: %d, sockfd: %d\n", tgid, args->fd);
    }
    bpf_perf_event_output(ctx, &socket_data_events_queue, BPF_F_CURRENT_CPU, data, sizeof(struct sock_data_event_t));
}

SEC("kretprobe/__sys_sendto")
int sys_sendto_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args;
    ssize_t bytes_count = PT_REGS_RC(ctx);

    data_args = bpf_map_lookup_elem(&writing_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_EGRESS);
    }

    bpf_map_delete_elem(&writing_args, &id);
    return 0;
}

SEC("kprobe/__sys_close")
int sys_close(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct sock_close_args_t close_args = {};
    close_args.fd = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&closing_args, &id, &close_args, 0);
//    __u32 tgid = id >> 32;
//    bpf_printk("close to: pid: %d, fd: %d\n", tgid, close_args.fd);
    return 0;
}

static __inline void process_close_sock(struct pt_regs* ctx, __u64 id, struct sock_close_args_t *args) {
    __u32 tgid = (__u32)(id >> 32);
    int ret = PT_REGS_RC(ctx);
//    bpf_printk("close ret: pid: %d, fd: %d, ret: %d", tgid, args->fd, ret);
    if (ret < 0) {
        return;
    }
    if (args->fd < 0) {
        return;
    }

    submit_close_connection(ctx, tgid, args->fd);
}

SEC("kretprobe/__sys_close")
int sys_close_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_close_args_t *close_args;

    close_args = bpf_map_lookup_elem(&closing_args, &id);
    if (close_args) {
        process_close_sock(ctx, id, close_args);
    }

    bpf_map_delete_elem(&writing_args, &id);
    return 0;
}


SEC("kprobe/__sys_recvfrom")
int sys_recvfrom(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct sock_data_args_t data_args = {};
    data_args.func = SOCK_DATA_FUNC_RECVFROM;
    data_args.fd = PT_REGS_PARM1(ctx);
    data_args.buf = (void *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&writing_args, &id, &data_args, 0);
    return 0;
}

SEC("kretprobe/__sys_recvfrom")
int sys_recvfrom_ret(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct sock_data_args_t *data_args;
    ssize_t bytes_count = PT_REGS_RC(ctx);

    data_args = bpf_map_lookup_elem(&writing_args, &id);
    if (data_args) {
        process_write_data(ctx, id, data_args, bytes_count, SOCK_DATA_DIRECTION_INGRESS);
    }

    bpf_map_delete_elem(&writing_args, &id);
    return 0;
}


//
//SEC("tracepoint/syscalls/sys_enter_writev")
//int syscall__probe_entry_writev(struct trace_event_raw_sys_enter *ctx) {
//    int fd = ctx->args[0];
//    int len = ctx->args[2];
//    bpf_printk("heelo writev: %d->%d\n", fd, len);
//    return 0;
//}

SEC("kprobe/__sys_accpet")
int sys_accept(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t sock = {};
    sock.addr = (void *)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&accepting_args, &id, &sock, 0);
    return 0;
}

static __inline void process_accept(struct pt_regs* ctx, __u64 id, struct accept_args_t *accept_args) {
    int fd = PT_REGS_RC(ctx);
    if (fd < 0) {
        return;
    }
    __u32 tgid = id >> 32;

    submit_new_connection(ctx, SOCKET_OPTS_TYPE_ACCEPT, tgid, fd, accept_args->addr, accept_args->socket);
}


SEC("kretprobe/__sys_accpet")
int sys_accept_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_sock;
    accept_sock = bpf_map_lookup_elem(&accepting_args, &id);
    if (accept_sock) {
        process_accept(ctx, id, accept_sock);
    }
    bpf_map_delete_elem(&accepting_args, &id);
    return 0;
}

SEC("kretprobe/sock_alloc")
int sock_alloc_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *accept_sock;
    accept_sock = bpf_map_lookup_elem(&accepting_args, &id);
    if (accept_sock) {
        struct socket *sock = (struct socket*)PT_REGS_RC(ctx);
        accept_sock->socket = sock;
    }
    return 0;
}