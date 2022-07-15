

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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} test_queue SEC(".maps");

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

static __always_inline void submit_new_connection(struct pt_regs* ctx, __u32 from_type, __u32 tgid, __u32 fd, __u64 start_nacs,
                                            struct sockaddr* addr, const struct socket* socket) {
    __u64 curr_nacs = bpf_ktime_get_ns();
    // active connection save
    struct active_connection_t con = {};
    con.pid = tgid;
    bpf_get_current_comm(&con.comm, sizeof(con.comm));
    con.sockfd = fd;
    con.role = CONNECTION_ROLE_TYPE_CLIENT;
    __u16 port;
    if (socket != NULL) {
        // only get from accept function(server side)
        struct sock* s;
        BPF_CORE_READ_INTO(&s, socket, sk);

        short unsigned int skc_family;
        BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
        con.socket_family = skc_family;
        if (con.socket_family == AF_INET) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            con.upstream_port = port;
            BPF_CORE_READ_INTO(&con.upstream_addr_v4, s, __sk_common.skc_rcv_saddr);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            con.downstream_port = port;
            BPF_CORE_READ_INTO(&con.downstream_addr_v4, s, __sk_common.skc_daddr);
        } else if (con.socket_family == AF_INET6) {
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_num);
            con.upstream_port = port;
            BPF_CORE_READ_INTO(&con.upstream_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
            BPF_CORE_READ_INTO(&port, s, __sk_common.skc_dport);
            con.downstream_port = port;
            BPF_CORE_READ_INTO(&con.downstream_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
       }
    } else if (addr != NULL) {
        con.socket_family = _(addr->sa_family);
        if (con.socket_family == AF_INET) {
            struct sockaddr_in *daddr = (struct sockaddr_in *)addr;
            bpf_probe_read(&con.upstream_addr_v4, sizeof(con.upstream_addr_v4), &daddr->sin_addr.s_addr);
            bpf_probe_read(&port, sizeof(con.upstream_port), &daddr->sin_port);
            con.upstream_port = port;
        } else if (con.socket_family == AF_INET6) {
            struct sockaddr_in6 *daddr = (struct sockaddr_in6 *)addr;
            bpf_probe_read(&con.upstream_addr_v6, sizeof(con.upstream_addr_v6), &daddr->sin6_addr.s6_addr);
            bpf_probe_read(&port, sizeof(con.upstream_port), &daddr->sin6_port);
            con.upstream_port = port;
        }
    }
    __u64 conid = gen_tgid_fd(tgid, fd);
    bpf_map_update_elem(&active_connection_map, &conid, &con, 0);

    if (con.socket_family != AF_INET && con.socket_family != AF_INET6) {
        bpf_printk("current create connect is not ip address, so ignores. %d, from type: %d\n", con.socket_family, from_type);
        return;
    }

    // event send
    struct sock_opts_event opts_event = {};
    opts_event.type = from_type;
    opts_event.pid = tgid;
    bpf_get_current_comm(&opts_event.comm, sizeof(opts_event.comm));
    opts_event.sockfd = fd;
    opts_event.upstream_addr_v4 = con.upstream_addr_v4;
    memcpy(opts_event.upstream_addr_v6, con.upstream_addr_v6, 16*sizeof(__u8));
    opts_event.upstream_port = con.upstream_port;
    opts_event.downstream_addr_v4 = con.downstream_addr_v4;
    memcpy(opts_event.downstream_addr_v6, con.downstream_addr_v6, 16*sizeof(__u8));
    opts_event.downstream_port = con.downstream_port;
    opts_event.exe_time = curr_nacs - start_nacs;
//    bpf_printk("execute time: start: %d, cur: %d, exe: %d\n", start_nacs, curr_nacs, opts_event.exe_time);

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
    __u32 tgid = id >> 32;

    struct sock *sock = connect_args->sock;
    struct socket *s = _(sock->sk_socket);
    submit_new_connection(ctx, SOCKET_OPTS_TYPE_CONNECT, tgid, connect_args->fd, connect_args->start_nacs, connect_args->addr, s);
}

SEC("kprobe/security_socket_sendmsg")
int security_socket_sendmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 tgid = (__u32)(id >> 32);
    if (tgid == 9118) {
        bpf_printk("9118 send msg");
    }
    return 0;
}

SEC("kprobe/security_socket_recvmsg")
int security_socket_recvmsg(struct pt_regs* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u64 tgid = (__u32)(id >> 32);
    if (tgid == 9118) {
        bpf_printk("9118 recv msg");
    }
    return 0;
}