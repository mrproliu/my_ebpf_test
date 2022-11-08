// +build ignore

#include <stddef.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <arpa/inet.h>
#include <bpf_tracing.h>
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define test_printk(fmt, args...) \
({                              \
    uint64_t id = bpf_get_current_pid_tgid();   \
    __u32 tgid = (__u32)(id >> 32);             \
    if (tgid == 19062) {                        \
    ___bpf_pick_printk(args)(fmt, ##args);      \
    }                                           \
})

struct key_t {
    __u32 name[50];
    int kernel_stack_id;
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

//SEC("kprobe/sys_sendto")
//int sys_sendto(struct pt_regs* ctx) {
//    test_printk("sys sys_sendto enter");
//    return 0;
//}
//
//SEC("kretprobe/sys_sendto")
//int sys_sendto_ret(struct pt_regs* ctx) {
//    test_printk("sys sys_sendto exit");
//    return 0;
//}

SEC("kprobe/write")
int sys_write(struct pt_regs* ctx) {
    test_printk("sys write enter");
    return 0;
}

SEC("kretprobe/write")
int sys_write_ret(struct pt_regs* ctx) {
    ssize_t bytes_count = PT_REGS_RC(ctx);
    test_printk("sys write exit: %lld", bytes_count);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs* ctx) {
    test_printk("tcp_sendmsg enter");
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int tcp_sendmsg_ret(struct pt_regs* ctx) {
    test_printk("tcp_sendmsg exit");
    return 0;
}

SEC("kprobe/tcp_push")
int tcp_push(struct pt_regs* ctx) {
    test_printk("sys tcp_push enter");
    return 0;
}

SEC("kretprobe/tcp_push")
int tcp_push_ret(struct pt_regs* ctx) {
    test_printk("sys tcp_push exit");
    return 0;
}

struct tmp {
    struct sk_buff *skb;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct tmp);
} active_connection_map SEC(".maps");

#define SKB_DST_NOREF	1UL
#define SKB_DST_PTRMASK	~(SKB_DST_NOREF)
typedef int64_t s64;
typedef s64	ktime_t;

struct tcp_skb_cb {
	__u32 seq;
	__u32 end_seq;
} __attribute__((preserve_access_index));

struct sk_buff {
    union {
        struct {
            struct sk_buff *next;
            struct sk_buff *prev;
            union {
                struct net_device *dev;
                long unsigned int dev_scratch;
            };
        };
    };
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		long unsigned int _sk_redir;
	};
	union {
        ktime_t		tstamp;
        __u64		skb_mstamp_ns; /* earliest departure time */
    };
	unsigned int len;
	unsigned int data_len;
	union {
        struct sock		*sk;
        int			ip_defrag_offset;
    };
    char			cb[48];
} __attribute__((preserve_access_index));

struct dst_entry {
	struct net_device *dev;
} __attribute__((preserve_access_index));

struct net_device {
	int ifindex;
	unsigned long		state;
	unsigned int		mtu;
} __attribute__((preserve_access_index));

struct rtable {
	struct dst_entry	dst;
} __attribute__((preserve_access_index));

struct net {
	int ifindex;
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u32 copied_seq;
	__u32 write_seq;
} __attribute__((preserve_access_index));


SEC("kprobe/ip_output")
int ip_output(struct pt_regs* ctx) {
    struct sock *sock = (void *)PT_REGS_PARM2(ctx);
    struct tcp_sock *tcp_sock = (struct tcp_sock *)sock;
    struct sk_buff *buff = (void *)PT_REGS_PARM3(ctx);

    long unsigned int _skb_refdst;
    bpf_probe_read(&_skb_refdst, sizeof(_skb_refdst), &buff->_skb_refdst);
    struct dst_entry *entry = (void *)(_skb_refdst & SKB_DST_PTRMASK);

    struct net_device *device;
    bpf_probe_read(&device, sizeof(device), &entry->dev);

    // 当前网卡的索引
    int ifindex;
    bpf_probe_read(&ifindex, sizeof(ifindex), &device->ifindex);

    // 没有太大的意义，可以忽略掉
    __u32 write_seq;
    bpf_probe_read(&write_seq, sizeof(write_seq), &tcp_sock->write_seq);

    // 当前发送的数据大小
    unsigned int data_len;
    bpf_probe_read(&data_len, sizeof(data_len), &buff->data_len);

    test_printk("ip_output before, ifindex: %d, data_len: %lld, seq: %d", ifindex, data_len, write_seq);
    return 0;
}

SEC("kprobe/recvmsg")
int sys_recvmsg(struct pt_regs* ctx) {
     test_printk("sys sys recvmsg enter");
    return 0;
}

SEC("kretprobe/recvmsg")
int sys_recvmsg_ret(struct pt_regs* ctx) {
     test_printk("sys sys recvmsg exit");
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int tcp_recvmsg(struct pt_regs* ctx) {
     test_printk("sys tcp_recvmsg enter");
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int tcp_recvmsg_ret(struct pt_regs* ctx) {
     test_printk("sys tcp_recvmsg exit");
    return 0;
}

SEC("kprobe/ip_rvc")
int ip_rcv(struct pt_regs* ctx) {
    test_printk("ip_rcv enter");
    return 0;
}

SEC("kretprobe/ip_rvc")
int ip_rcv_ret(struct pt_regs* ctx) {
    test_printk("ip_rcv exit");
    return 0;
}

SEC("kprobe/ip_rvc_finish")
int ip_rcv_finish(struct pt_regs* ctx) {
     test_printk("ip_rcv_finish enter");
    return 0;
}

SEC("kretprobe/ip_rvc_finish")
int ip_rcv_finish_ret(struct pt_regs* ctx) {
    test_printk("ip_rcv_finish exit");
    return 0;
}

SEC("kprobe/read")
int read(struct pt_regs* ctx) {
     test_printk("sys read enter");
    return 0;
}

SEC("kretprobe/read")
int read_ret(struct pt_regs* ctx) {
    test_printk("sys read exit");
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(void *));
    __uint(value_size, sizeof(void *));
    __uint(max_entries, 10000);
} buff_tmp SEC(".maps");

SEC("kprobe/ip_local_deliver_finish")
int ip_local_deliver_finish(struct pt_regs* ctx) {
    test_printk("ip_local_deliver enter");
    const struct sk_buff *buff = (void *)PT_REGS_PARM3(ctx);
    struct net *net = (void *)PT_REGS_PARM1(ctx);
    struct net_device *device;
    bpf_probe_read(&device, sizeof(device), &buff->dev);
//    if (device) {
//       bpf_printk("device exists in deliver");
//    } else {
//       bpf_printk("device not exists in deliver");
//    }
//    int ifindex = 0;
//    bpf_probe_read(&ifindex, sizeof(ifindex), &net->ifindex);
//    ktime_t		tstamp;
//    bpf_probe_read(&tstamp, sizeof(tstamp), &buff->tstamp);
//    bpf_printk("ip local deliver ifindex: %d, ts: %lld", ifindex, tstamp);
    bpf_map_update_elem(&buff_tmp, &buff, &net, 0);
    return 0;
}

SEC("kretprobe/ip_local_deliver_finish")
int ip_local_deliver_finish_ret(struct pt_regs* ctx) {
    test_printk("ip_local_deliver exit");
    return 0;
}

SEC("kprobe/skb_copy_datagram_msg")
int skb_copy_datagram_msg(struct pt_regs* ctx) {
    const struct sk_buff *buff = (void *)PT_REGS_PARM1(ctx);

    struct net *valp;
    valp = bpf_map_lookup_elem(&buff_tmp, &buff);
    int ifindex = 0;
    if (valp) {
        bpf_probe_read(&ifindex, sizeof(ifindex), &valp->ifindex);
    }
     struct net_device *device;
    bpf_probe_read(&device, sizeof(device), &buff->dev);
    if (device) {
       bpf_printk("device exists in copy");
    } else {
       bpf_printk("device not exists in copy");
    }
//    struct net_device *device;
//    bpf_probe_read(&device, sizeof(device), &buff->dev);
//    if (device) {
//        bpf_printk("device exists");
//    } else {
//        bpf_printk("device not exists");
//    }

//    long unsigned int dev_scratch;
//    bpf_probe_read(&dev_scratch, sizeof(dev_scratch), &buff->dev_scratch);

    ktime_t		tstamp;
    bpf_probe_read(&tstamp, sizeof(tstamp), &buff->tstamp);

    unsigned int data_len;
    bpf_probe_read(&data_len, sizeof(data_len), &buff->data_len);
    // ignore, 数据需要在ip_local_deliver_finish(kprobe)中获取并且利用map来转换，成本可能较高(因为ip_local_deliver_finish频率较高，不区分应用)，要考虑
    test_printk("skb copy: ifindex: %lld, data_len: %d, receive timestamp: %lld", ifindex, data_len, tstamp);
    return 0;
}

SEC("kretprobe/skb_copy_datagram_msg")
int skb_copy_datagram_msg_ret(struct pt_regs* ctx) {
    test_printk("skb_copy_datagram_iter exit");
    return 0;
}

SEC("kprobe/tcp_v4_rcv")
int tcp_v4_rcv(struct pt_regs* ctx) {
     test_printk("tcp_v4_rcv enter");
    return 0;
}

SEC("kretprobe/tcp_v4_rcv")
int tcp_v4_rcv_ret(struct pt_regs* ctx) {
    test_printk("tcp_v4_rcv exit");
    return 0;
}

//SEC("cgroup_skb/egress")
//int bpf_sockmap(struct pt_regs *ctx)
//{
////    struct sock* s;
////    BPF_CORE_READ_INTO(&s, buff, sk);
////    test_printk("sock addr: %p", s);
//
////    short unsigned int skc_family = 0;
////    BPF_CORE_READ_INTO(&skc_family, buff, family);
////    __u32 local_port = 0;
////    __u32 remote_port = 0;
////    __u16 port = 0;
////
////    BPF_CORE_READ_INTO(&port, buff, local_port);
////    local_port = port;
////    BPF_CORE_READ_INTO(&port, buff, remote_port);
////    remote_port = bpf_ntohs(port);
//
////    __u32 remote_port = buff->remote_port;
////    remote_port = __bpf_ntohs(buff->remote_port);
////	test_printk("family: %d, local port: %d, remote_port: %d\n", buff->family, buff->local_port, remote_port);
//	return 1;
//}
