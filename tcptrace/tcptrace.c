

// +build ignore

#include "api.h"
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct sock_common {
	unsigned short		skc_family;
	union {
		struct {
			__u32	skc_daddr;
			__u32	skc_rcv_saddr;
		};
	};
	union {
		struct {
			__u16	skc_dport;
			__u16	skc_num;
		};
	};
};

struct sock {
	struct sock_common	__sk_common;
};


SEC("kprobe/tcp_v4_connect")
int bpf_tcp_v4_connect(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    __u32 fromaddr = _(sk->__sk_common.skc_rcv_saddr);
	bpf_printk("send tcp v4 connect: %x\n", fromaddr);
	return 0;
}
