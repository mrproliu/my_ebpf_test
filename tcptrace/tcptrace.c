

// +build ignore

#include "api.h"
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>

char __license[] SEC("license") = "Dual MIT/GPL";

typedef __u64 __addrpair;
typedef __u32 __portpair;


struct sock_common {
		__addrpair skc_addrpair;
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common	__sk_common;
} __attribute__((preserve_access_index));

SEC("kprobe/tcp_v4_connect")
int bpf_tcp_v4_connect(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    __be32 skc_rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	bpf_printk("send tcp v4 connect: %d, %x\n", skc_rcv_saddr, skc_rcv_saddr);
	return 0;
}
