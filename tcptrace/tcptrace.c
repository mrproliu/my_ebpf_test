

// +build ignore

#include "api.h"
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>

char __license[] SEC("license") = "Dual MIT/GPL";

typedef __u64 __addrpair;
typedef __u32 __portpair;


struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		}  __attribute__((preserve_access_index));
	};
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

typedef unsigned short __kernel_sa_family_t;
typedef __kernel_sa_family_t	sa_family_t;
struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct sockaddr));
    __uint(max_entries, 10000);
} connect_socks SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int bpf_tcp_v4_connect(int sockfd, const struct sockaddr* addr) {
//    int fd = PT_REGS_PARM1(ctx);
////    struct sockaddr *addr = (void *)PT_REGS_PARM2(ctx);
    __u64 pid = bpf_get_current_pid_tgid();
    bpf_printk("enter connect: %d, pid\n", sockfd, pid);
//    bpf_map_update_elem(&connect_socks, &pid, addr, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int bpf_tcp_v4_connect_ret(struct pt_regs *ctx) {
//    __u64 pid = bpf_get_current_pid_tgid();
//    struct sock *sk;

//    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
//    if (sk == NULL) {
//        return 0;        // missed start or filtered
//    }

//    __u16 skc_daddr = BPF_CORE_READ(sk, __sk_common.skc_num);
//    __be16 skc_rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_dport);
//	bpf_printk("send tcp v4 connect return: %d, %d\n", skc_daddr, skc_rcv_saddr);
	return 0;
}
