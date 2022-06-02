

// +build ignore

#include <stddef.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__uint(key_size, sizeof(__u64));
//	__uint(value_size, sizeof(struct sock));
//    __uint(max_entries, 10000);
//} connect_socks SEC(".maps");

struct key_t {
    __u64 skc_rcv_saddr;
    char name[128];
};

#define MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");


typedef __u32 __portpair;
typedef __u64 __addrpair;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

struct sock_common {
	/* skc_daddr and skc_rcv_saddr must be grouped on a 8 bytes aligned
	 * address on 64bit arches : cf INET_MATCH()
	 */
	union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;
			__be32	skc_rcv_saddr;
		} __attribute__((preserve_access_index));
	};
	union  {
		unsigned int	skc_hash;
		__u16		skc_u16hashes[2];
	};
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;
			__u16	skc_num;
		} __attribute__((preserve_access_index));
	};

	unsigned short		skc_family;
	volatile unsigned char	skc_state;
	unsigned char		skc_reuse:4;
	unsigned char		skc_reuseport:1;
	unsigned char		skc_ipv6only:1;
	unsigned char		skc_net_refcnt:1;
	int			skc_bound_dev_if;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common	__sk_common;
} __attribute__((preserve_access_index));

SEC("kprobe/tcp_connect")
int bpf_tcp_v4_connect(struct pt_regs *ctx) {
//    struct sockaddr *uaddr = (void *)PT_REGS_PARM2(ctx);
////    struct sockaddr *addr = (void *)PT_REGS_PARM2(ctx);
//    __u64 pid = bpf_get_current_pid_tgid();
//    __u64 family = _(uaddr->sa_family);
//    bpf_printk("connect before, family: %d, pid: %d", family, pid);
//    bpf_map_update_elem(&connect_socks, &pid, sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_connect")
int bpf_tcp_v4_connect_ret(struct pt_regs *ctx) {
//    __u64 pid = bpf_get_current_pid_tgid();
//    struct sock *sk;

    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
//    if (sk == NULL) {
//        return 0;        // missed start or filtered
//    }

//    __u16 skc_daddr = BPF_CORE_READ(sk, __sk_common.skc_num);
//    __be16 skc_rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_dport);
//	bpf_printk("send tcp v4 connect return: %d, %d\n", skc_daddr, skc_rcv_saddr);
    struct key_t key = {};
    key.skc_rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_addrpair);
    bpf_get_current_comm(&key.name, sizeof(key.name));
    bpf_perf_event_output(ctx, &counts, BPF_F_CURRENT_CPU, &key, sizeof(key));
	return 0;
}
