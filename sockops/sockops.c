// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* User bpf_sock_ops struct to access socket values and specify request ops
 * and their replies.
 * Some of this fields are in network (bigendian) byte order and may need
 * to be converted before use (bpf_ntohl() defined in samples/bpf/bpf_endian.h).
 * New fields can only be added at the end of this structure
 */
struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];		/* Optionally passed to bpf program */
		__u32 reply;		/* Returned by bpf program	    */
		__u32 replylong[4];	/* Optionally returned by bpf prog  */
	};
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	__u32 is_fullsock;	/* Some TCP fields are only valid if
				 * there is a full socket. If not, the
				 * fields read as zero.
				 */
	__u32 snd_cwnd;
	__u32 srtt_us;		/* Averaged RTT << 3 in usecs */
	__u32 bpf_sock_ops_cb_flags; /* flags defined in uapi/linux/tcp.h */
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
};
//
//static __always_inline void sk_extract4_key(const struct bpf_sock_ops *ops,
//					    struct sock_key *key)
//{
//	key->dip4 = ops->remote_ip4;
//	key->sip4 = ops->local_ip4;
//	key->family = 1;
//}
//
//static __always_inline void sk_lb4_key(struct lb4_key *lb4,
//					  const struct sock_key *key)
//{
//	/* SK MSG is always egress, so use daddr */
//	lb4->address = key->dip4;
//	lb4->dport = (__u16)key->dport;
//}
//
//static __always_inline bool redirect_to_proxy(int verdict)
//{
//	return verdict > 0;
//}
//
//static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
//{
//	struct lb4_key lb4_key = {};
//	__u32 dip4, dport, dst_id = 0;
//	struct endpoint_info *exists;
//	struct lb4_service *svc;
//	struct sock_key key = {};
//	int verdict;
//
//	sk_extract4_key(skops, &key);
//
//	/* If endpoint a service use L4/L3 stack for now. These can be
//	 * pulled in as needed.
//	 */
//	sk_lb4_key(&lb4_key, &key);
//	svc = lb4_lookup_service(&lb4_key, true);
//	if (svc)
//		return;
//
//	/* Policy lookup required to learn proxy port */
//	if (1) {
//		struct remote_endpoint_info *info;
//
//		info = lookup_ip4_remote_endpoint(key.dip4);
//		if (info != NULL && info->sec_label)
//			dst_id = info->sec_label;
//		else
//			dst_id = WORLD_ID;
//	}
//
//	verdict = policy_sk_egress(dst_id, key.sip4, (__u16)key.dport);
//	if (redirect_to_proxy(verdict)) {
//		__be32 host_ip = IPV4_GATEWAY;
//
//		key.dip4 = key.sip4;
//		key.dport = key.sport;
//		key.sip4 = host_ip;
//		key.sport = verdict;
//
//		sock_hash_update(skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);
//		return;
//	}
//
//	/* Lookup IPv4 address, this will return a match if:
//	 * - The destination IP address belongs to the local endpoint manage
//	 *   by Cilium.
//	 * - The destination IP address is an IP address associated with the
//	 *   host itself.
//	 * Then because these are local IPs that have passed LB/Policy/NAT
//	 * blocks redirect directly to socket.
//	 */
//	exists = __lookup_ip4_endpoint(key.dip4);
//	if (!exists)
//		return;
//
//	dip4 = key.dip4;
//	dport = key.dport;
//	key.dip4 = key.sip4;
//	key.dport = key.sport;
//	key.sip4 = dip4;
//	key.sport = dport;
//
//	sock_hash_update(skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);
//}
//#endif /* ENABLE_IPV4 */


struct key_t {
    u32 pid;
    u32 tid;
    char name[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} counts SEC(".maps");

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;
	bpf_printk("hello:%d, %d\n", family, op);
	return 0;
}
