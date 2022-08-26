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
	short unsigned int skc_family;
	struct in6_addr_redefine		skc_v6_daddr;
    struct in6_addr_redefine		skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct socket {
	struct sock		*sk;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common	__sk_common;
	struct socket		*sk_socket;
} __attribute__((preserve_access_index));

struct tcp_sock {
	__u32 srtt_us;
} __attribute__((preserve_access_index));

struct sk_buff {
	union {
		struct sock *sk;
		int ip_defrag_offset;
	};
} __attribute__((preserve_access_index));
