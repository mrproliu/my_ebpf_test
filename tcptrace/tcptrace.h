struct connect_args_t {
  __u32 fd;
  struct sockaddr* addr;
};

struct accept_sock_t {
    __u32 fd;
	struct socket* socket;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} conecting_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct accept_sock_t);
} accept_socks SEC(".maps");