struct connect_args_t {
    __u32 fd;
    struct sockaddr* addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} conecting_args SEC(".maps");

#define SOCKET_OPTS_TYPE_CONNECT 1
#define SOCKET_OPTS_TYPE_ACCEPT  2
#define SOCKET_OPTS_TYPE_CLOSE   3
struct sock_opts_event {
    // connect, accept, close
    __u32 type;
    // process id
    __u32 pid;
    // process command line
    char comm[128];
    // socket file descriptor
    __u32 sockfd;
    // upstream(works on server and client side)
    __u32 upstream_addr_v4;
//    __u8 upstream_addr_v6[16];
    __u16 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
//    __u8 downstream_addr_v6[16];
    __u16 downstream_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_opts_events_queue SEC(".maps");

struct active_connection_t {
};

struct accept_sock_t {
    __u32 fd;
	struct socket* socket;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct accept_sock_t);
} accept_socks SEC(".maps");