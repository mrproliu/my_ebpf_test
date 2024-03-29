#pragma once

#define MAX_DATA_SIZE_BUF 1

struct trace_event_raw_sys_enter {
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct trace_event_raw_sys_exit {
	long int id;
	long int ret;
	char __data[0];
};

typedef enum
{
    true=1, false=0
}bool;

// syscall:connect
struct connect_args_t {
    __u32 fd;
    struct sockaddr* addr;
    struct sock *sock;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct connect_args_t);
} conecting_args SEC(".maps");

// detect socket operation and send to the user space
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
    __u8 upstream_addr_v6[16];
    __u32 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
    __u8 downstream_addr_v6[16];
    __u32 downstream_port;
    __u32 fix;
    __u64 exe_time;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 4096);
} socket_opts_events_queue SEC(".maps");

#define CONNECTION_ROLE_TYPE_UNKNOWN 0
#define CONNECTION_ROLE_TYPE_CLIENT 1
#define CONNECTION_ROLE_TYPE_SERVER 2
struct active_connection_t {
    // process id
    __u32 pid;
    // process command line
    char comm[128];
    // socket file descriptor
    __u32 sockfd;
    // the type of role in current connection
    __u32 role;
    // socket type
    __u32 socket_family;
    // upstream(works on server and client side)
    __u32 upstream_addr_v4;
    __u8 upstream_addr_v6[16];
    __u32 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
    __u8 downstream_addr_v6[16];
    __u16 downstream_port;
    __u64 total_bytes;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct active_connection_t);
} active_connection_map SEC(".maps");
static __inline __u64 gen_tgid_fd(__u32 tgid, __u32 fd) {
  return ((__u64)tgid << 32) | fd;
}

// syscall:sendto
#define SOCK_DATA_FUNC_SENDTO 1
#define SOCK_DATA_FUNC_RECVFROM 2
#define SOCK_DATA_FUNC_READ 3
#define SOCK_DATA_FUNC_WRITE 4
#define SOCK_DATA_FUNC_WRITEV 5
#define SOCK_DATA_FUNC_SEND 6
#define SOCK_DATA_FUNC_SENDMSG 7
struct sock_data_args_t {
    __u32 func;
    __u32 fd;
    const char* buf;
    // Used to filter out read/write and readv/writev calls that are not to sockets.
    bool sock_event;
    const struct iovec* iov;
    size_t iovlen;
    __u64 start_nacs;
    __u32 rtt;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_data_args_t);
} writing_args SEC(".maps");

// socket write or receive data event, communicate with user space
#define SOCK_DATA_DIRECTION_INGRESS 1 //receive from
#define SOCK_DATA_DIRECTION_EGRESS 2  //write to
struct sock_data_event_t {
    __u32 pid;
    char comm[128];
    __u32 sockfd;
//    char buf[MAX_DATA_SIZE_BUF];
    __u32 buf_size;
    __u32 protocol_type;
    __u32 message_type;
    __u32 data_direction;
    __u64 exe_time;
    __u32 rtt;
    // socket type
    __u32 socket_family;
    // upstream(works on server and client side)
    __u32 upstream_addr_v4;
    __u8 upstream_addr_v6[16];
    __u32 upstream_port;
    // downstream(only works on server side)
    __u32 downstream_addr_v4;
    __u8 downstream_addr_v6[16];
    __u16 downstream_port;
    __u64 total_bytes;
    __u32 func;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sock_data_event_t);
    __uint(max_entries, 1);
} sock_data_event_creator_map SEC(".maps");
static __inline struct sock_data_event_t* create_sock_data() {
    __u32 kZero = 0;
    struct sock_data_event_t* event = bpf_map_lookup_elem(&sock_data_event_creator_map, &kZero);
    if (event == NULL) {
        return NULL;
    }
    return event;
}
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} socket_data_events_queue SEC(".maps");

// syscall:close
struct sock_close_args_t {
    int fd;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct sock_close_args_t);
} closing_args SEC(".maps");

// syscall:accept
struct accept_args_t {
    __u32 fd;
    struct sockaddr* addr;
    struct socket* socket;
    __u64 start_nacs;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct accept_args_t);
} accepting_args SEC(".maps");