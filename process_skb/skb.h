
#include "tcp.h"

#define MAX_PROTOCOL_SOCKET_READ_LENGTH 31

struct recv_msg_args {
    struct sock* sock;
    struct msghdr* msg;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, __u64);
	__type(value, struct recv_msg_args);
} receiving_args SEC(".maps");


struct socket_buffer_reader_t {
    __u32 data_len;
    char buffer[MAX_PROTOCOL_SOCKET_READ_LENGTH + 1];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct socket_buffer_reader_t);
    __uint(max_entries, 1);
} socket_buffer_reader_map SEC(".maps");