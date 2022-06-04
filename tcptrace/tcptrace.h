struct connect_args_t {
  __u32 fd;
  struct sockaddr* addr;
};

struct accept_sock_t {
    __u32 fd;
	struct socket* socket;
};