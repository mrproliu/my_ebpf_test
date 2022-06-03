struct connect_args_t {
  __u32 fd;
  struct sockaddr* addr;
};

union sockaddr_t {
  struct sockaddr sa;
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;
};