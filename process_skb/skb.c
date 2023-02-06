#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <asm/errno.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "skb.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

// probing the tcp_data_queue kernel function, and adding the connection
// observed to the map.

static __always_inline void process_data(struct msghdr *msg) {
    const struct iovec *iovec;
    iovec = _(msg->msg_iter.iov);
    struct iovec iov;
    bpf_probe_read(&iov, sizeof(iov), iovec);
    char* buf = (char *)iov.iov_base;
    __u64 size = iov.iov_len;
    if (size <= 0) {
        return;
    }

    if (size > MAX_PROTOCOL_SOCKET_READ_LENGTH) {
        size = MAX_PROTOCOL_SOCKET_READ_LENGTH;
    }
    __u32 kZero = 0;
    struct socket_buffer_reader_t* reader = bpf_map_lookup_elem(&socket_buffer_reader_map, &kZero);
    if (reader == NULL) {
        return;
    }
    asm volatile("%[size] &= 0x1f;\n" ::[size] "+r"(size) :);
    bpf_probe_read(&reader->buffer, size & MAX_PROTOCOL_SOCKET_READ_LENGTH, buf);
    char *buffer = reader->buffer;
    if (buffer) {
       bpf_printk("send buffer[0]=%lld, buffer[1]=%lld, buffer[2]=%lld", buffer[0], buffer[1], buffer[2]);
       bpf_printk("send buffer[3]=%lld, buffer[4]=%lld, buffer[5]=%lld", buffer[3], buffer[4], buffer[5]);
       bpf_printk("send buffer[6]=%lld, buffer[7]=%lld, buffer[8]=%lld", buffer[6], buffer[7], buffer[8]);
       bpf_printk("send buffer[9]=%lld, buffer[10]=%lld, buffer[11]=%lld", buffer[9], buffer[10], buffer[11]);
       bpf_printk("send buffer[12]=%lld, buffer[13]=%lld, buffer[14]=%lld", buffer[12], buffer[13], buffer[14]);
       bpf_printk("send buffer[15]=%lld, buffer[16]=%lld, buffer[17]=%lld", buffer[15], buffer[16], buffer[17]);
       bpf_printk("send buffer[18]=%lld, buffer[19]=%lld, buffer[20]=%lld", buffer[18], buffer[19], buffer[20]);
       bpf_printk("send buffer[21]=%lld, buffer[22]=%lld, buffer[23]=%lld", buffer[21], buffer[22], buffer[23]);
   }
   if (buffer[0] == 'H' || buffer[0] == 'G') {
    bpf_printk("test1");
   } else {
    bpf_printk("test2");
   }

}

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid == 360674) {
        struct msghdr *msg = (void *)PT_REGS_PARM2(ctx);
        process_data(msg);
    }
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int tcp_recvmsg(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (tgid == 360674) {

        struct msghdr *msg = (void *)PT_REGS_PARM2(ctx);
        struct recv_msg_args args = {};
//        args.sock = sock;
        args.msg = msg;

        bpf_map_update_elem(&receiving_args, &id, &args, 0);
    }
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int ret_tcp_recvmsg(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct recv_msg_args *args = bpf_map_lookup_elem(&receiving_args, &id);
    int bytes_count = PT_REGS_RC(ctx);
    __u32 tgid = id >> 32;
    if (args != NULL && bytes_count > 0 && tgid == 360674) {
        process_data(args->msg);
    }
    bpf_map_delete_elem(&receiving_args, &id);
    return 0;
}