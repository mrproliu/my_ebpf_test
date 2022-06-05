

#define SOCK_DATA_PROTOCOL_TYPE_UNKNOWN 0
#define SOCK_DATA_PROTOCOL_TYPE_HTTP 1

static __inline __u32 sock_data_analyze_protocol(const char* data, __u32 len) {
    if (len < 16) {
        return 0;
    }

    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
        bpf_printk("get request \n");
    } else {
        bpf_printk("unknown\n");
    }
    return 0;
}