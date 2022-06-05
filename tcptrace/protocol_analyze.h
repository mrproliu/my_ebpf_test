//#include "tcptrace.h"


//#default SOCK_DATA_MESSAGE_TYPE_UNKNOWN 0
//#default SOCK_DATA_MESSAGE_TYPE_REQUEST 1
//#default SOCK_DATA_MESSAGE_TYPE_RESPONSE 2

#define SOCK_DATA_PROTOCOL_TYPE_UNKNOWN 0
#define SOCK_DATA_PROTOCOL_TYPE_HTTP 1

static __inline __u32 sock_data_analyze_protocol(const char* data, __u32 len, struct sock_data_event_t* event) {
    if (len < 16) {
        return 0;
    }

//    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
//        event->protocol_type = SOCK_DATA_PROTOCOL_TYPE_HTTP;
//        event->message_type = SOCK_DATA_MESSAGE_TYPE_REQUEST;
//        bpf_printk("get request \n");
//    } else {
//        bpf_printk("unknown\n");
//    }
    return 0;
}