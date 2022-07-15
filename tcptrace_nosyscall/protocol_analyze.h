
#pragma once

#include "tcptrace.h"

#define SOCK_DATA_MESSAGE_TYPE_UNKNOWN 0
#define SOCK_DATA_MESSAGE_TYPE_REQUEST 1
#define SOCK_DATA_MESSAGE_TYPE_RESPONSE 2

#define SOCK_DATA_PROTOCOL_TYPE_UNKNOWN 0
#define SOCK_DATA_PROTOCOL_TYPE_HTTP 1

static __inline void sock_data_analyze_protocol(const char* data, __u32 len, struct sock_data_event_t* event) {
    if (len < 16) {
        return;
    }

    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
        event->protocol_type = SOCK_DATA_PROTOCOL_TYPE_HTTP;
        event->message_type = SOCK_DATA_MESSAGE_TYPE_REQUEST;
    } else if (data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P') {
        event->protocol_type = SOCK_DATA_PROTOCOL_TYPE_HTTP;
        event->message_type = SOCK_DATA_MESSAGE_TYPE_RESPONSE;
    }else {
        event->protocol_type = SOCK_DATA_PROTOCOL_TYPE_UNKNOWN;
        event->message_type = SOCK_DATA_MESSAGE_TYPE_UNKNOWN;
    }
}