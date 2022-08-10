// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("uprobe/go_tls_read")
int go_tls_read(struct pt_regs *ctx) {
    return 0;
}
