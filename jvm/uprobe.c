// +build ignore

#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
	u32 pid;
	char comm[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("uprobe/JVM_InvokeMethod")
int uprobe_jvm_invoke_method(struct pt_regs *ctx) {
	struct event_t event;

	event.pid = bpf_get_current_pid_tgid();

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}
