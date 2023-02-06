//go:build linux
// +build linux

package main

import (
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const (
	BPFSocketAttach = 50
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf skb.c      -- -I$HOME/headers/ -D__TARGET_ARCH_x86

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading objects: %s", err)
		return
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kprobe, err := link.Kprobe("tcp_sendmsg", objs.TcpSendmsg)
	if err != nil {
		log.Fatal(err)
	}
	defer kprobe.Close()
	kprobe2, err := link.Kprobe("tcp_recvmsg", objs.TcpRecvmsg)
	if err != nil {
		log.Fatal(err)
	}
	defer kprobe2.Close()
	kprobe1, err := link.Kretprobe("tcp_recvmsg", objs.RetTcpRecvmsg)
	if err != nil {
		log.Fatal(err)
	}
	defer kprobe1.Close()

	<-stopper
}
