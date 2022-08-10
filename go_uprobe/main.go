//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf uprobe.c -- -I../headers

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("please input the pid need to be monitor")
		return
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("could not reconized the pid: %s", os.Args[1])
		return
	}
	fmt.Printf("read get link for pid: %d\n", pid)
	executeFile := fmt.Sprintf("/proc/%d/exe", pid)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	err = loadBpfObjects(objs, nil)
	if err != nil {
		log.Fatalf("loading objects: %s", err)
		return
	}
	defer objs.Close()

	executable, err := link.OpenExecutable(executeFile)
	if err != nil {
		log.Fatal("open executable file error: file: %s, error: %s", executable, err)
	}
	uprobe, err := executable.Uprobe("crypto/tls.(*Conn).Read", objs.GoTlsRead, nil)
	if err != nil {
		log.Fatalf("load uprobe error: %v", err)
	}
	defer uprobe.Close()
	uretprobe, err := executable.Uretprobe("crypto/tls.(*Conn).Read", objs.GoTlsRead, nil)
	if err != nil {
		log.Fatalf("load uretprobe error: %v", err)
	}
	defer uretprobe.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("Received signal, exiting program..")

}
