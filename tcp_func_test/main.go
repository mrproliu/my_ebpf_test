//go:build linux
// +build linux

package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcp.c -- -I../headers

type Event struct {
	Pid    uint32
	TaskId uint32
	Name   [128]byte
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	writeVEnter, writeVExit := kprobe("sys_write", objs.SysWritev, objs.SysWritevRet)
	defer writeVEnter.Close()
	defer writeVExit.Close()

	//// Get the first-mounted cgroupv2 path.
	//cgroupPath, err := detectCgroupPath()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//// Link the count_egress_packets program to the cgroup.
	//l, err := link.AttachCgroup(link.CgroupOptions{
	//	Path:    cgroupPath,
	//	Attach:  ebpf.AttachCGroupInetIngress,
	//	Program: objs.BpfSockmap,
	//})
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer l.Close()

	log.Println("Counting packets...")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}

func kprobe(symbol string, enter, exit *ebpf.Program) (link.Link, link.Link) {
	r1, err := link.Kprobe(symbol, enter)
	if err != nil {
		log.Fatalf("attach enter failure, symbol: %s, error: %v", symbol, err)
	}
	r2, err := link.Kretprobe(symbol, enter)
	if err != nil {
		log.Fatalf("attach exit failure, symbol: %s, error: %v", symbol, err)
	}
	return r1, r2
}

//// detectCgroupPath returns the first-found mount point of type cgroup2
//// and stores it in the cgroupPath global variable.
//func detectCgroupPath() (string, error) {
//	f, err := os.Open("/proc/mounts")
//	if err != nil {
//		return "", err
//	}
//	defer f.Close()
//
//	scanner := bufio.NewScanner(f)
//	for scanner.Scan() {
//		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
//		fields := strings.Split(scanner.Text(), " ")
//		if len(fields) >= 3 && fields[2] == "cgroup2" {
//			return fields[1], nil
//		}
//	}
//
//	return "", errors.New("cgroup2 not mounted")
//}
