//go:build linux
// +build linux

package main

import (
	"bufio"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcp.c -- -I../headers

type Event struct {
	Name          [50]byte
	KernelStackId uint32
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

	writeVEnter, writeVExit := kprobe("sys_sendto", objs.SysSendto, objs.SysSendtoRet)
	tcpSendMsg, tcpSendMsgExit := kprobe("tcp_sendmsg", objs.TcpSendmsg, objs.TcpSendmsgRet)
	defer writeVEnter.Close()
	defer writeVExit.Close()
	defer tcpSendMsg.Close()
	defer tcpSendMsgExit.Close()

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
	//
	//rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	//if err != nil {
	//	log.Fatalf("creating perf event reader: %s", err)
	//}
	//defer rd.Close()
	//
	//kernelFileProfilingStat, err := tools.KernelFileProfilingStat()
	//if err != nil {
	//	log.Fatalf("read symbol error: %v", err)
	//}
	//
	//var event Event
	//for {
	//	record, err := rd.Read()
	//	if err != nil {
	//		if errors.Is(err, perf.ErrClosed) {
	//			return
	//		}
	//		log.Printf("reading from perf event reader: %s", err)
	//		continue
	//	}
	//
	//	if record.LostSamples != 0 {
	//		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
	//		continue
	//	}
	//
	//	// Parse the perf event entry into an Event structure.
	//	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
	//		log.Printf("parsing perf event: %s", err)
	//		continue
	//	}
	//
	//	val := make([]uint64, 100)
	//	fmt.Printf("kernel:\n")
	//	err = objs.Stacks.Lookup(event.KernelStackId, &val)
	//	if err != nil {
	//		fmt.Printf("err look up : %d, %v\n", event.KernelStackId, err)
	//		continue
	//	}
	//	symbols := kernelFileProfilingStat.FindSymbols(val, "[MISSING]")
	//	for _, s := range symbols {
	//		fmt.Printf("%s\n", s)
	//	}
	//
	//	fmt.Printf("---------------\n")
	//}

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
	r2, err := link.Kretprobe(symbol, exit)
	if err != nil {
		log.Fatalf("attach exit failure, symbol: %s, error: %v", symbol, err)
	}
	return r1, r2
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}
