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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcp.c -- -I../headers -D__TARGET_ARCH_x86

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

	sysSendMsg, sysSendMsgRet := kprobe("sys_write", objs.SysWrite, objs.SysWriteRet)
	sysRecvMsg, sysRecvMsgRet := kprobe("sys_recvmsg", objs.SysRecvmsg, objs.SysRecvmsgRet)

	tcpSendMsg, tcpSendMsgExit := kprobe("tcp_sendmsg", objs.TcpSendmsg, objs.TcpSendmsgRet)
	tcpRecvMsg, tcpRecvMsgExit := kprobe("tcp_recvmsg", objs.TcpRecvmsg, objs.TcpRecvmsgRet)
	tcpPush, tcpPushExit := kprobe("tcp_push", objs.TcpPush, objs.TcpPushRet)
	ipLocal, _ := kprobe("ip_finish_output", objs.IpOutput, nil)

	ipRcv, ipRcvRet := kprobe("ip_rcv", objs.IpRcv, objs.IpRcvRet)
	ipRcvFinish, ipRcvFinishRet := kprobe("ip_rcv_finish", objs.IpRcvFinish, objs.IpRcvFinishRet)
	read, readRet := kprobe("sys_read", objs.Read, objs.ReadRet)
	ipLocalDeliver, ipLocalDeliverRet := kprobe("ip_local_deliver_finish", objs.IpLocalDeliverFinish, objs.IpLocalDeliverFinishRet)
	skbCopyDatagramMsg, skbCopyDatagramMsgRet := kprobe("skb_copy_datagram_iter", objs.SkbCopyDatagramMsg, objs.SkbCopyDatagramMsgRet)
	tcpV4Rcv, tcpV4RcvRet := kprobe("tcp_v4_rcv", objs.TcpV4Rcv, objs.TcpV4RcvRet)
	defer sysSendMsg.Close()
	defer sysSendMsgRet.Close()
	defer sysRecvMsg.Close()
	defer sysRecvMsgRet.Close()
	defer tcpSendMsg.Close()
	defer tcpSendMsgExit.Close()
	defer tcpRecvMsg.Close()
	defer tcpRecvMsgExit.Close()
	defer tcpPush.Close()
	defer tcpPushExit.Close()
	defer ipLocal.Close()

	defer ipRcv.Close()
	defer ipRcvRet.Close()
	defer ipRcvFinish.Close()
	defer ipRcvFinishRet.Close()
	defer read.Close()
	defer readRet.Close()
	defer ipLocalDeliver.Close()
	defer ipLocalDeliverRet.Close()
	defer skbCopyDatagramMsg.Close()
	defer skbCopyDatagramMsgRet.Close()
	defer tcpV4Rcv.Close()
	defer tcpV4RcvRet.Close()

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
	var r1, r2 link.Link
	var err error
	if enter != nil {
		r1, err = link.Kprobe(symbol, enter)
		if err != nil {
			log.Fatalf("attach enter failure, symbol: %s, error: %v", symbol, err)
		}
	}
	if exit != nil {
		r2, err = link.Kretprobe(symbol, exit)
		if err != nil {
			log.Fatalf("attach exit failure, symbol: %s, error: %v", symbol, err)
		}
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
