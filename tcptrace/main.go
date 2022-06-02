//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// #include <linux/types.h>
// #include <arpa/inet.h>
// #include <stdlib.h>
//
//char *addr_str(const void *addr, __u32 af) {
//	size_t size = af == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
//	char *str;
//
//	str = malloc(size);
//	if (!str)
//		return NULL;
//
//	inet_ntop(af, addr, str, size);
//
//	return str;
//}
//
//char *get_src_addr(const struct event *ev) {
//	if (ev->af == AF_INET)
//		return addr_str(&ev->saddr_v4, ev->af);
//	else if (ev->af == AF_INET6)
//		return addr_str(&ev->saddr_v6, ev->af);
//	else
//		return NULL;
//}
//
//char *get_dst_addr(const struct event *ev) {
//	if (ev->af == AF_INET)
//		return addr_str(&ev->daddr_v4, ev->af);
//	else if (ev->af == AF_INET6)
//		return addr_str(&ev->daddr_v6, ev->af);
//	else
//		return NULL;
//}
import "C"

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcptrace.c -- -I$HOME/headers/ -D__TARGET_ARCH_x86

type Event struct {
	SourceAddr uint32
	DistAddr   uint32
	Comm       [128]byte
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe("tcp_v4_connect", objs.BpfTcpV4Connect)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()
	kpre, err := link.Kretprobe("tcp_v4_connect", objs.BpfTcpV4ConnectRet)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpre.Close()
	log.Printf("start probes success...")

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		rd.Close()
	}()

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("%d -> %d, comm: %s\n", event.SourceAddr, event.DistAddr, event.Comm)
	}
}
