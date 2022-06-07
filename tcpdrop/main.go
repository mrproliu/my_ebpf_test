//go:build linux
// +build linux

package main

import (
	"bytes"
	"ebpf_test/tools/btf"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcpdrop.c -- -I$HOME/headers/ -D__TARGET_ARCH_x86

type TcpDropEvent struct {
	Pid              uint32
	Comm             [128]byte
	Family           uint16
	UpstreamAddrV4   uint32
	UpstreamAddrV6   [16]uint8
	UpstreamPort     uint32
	DownstreamAddrV4 uint32
	DownstreamAddrV6 [16]uint8
	DownstreamPort   uint32
}

func parsePort(val uint16) uint16 {
	return binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&val)))[:])
}

func parseAddressV4(val uint32) string {
	return net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&val)))[:]).String()
}

func parseAddressV6(val [16]uint8) string {
	return net.IP((*(*[net.IPv6len]byte)(unsafe.Pointer(&val)))[:]).String()
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
	if err := loadBpfObjects(&objs, btf.GetEBPFCollectionOptionsIfNeed()); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kprobe, err := link.Kprobe("tcp_drop", objs.TcpDrop)
	if err != nil {
		log.Fatalf("link tcp drop failure: %v", err)
	}
	defer kprobe.Close()
	log.Printf("start probes success...")

	eventsFd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event sock data reader: %s", err)
	}
	defer eventsFd.Close()

	go func() {
		var event TcpDropEvent
		for {
			record, err := eventsFd.Read()
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

			var downstreamAddr, upstreamAddr string
			if syscall.AF_INET == event.Family {
				downstreamAddr = parseAddressV4(event.DownstreamAddrV4)
				upstreamAddr = parseAddressV4(event.UpstreamAddrV4)
			} else {
				downstreamAddr = parseAddressV6(event.DownstreamAddrV6)
				upstreamAddr = parseAddressV6(event.UpstreamAddrV6)
			}
			fmt.Printf("TCP DROP: familu: %d: %s:%d(in %d(%s)) -> %s:%d\n", event.Family, downstreamAddr, parsePort(uint16(event.DownstreamPort)),
				event.Pid, event.Comm, upstreamAddr, parsePort(uint16(event.UpstreamPort)))
		}
	}()

	<-stopper
	log.Println("Received signal, exiting program..")
}
