//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/go-multierror"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcptrace.c -- -I$HOME/headers/ -D__TARGET_ARCH_x86

type Event struct {
	SourceAddrV4 uint32
	DistAddrV4   uint32
	SourceAddrV6 [16]uint8
	DistAddrV6   [16]uint8
	SourcePort   uint16
	DistPort     uint16
	IpVersion    uint16
	Comm         [128]byte
}

type LinkFunc func(symbol string, prog *ebpf.Program) (link.Link, error)

type MultipleLinker struct {
	links     []link.Link
	linkError error
}

func (m *MultipleLinker) AddLink(name string, linkF LinkFunc, p *ebpf.Program) {
	l, e := linkF(name, p)
	if e != nil {
		m.linkError = multierror.Append(m.linkError, fmt.Errorf("open %s error: %v", name, e))
	} else {
		m.links = append(m.links, l)
	}
}

func (m *MultipleLinker) HasError() error {
	return m.linkError
}

func (m *MultipleLinker) Close() error {
	var err error
	for _, l := range m.links {
		if e := l.Close(); e != nil {
			err = multierror.Append(err, e)
		}
	}
	return err
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
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	linker := &MultipleLinker{}
	linker.AddLink("tcp_v4_connect", link.Kprobe, objs.BpfTcpV4Connect)
	linker.AddLink("tcp_v4_connect", link.Kretprobe, objs.BpfTcpV4ConnectRet)
	linker.AddLink("tcp_v6_connect", link.Kprobe, objs.BpfTcpV6Connect)
	linker.AddLink("tcp_v6_connect", link.Kretprobe, objs.BpfTcpV6ConnectRet)
	defer linker.Close()
	err := linker.HasError()
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
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

		var fromAddr, distAddr string
		if event.IpVersion == 4 {
			fromAddr = parseAddressV4(event.SourceAddrV4)
			distAddr = parseAddressV4(event.DistAddrV4)
		} else {
			fromAddr = parseAddressV6(event.SourceAddrV6)
			distAddr = parseAddressV6(event.DistAddrV6)
		}
		fmt.Printf("%s:%d -> %s:%d, comm: %s\n", fromAddr, parsePort(event.SourcePort),
			distAddr, parsePort(event.DistPort), event.Comm)
	}
}
