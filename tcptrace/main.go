//go:build linux
// +build linux

package main

import (
	"bufio"
	"bytes"
	"ebpf_test/tools/btf"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/go-multierror"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcptrace.c -- -I$HOME/headers/ -D__TARGET_ARCH_x86

type SocketOptsEvent struct {
	Type             uint32
	Pid              uint32
	Comm             [128]byte
	SocketFd         uint32
	UpstreamAddrV4   uint32
	UpstreamAddrV6   [16]uint8
	UpstreamPort     uint32
	DownStreamAddrV4 uint32
	DownStreamAddrV6 [16]uint8
	DownStreamPort   uint32
	Fix              uint32
	ExeTime          uint64
}

type SocketDataEvent struct {
	Pid              uint32
	Comm             [128]byte
	SocketFd         uint32
	Buffer           [1024 * 3]byte
	BufferSize       uint32
	ProtocolType     uint32
	MessageType      uint32
	DataDirection    uint32
	ExeTime          uint64
	Rtt              uint32
	SocketFamily     uint32
	UpstreamAddrV4   uint32
	UpstreamAddrV6   [16]uint8
	UpstreamPort     uint32
	DownStreamAddrV4 uint32
	DownStreamAddrV6 [16]uint8
	DownStreamPort   uint32
}

type LinkFunc func(symbol string, prog *ebpf.Program) (link.Link, error)
type TreacepointFunc func(symbol string, prog *ebpf.Program) (link.Link, error)

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

func (m *MultipleLinker) AddTracepoint(sys, name string, p *ebpf.Program) {
	l, e := link.Tracepoint(sys, name, p)
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
	if err := loadBpfObjects(&objs, btf.GetEBPFCollectionOptionsIfNeed()); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// try to using the tracepoint
	linker := &MultipleLinker{}
	linker.AddLink("__sys_connect", link.Kprobe, objs.SysConnect)
	linker.AddLink("__sys_connect", link.Kretprobe, objs.SysConnectRet)
	linker.AddLink("sys_accept", link.Kprobe, objs.SysAccept)
	linker.AddLink("sys_accept", link.Kretprobe, objs.SysAcceptRet)
	linker.AddLink("__sys_accept4", link.Kprobe, objs.SysAccept)
	linker.AddLink("__sys_accept4", link.Kretprobe, objs.SysAcceptRet)
	linker.AddLink("sys_write", link.Kprobe, objs.SysWrite)
	linker.AddLink("sys_write", link.Kretprobe, objs.SysWriteRet)
	linker.AddLink("sys_writev", link.Kprobe, objs.SysWritev)
	linker.AddLink("sys_writev", link.Kretprobe, objs.SysWritevRet)
	linker.AddLink("sys_send", link.Kprobe, objs.SysSend)
	linker.AddLink("sys_send", link.Kretprobe, objs.SysSendRet)
	linker.AddLink("__sys_sendto", link.Kprobe, objs.SysSendto)
	linker.AddLink("__sys_sendto", link.Kretprobe, objs.SysSendtoRet)
	linker.AddLink("__sys_sendmsg", link.Kprobe, objs.SysSendmsg)
	linker.AddLink("__sys_sendmsg", link.Kretprobe, objs.SysSendmsgRet)
	linker.AddLink("__sys_sendmmsg", link.Kprobe, objs.SysSendmmsg)
	linker.AddLink("__sys_sendmmsg", link.Kretprobe, objs.SysSendmmsgRet)
	linker.AddLink("__sys_recvfrom", link.Kprobe, objs.SysRecvfrom)
	linker.AddLink("__sys_recvfrom", link.Kretprobe, objs.SysRecvfromRet)
	linker.AddLink("sys_read", link.Kprobe, objs.SysRead)
	linker.AddLink("sys_read", link.Kretprobe, objs.SysReadRet)

	// close_fd or __close_fd
	//linker.AddLink("__close_fd", link.Kprobe, objs.SysClose)
	//linker.AddLink("__close_fd", link.Kretprobe, objs.SysCloseRet)

	//linker.AddTracepoint("syscalls", "sys_exit_connect", objs.SysConnectRet)
	//linker.AddTracepoint("syscalls", "sys_enter_sendto", objs.SyscallProbeEntryWrite)
	linker.AddLink("sock_alloc", link.Kretprobe, objs.SockAllocRet)
	//linker.AddLink("__inet_stream_connect", link.Kprobe, objs.SockFromFileRet)
	linker.AddLink("tcp_connect", link.Kprobe, objs.TcpConnect)
	linker.AddLink("tcp_rcv_established", link.Kprobe, objs.TcpRcvEstablished)
	linker.AddLink("security_socket_sendmsg", link.Kprobe, objs.SecuritySocketSendmsg)
	linker.AddLink("security_socket_recvmsg", link.Kprobe, objs.SecuritySocketRecvmsg)

	////linker.AddTracepoint("syscalls", "sys_enter_writev", objs.SyscallProbeEntryWritev)
	defer linker.Close()
	err := linker.HasError()
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	log.Printf("start probes success...")

	sockOpsRd, err := perf.NewReader(objs.SocketOptsEventsQueue, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event sock ops reader: %s", err)
	}
	defer sockOpsRd.Close()
	sockDataRd, err := perf.NewReader(objs.SocketDataEventsQueue, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event sock data reader: %s", err)
	}
	defer sockDataRd.Close()

	go func() {
		var event SocketOptsEvent
		for {
			record, err := sockOpsRd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("opts perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			// Parse the perf event entry into an Event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			var downstreamAddr, upstreamAddr string
			if event.DownStreamAddrV4 != 0 {
				downstreamAddr = parseAddressV4(event.DownStreamAddrV4)
			} else {
				downstreamAddr = parseAddressV6(event.DownStreamAddrV6)
			}
			if event.UpstreamAddrV4 != 0 {
				upstreamAddr = parseAddressV4(event.UpstreamAddrV4)
			} else {
				upstreamAddr = parseAddressV6(event.UpstreamAddrV6)
			}
			var base string
			switch event.Type {
			case 1:
				base = fmt.Sprintf("CONNECT: %s:%d(in %d(%s)) -> %s:%d", upstreamAddr, parsePort(uint16(event.UpstreamPort)),
					event.Pid, event.Comm, downstreamAddr, parsePort(uint16(event.DownStreamPort)))
			case 2:
				base = fmt.Sprintf("ACCEPT: %s:%d -> %s:%d(in %d(%s))", downstreamAddr, event.DownStreamPort,
					upstreamAddr, parsePort(parsePort(uint16(event.UpstreamPort))), event.Pid, event.Comm)
			case 3:
				base = fmt.Sprintf("CLOSE: %d(%s)", event.Pid, event.Comm)
			}

			fmt.Printf("%s, execute time: %fms, socket fd: %d\n", base, float64(event.ExeTime)/1e6, event.SocketFd)
		}
	}()

	go func() {
		var event SocketDataEvent
		for {
			record, err := sockDataRd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("data perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			// Parse the perf event entry into an Event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}
			if strings.Contains(fmt.Sprintf("%s", event.Comm), "nginx") {
				//fmt.Printf("contians nginx: %v\n", event)
				fmt.Printf("nginx: ")

				request, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(event.Buffer[:])))
				if err == nil {
					fmt.Printf("request host: %s, url: %s\n", request.Host, request.URL)
				}

				response, err := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(event.Buffer[:])), nil)
				if err == nil {
					body, err := ioutil.ReadAll(response.Body)
					if err == nil {
						fmt.Printf("response data: %s\n", string(body))
					}
				}

				fmt.Printf("\n")
			}

			var direction string
			switch event.DataDirection {
			case 1:
				direction = "RECEIVE"
			case 2:
				direction = "WRITE"
			default:
				direction = "UNKNOWN"
			}

			var message string
			switch event.MessageType {
			case 1:
				message = "REQUEST"
			case 2:
				message = "RESPONSE"
			default:
				message = "UNKNOWN"
			}

			var protocol string
			switch event.ProtocolType {
			case 1:
				protocol = "HTTP"
			default:
				protocol = "UNKNOWN"
			}
			fmt.Printf("%s: %d(%s), protcol: %s, message: %s, socket fd: %d, size: %d, exe time: %fms, RTT: %d\n", direction, event.Pid, event.Comm, protocol, message, event.SocketFd, event.BufferSize, float64(event.ExeTime)/1e6, event.Rtt)
			if event.SocketFamily != 0 {
				var downstreamAddr, upstreamAddr string
				if event.SocketFamily == syscall.AF_INET {
					downstreamAddr = parseAddressV4(event.DownStreamAddrV4)
				} else {
					downstreamAddr = parseAddressV6(event.DownStreamAddrV6)
				}
				if event.SocketFamily == syscall.AF_INET {
					upstreamAddr = parseAddressV4(event.UpstreamAddrV4)
				} else {
					upstreamAddr = parseAddressV6(event.UpstreamAddrV6)
				}
				if event.DataDirection == 1 {
					fmt.Printf("%d, %s:%d -> %s:%d\n", event.SocketFamily, downstreamAddr, parsePort(uint16(event.DownStreamPort)), upstreamAddr, parsePort(parsePort(uint16(event.UpstreamPort))))
				} else {
					fmt.Printf("%d, %s:%d -> %s:%d\n", event.SocketFamily, upstreamAddr, parsePort(parsePort(uint16(event.UpstreamPort))), downstreamAddr, parsePort(uint16(event.DownStreamPort)))
				}
			}
			if event.MessageType == 1 {
				request, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(event.Buffer[:])))
				if err != nil {
					fmt.Errorf("read request error: %v\n", err)
					continue
				}
				fmt.Printf("request host: %s, url: %s\n", request.Host, request.URL)
			} else if event.MessageType == 2 {
				response, err := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(event.Buffer[:])), nil)
				if err != nil {
					fmt.Errorf("read response error: %v\n", err)
					continue
				}
				body, err := ioutil.ReadAll(response.Body)
				if err != nil {
					fmt.Errorf("read response body error: %v\n", err)
					continue
				}
				fmt.Printf("response data: %s\n", string(body))
			}
		}
	}()

	<-stopper
	log.Println("Received signal, exiting program..")
}
