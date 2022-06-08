//go:build linux
// +build linux

package main

import (
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
	"os"
	"os/signal"
	"regexp"
	"strconv"
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

func getAllContainedProcessIdList() ([]int, error) {
	dir, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	res := make([]int, 0)
	for _, f := range dir {
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		file, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(file), "/kubepods/burstable/") {
			res = append(res, pid)
		}
	}
	return res, nil
}

func getAddr(addr syscall.Sockaddr) (ip string, port int) {
	switch addr.(type) {
	case *syscall.SockaddrInet4:
		inet4 := addr.(*syscall.SockaddrInet4)
		ipv4Addr := inet4.Addr
		ip = fmt.Sprintf("%d.%d.%d.%d", ipv4Addr[0], ipv4Addr[1], ipv4Addr[2], ipv4Addr[3])
		port = inet4.Port
	case *syscall.SockaddrInet6:
		ip = "v6"
	case *syscall.SockaddrUnix:
		ip = "unix"
	case *syscall.SockaddrLinklayer:
		ip = "link layer"
	case *syscall.SockaddrNetlink:
		ip = "netlink"
	}
	if addr == nil {
		ip = "addr is null"
	}
	return ip, port
}

func main() {
	pidList, err := getAllContainedProcessIdList()
	if err != nil {
		log.Fatalf("read container process error: %v", err)
		return
	}
	fmt.Printf("total found %d container process\n", len(pidList))
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
	linker.AddTracepoint("syscalls", "sys_enter_write", objs.SysWrite)
	linker.AddTracepoint("syscalls", "sys_exit_write", objs.SysWriteRet)
	//linker.AddLink("sys_writev", link.Kprobe, objs.SysWritev)
	//linker.AddLink("sys_writev", link.Kretprobe, objs.SysWritevRet)
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

	linker.AddTracepoint("syscalls", "sys_enter_writev", objs.TracepointSysEnterWritev)
	linker.AddTracepoint("syscalls", "sys_exit_writev", objs.TracepointSysExitWritev)
	linker.AddLink("sock_alloc", link.Kretprobe, objs.SockAllocRet)
	//linker.AddLink("__inet_stream_connect", link.Kprobe, objs.SockFromFileRet)
	linker.AddLink("tcp_connect", link.Kprobe, objs.TcpConnect)
	linker.AddLink("tcp_rcv_established", link.Kprobe, objs.TcpRcvEstablished)
	linker.AddLink("security_socket_sendmsg", link.Kprobe, objs.SecuritySocketSendmsg)
	linker.AddLink("security_socket_recvmsg", link.Kprobe, objs.SecuritySocketRecvmsg)

	////linker.AddTracepoint("syscalls", "sys_enter_writev", objs.SyscallProbeEntryWritev)
	defer linker.Close()
	err = linker.HasError()
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
	testRd, err := perf.NewReader(objs.TestQueue, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event sock ops reader: %s", err)
	}
	defer testRd.Close()

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
		var event SocketOptsEvent
		for {
			record, err := testRd.Read()
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
			fmt.Printf("test queu data %s\n", event.Comm)
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

			found := false
			for _, pid := range pidList {
				if pid == int(event.Pid) {
					found = true
					break
				}
			}
			if !found {
				continue
			}

			// for gcloud terminal, remove output
			comm := fmt.Sprintf("%s", event.Comm)
			if strings.Contains(comm, "sshd") || strings.Contains(comm, "kubelet") || strings.Contains(comm, "containerd") {
				continue
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

			//var message string
			//switch event.MessageType {
			//case 1:
			//	message = "REQUEST"
			//case 2:
			//	message = "RESPONSE"
			//default:
			//	message = "UNKNOWN"
			//}
			//
			//var protocol string
			//switch event.ProtocolType {
			//case 1:
			//	protocol = "HTTP"
			//default:
			//	protocol = "UNKNOWN"
			//}
			//fmt.Printf("%s: %d(%s), protcol: %s, message: %s, socket fd: %d, size: %d, exe time: %fms, RTT: %d\n", direction, event.Pid, event.Comm, protocol, message, event.SocketFd, event.BufferSize, float64(event.ExeTime)/1e6, event.Rtt)
			fmt.Printf("%s: %d(%s), socket fd: %d, size: %d, exe time: %fms, RTT: %d\n", direction, event.Pid, event.Comm, event.SocketFd, event.BufferSize, float64(event.ExeTime)/1e6, event.Rtt)
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
					fmt.Printf("%d, %s:%d -> %s:%d\n", event.SocketFamily, downstreamAddr, parsePort(parsePort(uint16(event.DownStreamPort))), upstreamAddr, parsePort(parsePort(uint16(event.UpstreamPort))))
				} else {
					fmt.Printf("%d, %s:%d -> %s:%d\n", event.SocketFamily, upstreamAddr, parsePort(parsePort(uint16(event.UpstreamPort))), downstreamAddr, parsePort(uint16(event.DownStreamPort)))
				}
			} else {
				connections := Tcp(int(event.Pid))
				link := fmt.Sprintf("/proc/%d/fd/%d", event.Pid, event.SocketFd)
				dest, err := os.Readlink(link)
				if err != nil {
					log.Printf("---read sockfile path error: %s, %v", link, err)
					continue
				}
				if !strings.HasPrefix(dest, "socket:[") {
					log.Printf("---current socketfd:%d is not socket: %s", event.SocketFd, dest)
					continue
				}

				inode := strings.TrimSuffix(strings.TrimPrefix(dest, "socket:["), "]")
				found := false
				exinodes := make([]string, 0)
				for _, c := range connections {
					exinodes = append(exinodes, c.Inode)
					if c.Inode == inode {
						if event.DataDirection == 1 {
							fmt.Printf("---load from linux fs, %s\n", c.Addr)
						} else {
							fmt.Printf("---load from linux fs, %s\n", c.ReverseAddr)
						}
						found = true
					}
				}

				if !found {
					fmt.Printf("---could not found the socket fd, current inode: %s, exists inode: %v", inode, exinodes)
				}

			}
			//if event.MessageType == 1 {
			//	request, err := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(event.Buffer[:])))
			//	if err != nil {
			//		fmt.Errorf("read request error: %v\n", err)
			//		continue
			//	}
			//	fmt.Printf("request host: %s, url: %s\n", request.Host, request.URL)
			//} else if event.MessageType == 2 {
			//	response, err := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(event.Buffer[:])), nil)
			//	if err != nil {
			//		fmt.Errorf("read response error: %v\n", err)
			//		continue
			//	}
			//	body, err := ioutil.ReadAll(response.Body)
			//	if err != nil {
			//		fmt.Errorf("read response body error: %v\n", err)
			//		continue
			//	}
			//	fmt.Printf("response data: %s\n", string(body))
			//}
		}
	}()

	<-stopper
	log.Println("Received signal, exiting program..")
}

type ConnectionItem struct {
	Addr        string `json:"addr" valid:"-"`
	ReverseAddr string `json:"reverse_addr" valid:"-"`
	SrcIP       string `json:"ip"`
	SrcPort     string `json:"port"`
	DestIP      string `json:"foreignip"`
	DestPort    string `json:"foreignport"`
	Inode       string
}

func parseNetworkLines(pid int) ([]string, error) {
	pf := fmt.Sprintf("/proc/%d/net/tcp", pid)

	data, err := ioutil.ReadFile(pf)
	if err != nil {
		fmt.Printf("read error: %v", err)
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	return lines[1 : len(lines)-1], nil
}

func hex2dec(hexstr string) string {
	i, _ := strconv.ParseInt(hexstr, 16, 0)
	return strconv.FormatInt(i, 10)
}

func hex2ip(hexstr string) (string, string) {
	var ip string
	if len(hexstr) != 8 {
		err := "parse error"
		return ip, err
	}

	i1, _ := strconv.ParseInt(hexstr[6:8], 16, 0)
	i2, _ := strconv.ParseInt(hexstr[4:6], 16, 0)
	i3, _ := strconv.ParseInt(hexstr[2:4], 16, 0)
	i4, _ := strconv.ParseInt(hexstr[0:2], 16, 0)
	ip = fmt.Sprintf("%d.%d.%d.%d", i1, i2, i3, i4)

	return ip, ""
}

func parseAddr(str string) (string, string) {
	l := strings.Split(str, ":")
	if len(l) != 2 {
		return str, ""
	}

	ip, err := hex2ip(l[0])
	if err != "" {
		return str, ""
	}

	return ip, hex2dec(l[1])
}

// convert hexadecimal to decimal.
func hexToDec(h string) int64 {
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return d
}

// remove empty data from line
func removeEmpty(array []string) []string {
	var columns []string
	for _, i := range array {
		if i == "" {
			continue
		}
		columns = append(columns, i)
	}
	return columns
}

func netstat(pid int) ([]*ConnectionItem, error) {
	var (
		conns []*ConnectionItem
	)

	data, err := parseNetworkLines(pid)
	if err != nil {
		return nil, err
	}

	for _, line := range data {
		pp := getConnectionItem(line)
		if pp == nil {
			continue
		}

		conns = append(conns, pp)
	}

	return conns, nil
}

func getConnectionItem(line string) *ConnectionItem {
	// local ip and port
	r := regexp.MustCompile("\\s+")
	source := r.Split(strings.TrimSpace(line), -1)

	// ignore local listenning records
	destIP, destPort := parseAddr(source[2])
	//if destIP == "0.0.0.0" {
	//	return nil
	//}

	// source ip and port
	ip, port := parseAddr(source[1])

	// tcp 4 fileds
	addr := ip + ":" + port + "->" + destIP + ":" + destPort
	raddr := destIP + ":" + destPort + "->" + ip + ":" + port

	inode := source[9]

	cc := &ConnectionItem{
		Addr:        addr,
		ReverseAddr: raddr,
		SrcIP:       ip,
		SrcPort:     port,
		DestIP:      destIP,
		Inode:       inode,
		DestPort:    destPort,
	}
	return cc
}

// Tcp func Get a slice of Process type with TCP data
func Tcp(pid int) []*ConnectionItem {
	data, _ := netstat(pid)
	return data
}
