//go:build linux
// +build linux

package main

import (
	"bytes"
	"ebpf_test/tools"
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
	"time"
	"unsafe"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcptrace.c -- -I$HOME/headers/ -D__TARGET_ARCH_x86

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

type Event struct {
	Pid           uint32
	TaskId        uint32
	UserStackId   uint32
	KernelStackId uint32
	Name          [128]byte
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
	linker.AddLink("security_socket_sendmsg", link.Kprobe, objs.SecuritySocketSendmsg)
	linker.AddLink("security_socket_recvmsg", link.Kprobe, objs.SecuritySocketRecvmsg)

	////linker.AddTracepoint("syscalls", "sys_enter_writev", objs.SyscallProbeEntryWritev)
	defer linker.Close()
	err = linker.HasError()
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	log.Printf("start probes success...")

	kernelFileProfilingStat, err := tools.KernelFileProfilingStat()
	if err != nil {
		log.Fatalf("read symbol error: %v", err)
	}

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

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

		//if int(event.Pid) != pid {
		//	continue
		//}
		ti := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("%s: pid: %d, taskid: %d, name: %s, stack: %d:%d\n", ti, event.Pid, event.TaskId, event.Name, event.KernelStackId, event.UserStackId)

		fmt.Printf("stack id to bytes: %d %d\n", event.KernelStackId, event.UserStackId)

		val := make([]uint64, 100)
		fmt.Printf("kernel:\n")
		err = objs.Stacks.Lookup(event.KernelStackId, &val)
		if err != nil {
			fmt.Printf("err look up : %d, %v\n", event.KernelStackId, err)
			continue
		}
		symbols := kernelFileProfilingStat.FindSymbols(val, "[MISSING]")
		for _, s := range symbols {
			fmt.Printf("%s\n", s)
		}

		fmt.Printf("---------------\n")
	}

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
