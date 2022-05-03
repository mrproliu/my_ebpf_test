//go:build linux
// +build linux

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf perf.c -- -I../headers

type Event struct {
	UserStackId uint32
}

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("please input the pid need to be monitor")
		return
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal("could not reconized the pid: %s", os.Args[1])
		return
	}
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

	perfEvents := make([]int, 0)
	for i := 0; i < runtime.NumCPU(); i++ {
		eventAttr := &unix.PerfEventAttr{
			Type:        unix.PERF_TYPE_SOFTWARE,
			Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
			Sample_type: unix.PERF_SAMPLE_RAW,
			Sample:      uint64(time.Second.Nanoseconds()),
			Wakeup:      1,
		}
		fd, err := unix.PerfEventOpen(eventAttr, pid, i, -1, 0)
		if err != nil {
			log.Fatal("open perf error", err)
		}
		perfEvents = append(perfEvents, fd)

		// attach ebpf to perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, objs.DoPerfEvent.FD()); err != nil {
			log.Fatal(err)
		}

		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			log.Fatal(err)
		}
	}

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	elfFile := readSymbols(pid, fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatalf("read symbols error: %v", err)
		return
	}

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		for _, fd := range perfEvents {
			if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
				log.Fatalf("closing perf event reader: %s", err)
			}
		}

		if err := rd.Close(); err != nil {
			log.Fatal("close reader error: %s", err)
		}
	}()

	log.Printf("Listening for events..")

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

		val := make([]uint64, 100)
		err = objs.Stacks.Lookup(event.UserStackId, &val)
		if err != nil {
			fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
			continue
		}
		for _, addr := range val {
			if addr == 0 {
				continue
			}
			funcName := elfFile.FindSymbolName(addr)
			if funcName != "" {
				fmt.Printf("%s\n", funcName)
				continue
			}
			fmt.Printf("not found stack symbol, addr: %d\n", addr)
		}
	}
}

func readSymbols(pid int, file string) *Elf {
	// TODO using maps file to read(/proc/{pid}/maps)
	//var addrStartInx int64 = 93966328557568
	//var offset int64 = 20608
	//var symbolOffset = needToFind - addrStartInx + offset
	//realPath, err := os.Readlink(file)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//mapFile, _ := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	//scanner := bufio.NewScanner(mapFile)
	//var addrStartInx uint64
	//var found = true
	//for scanner.Scan() {
	//	info := strings.Split(scanner.Text(), " ")
	//	if len(info) < 6 {
	//		continue
	//	}
	//	if info[5] != realPath && info[1][2] != 'x' {
	//		continue
	//	}
	//	addrInfo := strings.Split(info[0], "-")
	//	startAddr, err := strconv.ParseUint(addrInfo[0], 16, 64)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	addrStartInx = startAddr
	//	found = true
	//	fmt.Printf("found the execute file in map file start addr: %d, original: %s, map line: %s, realPath: %s\n", addrStartInx, addrInfo[0], info, realPath)
	//}
	//if !found {
	//	log.Fatal("could not found the execute file map start addr")
	//}
	// and name not start with
	//mapname[0] && !(
	//	STARTS_WITH(mapname, "//anon") ||
	//		STARTS_WITH(mapname, "/dev/zero") ||
	//		STARTS_WITH(mapname, "/anon_hugepage") ||
	//		STARTS_WITH(mapname, "[stack") ||
	//		STARTS_WITH(mapname, "/SYSV") ||
	//		STARTS_WITH(mapname, "[heap]") ||
	//		STARTS_WITH(mapname, "[vsyscall]"));

	elfFile, err := elf.Open(file)
	if err != nil {
		os.Exit(1)
	}
	defer elfFile.Close()

	// exist symbol data
	symbols, err := elfFile.Symbols()
	if err != nil {
		os.Exit(1)
	}

	d := make([]*Symbol, 0)
	for _, sym := range symbols {
		d = append(d, &Symbol{
			Name: sym.Name,
			Addr: sym.Value,
			Real: sym.Value,
		})
	}
	return &Elf{symbols: d}
}

type Elf struct {
	symbols []*Symbol
}
type Symbol struct {
	Name string
	Addr uint64
	Real uint64
}

// FindSymbolName by address
func (i *Elf) FindSymbolName(address uint64) string {
	symbols := i.symbols
	var addrStartInx int64 = 93966328557568
	var offset int64 = 20608
	fmt.Printf("need to found addr: %d\n", address)
	address = uint64(int64(address) - addrStartInx + offset)

	start := 0
	end := len(symbols) - 1
	for start < end {
		mid := start + (end-start)/2

		if address < symbols[mid].Addr {
			end = mid
		} else if address > symbols[mid].Addr {
			start = mid + 1
		} else {
			return symbols[mid].Name
		}
	}

	if start >= 1 && symbols[start-1].Addr < address && address < symbols[start].Addr {
		return symbols[start-1].Name
	}

	return ""
}
