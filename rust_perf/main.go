//go:build linux
// +build linux

package main

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
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
	"strings"
	"syscall"
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
			Sample:      1000000 * 10,
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

	elfFile := readSymbols(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatalf("read symbols error: %v", err)
		return
	}

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		_ = elfFile.Close()

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
			fmt.Printf("not found stack symbol, addr: %d", addr)
		}
	}
}

func readSymbols(file string) *Elf {
	file, err := elf.Open("/Users/hanliu/Documents/go_workspace/github/tetrate/tctl/build/bin/linux/amd64/tctl")
	if err != nil {
		os.Exit(1)
	}
	defer file.Close()

	symbols, err := file.Symbols()
	if err != nil {
		os.Exit(1)
	}

	symbols = make([]*Symbol, 0)
	for _, sym := range symbols {
		symbols = append(symbols, &Symbol{
			Name: sym.Name,
			Addr: sym.Value,
		})
	}
	return &Elf{symbols: symbols}
}

type Elf struct {
	symbols []*Symbol
}
type Symbol struct {
	Name string
	Addr uint64
}

// FindSymbolName by address
func (i *Elf) FindSymbolName(address uint64) string {
	symbols := i.symbols

	start := 0
	end := len(symbols) - 1
	for start < end {
		mid := start + (end-start)/2
		result := int64(address) - int64(symbols[mid].Addr)

		if result < 0 {
			end = mid
		} else if result > 0 {
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
