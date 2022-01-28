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
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf perf-java.c -- -I../headers

type Event struct {
	Pid           uint32
	UserStackId   uint32
	KernelStackId uint32
	Name          [128]byte
}

func i32tob(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

func btoi32(val []byte) uint32 {
	r := uint32(0)
	for i := uint32(0); i < 4; i++ {
		r |= uint32(val[i]) << (8 * i)
	}
	return r
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
			Sample:      1000000 * 1000,
			Wakeup:      1,
		}
		fd, err := unix.PerfEventOpen(
			eventAttr,
			-1,
			i,
			-1,
			0,
		)
		if err != nil {
			log.Fatal("test1", err)
		}
		perfEvents = append(perfEvents, fd)

		// attach ebpf to perf event
		unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, objs.DoPerfEvent.FD())

		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			log.Fatalf("test2", err)
		}
	}

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	elfFile, symbols, err := readSymbols(fmt.Sprintf("/proc/%d/exe", pid))
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

		//if int(event.Pid) != pid {
		//	continue
		//}

		fmt.Printf("id: %d, name: %s, stack: %d:%d\n", event.Pid, event.Name, event.KernelStackId, event.UserStackId)

		fmt.Printf("stack id to bytes: %d:%v, %d:%v\n", event.KernelStackId, i32tob(event.KernelStackId), event.UserStackId, i32tob(event.UserStackId))
		val := make([]uint64, 100)
		err = objs.Stacks.Lookup(event.UserStackId, &val)
		if err != nil {
			fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
			continue
		} else {
			for _, addr := range val {
				if addr == 0 {
					continue
				}
				toFunc := symbols.PCToFunc(addr)
				if toFunc != nil {
					fmt.Printf("%s", toFunc.Name)
					fmt.Printf("(")
					for i, p := range toFunc.Params {
						if i > 0 {
							fmt.Printf(", ")
						}
						fmt.Printf("%s", p.Name)
					}
					fmt.Printf(")\n")
					continue
				}
				fmt.Printf("not found!!!")
			}
		}
	}
}

func readSymbols(file string) (*elf.File, *gosym.Table, error) {
	// Open self
	f, err := elf.Open(file)
	if err != nil {
		return nil, nil, err
	}
	table, err := parse(f)
	if err != nil {
		return nil, nil, err
	}
	return f, table, err
}

func parse(f *elf.File) (*gosym.Table, error) {
	s := f.Section(".gosymtab")
	if s == nil {
		return nil, fmt.Errorf("no symbles")
	}
	symdat, err := s.Data()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read symbols failure: %v", err)
	}
	pclndat, err := f.Section(".gopclntab").Data()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read gopclntab failure: %v", err)
	}

	pcln := gosym.NewLineTable(pclndat, f.Section(".text").Addr)
	tab, err := gosym.NewTable(symdat, pcln)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse gosymtab failure: %v", err)
	}

	return tab, nil
}
