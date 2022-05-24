//go:build linux
// +build linux

package main

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"ebpf_test/tools"
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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf perf-java.c -- -I../headers

type Event struct {
	Pid           uint32
	TaskId        uint32
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
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading objects: %s", err)
		return
	}
	// adjust the pid
	funcName := "do_perf_event"
	for _, ins := range spec.Programs[funcName].Instructions {
		if ins.Constant == int64(999) {
			ins.Constant = int64(pid)
			fmt.Printf("found the pid and replaced\n")
			break
		}
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	perfEvents := make([]int, 0)
	//duration, _ := time.ParseDuration("9ms")
	//t := duration
	for i := 0; i < runtime.NumCPU(); i++ {
		eventAttr := &unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Sample: 49,
			Wakeup: 1,
		}
		fd, err := unix.PerfEventOpen(
			eventAttr,
			pid,
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

	_, err = tools.ProcessProfilingStat(int32(pid), fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatalf("read symbol error: %v", err)
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

		//if int(event.Pid) != pid {
		//	continue
		//}
		ti := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("%s: pid: %d, taskid: %d, name: %s, stack: %d:%d\n", ti, event.Pid, event.TaskId, event.Name, event.KernelStackId, event.UserStackId)

		fmt.Printf("stack id to bytes: %d %d\n", event.KernelStackId, event.UserStackId)

		//if int(event.Pid) == pid {
		//	val := make([]uint64, 100)
		//	err = objs.Stacks.Lookup(event.UserStackId, &val)
		//	if err != nil {
		//		fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
		//		continue
		//	}
		//	for _, addr := range val {
		//		if addr == 0 {
		//			continue
		//		}
		//		toFunc := symbols.PCToFunc(addr)
		//		if toFunc != nil {
		//			fmt.Printf("%s", toFunc.Name)
		//			fmt.Printf("(")
		//			for i, p := range toFunc.Params {
		//				if i > 0 {
		//					fmt.Printf(", ")
		//				}
		//				fmt.Printf("%s", p.Name)
		//			}
		//			fmt.Printf(")\n")
		//			continue
		//		}
		//		fmt.Printf("not found!!!")
		//	}
		//} else if int(event.Pid) == 0 {
		//	val := make([]uint64, 100)
		//	err = objs.Stacks.Lookup(event.KernelStackId, &val)
		//	if err != nil {
		//		fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
		//		continue
		//	}
		//
		//	fmt.Printf("find kernel stack: %v\n", val)
		//}

		fmt.Printf("---------------\n")
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
