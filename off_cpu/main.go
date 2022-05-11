//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
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
	"strconv"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf perf.c -- -I../headers

type Event struct {
	Pid           uint32
	UserStackId   uint32
	KernelStackId uint32
	Time          uint32
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

	//processStat, err := tools.ExecutableFileProfilingStat(fmt.Sprintf("/proc/%d/exe", pid))
	//if err != nil {
	//	log.Fatalf("read symbols error in file: %s: %v", fmt.Sprintf("/proc/%d/exe", pid), err)
	//	return
	//}
	//
	// load bpf
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading objects: %s", err)
		return
	}
	funcName := "do_stack_switch"
	for i, ins := range spec.Programs[funcName].Instructions {
		if ins.Reference == "MY_CONST" {
			spec.Programs[funcName].Instructions[i].Constant = int64(pid)
			spec.Programs[funcName].Instructions[i].Offset = 0
			fmt.Printf("found the my_const and replaced, index: %d, opCode: %d\n", i, ins.OpCode)
		}
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}

	kprobe, err := link.Kprobe("finish_task_switch", objs.DoStackSwitch)
	if err != nil {
		log.Fatalf("link to finish task swtich failure: %v", err)
	}
	defer kprobe.Close()

	// listen the event
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

		fmt.Printf("tid: %d, userStackId: %d, kernelStackId: %s, time: %d\n", event.Pid, event.UserStackId, event.KernelStackId, event.Time)
	}
}
