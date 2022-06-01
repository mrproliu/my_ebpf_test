//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"ebpf_test/tools"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf perf.c -- -I$HOME/headers/noinclude/ -D__TARGET_ARCH_x86

type Event struct {
	Pid           uint32
	UserStackId   uint32
	KernelStackId uint32
}

type EventValue struct {
	Counts uint64
	Deltas uint64
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

	btf, err := findKernelBTF()
	if err != nil {
		log.Fatalf("load btf file error: %v", err)
		return
	}

	kernelFileProfilingStat, err := tools.KernelFileProfilingStat()
	if err != nil {
		log.Fatalf("load kernel symbol error: %v", err)
	}

	exeProfilingStat, err := tools.ProcessProfilingStat(int32(pid), fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatalf("load exe symbol error: %v", err)
	}

	// load bpf
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading objects: %s", err)
		return
	}
	funcName := "do_finish_task_switch"
	for i, ins := range spec.Programs[funcName].Instructions {
		if ins.Reference == "MONITOR_PID" {
			spec.Programs[funcName].Instructions[i].Constant = int64(pid)
			spec.Programs[funcName].Instructions[i].Offset = 0
			fmt.Printf("found the monitor_pid and replaced, index: %d, opCode: %d\n", i, ins.OpCode)
		}
	}
	var option *ebpf.CollectionOptions
	if btf != nil {
		option = &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{TargetBTF: btf}}
	}
	if err := spec.LoadAndAssign(&objs, option); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kprobe, err := link.Kprobe("finish_task_switch", objs.DoFinishTaskSwitch)
	if err != nil {
		log.Fatalf("link to finish task swtich failure: %v", err)
	}

	timer := time.NewTicker(5 * time.Second)
	var event Event
	var val EventValue
	count := 0
	for {
		select {
		case <-timer.C:
			count++
			fmt.Printf("total off cpu for %d, cycle:%d\n", pid, count)
			fmt.Printf("-------------------------------------------\n")
			iterate := objs.Counts.Iterate()
			eachCount := 0
			var totalDuration int64 = 0
			for iterate.Next(&event, &val) {
				eachCount++
				totalDuration += int64(val.Deltas)
				exeTime := time.Duration(val.Deltas)
				fmt.Printf("found event, userStack: %d, kernelStack: %d, execute count: %d, total duration: %dms\n", event.UserStackId, event.KernelStackId, val.Counts, exeTime.Milliseconds())

				stackIdList := make([]uint64, 100)
				err = objs.Stacks.Lookup(event.UserStackId, &stackIdList)
				if err != nil {
					fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
					continue
				}
				symbols := exeProfilingStat.FindSymbols(stackIdList, "MISSING")
				fmt.Printf("user stack:\n")
				for _, s := range symbols {
					fmt.Printf("%s\n", s)
				}

				err = objs.Stacks.Lookup(event.KernelStackId, &stackIdList)
				if err != nil {
					fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
					continue
				}
				fmt.Printf("kernel stack:\n")
				symbols = kernelFileProfilingStat.FindSymbols(stackIdList, "MISSING")
				for _, s := range symbols {
					fmt.Printf("%s\n", s)
				}
			}
			fmt.Printf("-------------------------------------------\n")
			fmt.Printf("total each count: %d, cycle: %d\n", eachCount, count)
			fmt.Printf("total duration: %fs\n", time.Duration(totalDuration).Seconds())
			fmt.Printf("-------------------------------------------\n")
		case <-stopper:
			_ = kprobe.Close()
			log.Println("Received signal, exiting program..")

			kprobe.Close()
			return
		}
	}
	//// listen the event
	//var event Event
	//for {
	//	record, err := rd.Read()
	//	if err != nil {
	//		if errors.Is(err, perf.ErrClosed) {
	//			return
	//		}
	//		log.Printf("reading from perf event reader: %s", err)
	//		continue
	//	}
	//
	//	if record.LostSamples != 0 {
	//		log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
	//		continue
	//	}
	//
	//	// Parse the perf event entry into an Event structure.
	//	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
	//		log.Printf("parsing perf event: %s, original data: %v", err, record.RawSample)
	//		continue
	//	}
	//
	//	exeTime := time.Duration(event.Time)
	//	fmt.Printf("pid: %d, user stack: %d, kernel stack: %d, time: %d\n", event.Pid, event.UserStackId, event.KernelStackId, exeTime.Milliseconds())
	//
	//	//if int(event.Pid) == pid {
	//	stackIdList := make([]uint64, 100)
	//	err = objs.Stacks.Lookup(event.UserStackId, &stackIdList)
	//	if err != nil {
	//		fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
	//		continue
	//	}
	//	symbols := exeProfilingStat.FindSymbols(stackIdList, "MISSING")
	//	fmt.Printf("user stack:\n")
	//	for _, s := range symbols {
	//		fmt.Printf("%s\n", s)
	//	}
	//
	//	err = objs.Stacks.Lookup(event.KernelStackId, &stackIdList)
	//	if err != nil {
	//		fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
	//		continue
	//	}
	//	fmt.Printf("kernel stack:\n")
	//	symbols = kernelFileProfilingStat.FindSymbols(stackIdList, "MISSING")
	//	for _, s := range symbols {
	//		fmt.Printf("%s\n", s)
	//	}
	//	fmt.Printf("---------------\n")
	//}
}
