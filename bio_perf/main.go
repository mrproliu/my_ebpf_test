//go:build linux
// +build linux

package main

import (
	"bytes"
	"ebpf_test/tools"
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
	TaskId        uint32
	UserStackId   int32
	KernelStackId int32
	Name          [128]byte
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
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kprobe, err := link.Kprobe("blk_account_io_start", objs.BpfSockSendmsg)

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	kernelFile, err := tools.KernelFileProfilingStat()
	if err != nil {
		log.Fatalf("read symbols error: %v", err)
		return
	}
	processFile, err := tools.ExecutableFileProfilingStat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatalf("read symbols error: %v", err)
		return
	}

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		kprobe.Close()
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
		fmt.Printf("pid: %d, taskid: %d, name: %s, stack: %d:%d\n", event.Pid, event.TaskId, event.Name, event.UserStackId, event.KernelStackId)

		//if int(event.Pid) == pid {
		stackIdList := make([]uint64, 100)
		err = objs.Stacks.Lookup(event.UserStackId, &stackIdList)
		if err != nil {
			fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
			continue
		}
		symbols := processFile.FindSymbols(stackIdList, "MISSING")
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
		symbols = kernelFile.FindSymbols(stackIdList, "MISSING")
		for _, s := range symbols {
			fmt.Printf("%s\n", s)
		}
		fmt.Printf("---------------\n")
	}
}
