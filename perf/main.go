//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
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

	eventAttr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1000000 * 1,
		Wakeup:      1,
	}
	fd, err := unix.PerfEventOpen(
		eventAttr,
		pid,
		0,
		-1,
		0,
	)
	if err != nil {
		log.Fatal("test1", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// attach ebpf to perf event
	unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, objs.DoPerfEvent.FD())

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		log.Fatalf("test2", err)
	}

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
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
		fmt.Printf("id: %d, name: %s, stack: %d:%d\n", event.Pid, event.Name, event.KernelStackId, event.UserStackId)

		fmt.Printf("stack id to bytes: %d:%v, %d:%v\n", event.KernelStackId, i32tob(event.KernelStackId), event.UserStackId, i32tob(event.UserStackId))
		val := make([]uint64, 100)
		err = objs.Stacks.Lookup(event.UserStackId, &val)
		if err != nil {
			fmt.Printf("err look up : %d, %v", event.UserStackId, err)
			continue
		} else {
			fmt.Printf("find user stack !!!: %v", val)
		}

		iterate := objs.Stacks.Iterate()
		key := make([]byte, 4)
		value := make([]byte, 800)
		for iterate.Next(&key, &value) {
			fmt.Printf("key: %d:%v, value: %v\n", btoi32(key), key, value)
			key = make([]byte, 4)
			value = make([]byte, 800)
		}

		//symbls := make([]uint64, 0)
		//err = objs.Stacks.Lookup(&event.UserStackId, &symbls)
		//if err != nil {
		//	log.Printf("err look up stackid: %d, %v", event.UserStackId, err)
		//	continue
		//}

		//fmt.Printf("found stacks: %d", len(symbls))
	}
}
