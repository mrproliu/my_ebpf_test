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
	"syscall"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf kprobe.c -- -I../headers

type Event struct {
	Pid    uint32
	Random uint32
	Name   [128]byte
}

func main() {
	// Name of the kernel function to trace.
	fn := "sys_execve"

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

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		rd.Close()
	}()

	log.Printf("starting listen events...")
	timer := time.NewTicker(5 * time.Second)
	for true {
		select {
		case <-timer.C:
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

				fmt.Printf("pid: %d, random: %d, name: %s\n", event.Pid, event.Random, event.Name)
			}
		}
	}
}