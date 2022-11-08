//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/shirou/gopsutil/host"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf time.c -- -I../headers

var BootTime time.Time

func init() {
	boot, err := host.BootTime()
	if err != nil {
		panic(fmt.Errorf("init boot time error: %v", err))
	}
	BootTime = time.Unix(int64(boot), 0)
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

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objects := &bpfObjects{}
	if err := loadBpfObjects(objects, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objects.Close()

	executable, err := link.OpenExecutable(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatal(err)
	}

	uretprobe, err := executable.Uretprobe("time.Now", objects.DoPerfEvent, nil)

	rd, err := perf.NewReader(objects.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()
	defer uretprobe.Close()

	log.Printf("Listening for events..")

	go func() {
		var event uint64
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

			info := &syscall.Sysinfo_t{}
			err = syscall.Sysinfo(info)
			if err != nil {
				log.Fatal(err)
			}
			timeCopy := time.Unix(BootTime.Unix(), int64(BootTime.Nanosecond()))
			result := timeCopy.Add(time.Duration(event))
			fmt.Printf("current second: %d, nano: %d, uptime: %d\n", result.Unix(), result.Nanosecond(), info.Uptime)
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}
