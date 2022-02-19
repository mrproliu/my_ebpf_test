//go:build linux
// +build linux

package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/gosym"
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
	"strings"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf perf.c -- -I../headers

type Event struct {
	Pid           uint32
	TaskId        uint32
	UserStackId   uint32
	KernelStackId uint32
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

	kprobe, err := link.Kprobe("blk_account_io_start", objs.BpfBlkAccountIoStart)

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

	kernelSymbols, err := testSysSymbol()
	if err != nil {
		log.Fatalf("read kernel symbol error: %v", err)
		return
	}

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		_ = elfFile.Close()

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

		if int(event.Pid) == pid {
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

			err = objs.Stacks.Lookup(event.KernelStackId, &val)
			if err != nil {
				fmt.Printf("err look up : %d, %v\n", event.UserStackId, err)
				continue
			}
			for _, addr := range val {
				if addr == 0 {
					continue
				}
				for _, sym := range kernelSymbols {
					if sym.Addr == addr {
						fmt.Printf("%s\n", sym.Symbol)
						break
					}
				}
				fmt.Printf("Not Found!!!id: %v\n", addr)
			}
		}

		fmt.Printf("---------------\n")
	}
}

type kernelSymbol struct {
	Addr   uint64
	Symbol string
}

func testSysSymbol() ([]*kernelSymbol, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// read the file line by line using scanner
	scanner := bufio.NewScanner(file)

	symbols := make([]*kernelSymbol, 0)
	count := 0
	for scanner.Scan() {
		info := strings.Split(scanner.Text(), " ")
		atoi, err := strconv.ParseUint(info[0], 16, 64)
		if strings.HasPrefix(info[0], "ffffffff") {
			count++
		}
		if err != nil {
			return nil, fmt.Errorf("error read addr: %s, %v", info[0], err)
		}
		symbols = append(symbols, &kernelSymbol{
			Addr:   atoi,
			Symbol: info[2],
		})
	}
	fmt.Printf("total count: %d\n", count)
	return symbols, nil
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
