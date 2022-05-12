//go:build linux
// +build linux

package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/gosym"
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
	"sort"
	"strconv"
	"strings"
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

func findKernelSymbol(symbols []kernelSymbol, addr uint64) string {
	start := 0
	end := len(symbols)

	for start < end {
		mid := start + (end-start)/2
		result := int64(addr) - int64(symbols[mid].Addr)

		//c := int64(-symbols[mid].Addr)
		//d := uint64(c)
		//f := atomic.AddUint64(&copyAddr, d)
		//fmt.Printf("%d-%d=%d\n", addr, symbols[mid].Addr, f)
		//fmt.Printf("start: %d, end: %d, mid: %d, addr(%d)-symAddr(%d) = %d\n", start, end, mid, addr, symbols[mid].Addr, result)
		if result < 0 {
			end = mid
		} else if result > 0 {
			start = mid + 1
		} else {
			return symbols[mid].Symbol
		}
	}

	if start >= 1 && symbols[start-1].Addr < addr && addr < symbols[start].Addr {
		return symbols[start-1].Symbol
	}

	return "NOT FOUND!!!!"
}

type kernelSymbol struct {
	Addr   uint64
	Symbol string
}

func testSysSymbol() ([]kernelSymbol, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// read the file line by line using scanner
	scanner := bufio.NewScanner(file)

	symbols := make([]kernelSymbol, 0)
	count := 0
	for scanner.Scan() {
		count++
		info := strings.Split(scanner.Text(), " ")
		//stype := info[1]
		//if stype == "T" || stype == "t" || stype == "W" || stype == "w" {
		atoi, err := strconv.ParseUint(info[0], 16, 64)

		if strings.HasPrefix(info[0], "ffffffff9435d7d0") {
			fmt.Printf("Addr: %s, \t, type: %s, symbol: %s, toint: %d\n", info[0], info[1], info[2], uint64(atoi))
		}
		//fmt.Printf("index: %d: %d -> %s\n", count, atoi, info[2])
		if err != nil {
			return nil, fmt.Errorf("error read addr: %s, %v", info[0], err)
		}
		symbols = append(symbols, kernelSymbol{
			Addr:   atoi,
			Symbol: info[2],
		})
		//}
	}

	sort.SliceStable(symbols, func(i, j int) bool {
		return symbols[i].Addr < symbols[j].Addr
	})
	fmt.Printf("total count: %d\n", count)
	last := len(symbols) - 1
	fmt.Printf("last symbole: %d: addr: %d, name: %d", last, symbols[last].Addr, symbols[last].Symbol)
	return symbols, nil
}

type symbolInter struct {
	symbols []kernelSymbol
}

func (s *symbolInter) Len() int {
	return len(s.symbols)
}

func (s *symbolInter) Less(i, j int) bool {
	return s.symbols[i].Addr < s.symbols[j].Addr
}

func (s *symbolInter) Swap(i, j int) {
	tmp := s.symbols[i]
	s.symbols[j] = s.symbols[i]
	s.symbols[i] = tmp
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
