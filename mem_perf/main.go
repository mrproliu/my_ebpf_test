package main

import (
	"bytes"
	"debug/elf"
	"ebpf_test/tools"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf perf.c -- -I../headers

var allocFuncs = []string{
	"runtime.mallocgc",
	"runtime.newobject",
	"runtime.newarray",
}

type Event struct {
	UserStackId   uint32
	KernelStackId uint32
	Size          uint64
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
	fmt.Printf("read get link for pid: %d\n", pid)

	executeFile := fmt.Sprintf("/proc/%d/exe", pid)
	links, err := readLinks(executeFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("execute file total links:\n")
	for _, va := range links {
		fmt.Printf("%s\n", va)
	}

	links = append(links, executeFile)

	allocers, err := allMemoryAlloc(links)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("find all allocator: %v\n", allocers)
	if len(allocers) == 0 {
		log.Fatal("could not found any allocator symbol, shutdown")
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// load bpf
	objs := bpfObjects{}
	err = loadBpfObjects(&objs, nil)
	if err != nil {
		log.Fatalf("load bpf object failure: %v", err)
	}

	// open all uprobes
	uprobes := make([]link.Link, 0)
	defer closeAllUprobes(uprobes)
	for file, symbols := range allocers {
		executableFile, err := link.OpenExecutable(file)
		if err != nil {
			log.Fatalf("read execute file failure, file path: %s, %v", file, err)
		}
		for _, symbol := range symbols {
			uprobe, err := executableFile.Uprobe(symbol, objs.MallocEnter, &link.UprobeOptions{
				PID: pid,
			})
			if err != nil {
				log.Fatalf("could not open uprobe: %v", err)
			}
			log.Printf("start uprobe with file: %s, symbol: %s", file, symbol)
			uprobes = append(uprobes, uprobe)
		}
	}

	// listen the event
	rd, err := perf.NewReader(objs.Counts, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	kernelStat, err := tools.KernelFileProfilingStat()
	if err != nil {
		log.Printf("could not read the kernel symbols: %v, so ignored.", err)
	}
	processStat, err := tools.ExecutableFileProfilingStat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatalf("read symbols error in file: %s: %v", fmt.Sprintf("/proc/%d/exe", pid), err)
		return
	}

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		rd.Close()
	}()

	log.Printf("Listening for events..")

	var event Event
	stacks := make([]uint64, 100)
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			return
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		fmt.Printf("stack: %d:%d, size: %d\n", event.KernelStackId, event.UserStackId, event.Size)

		if err = objs.Stacks.Lookup(event.UserStackId, stacks); err == nil && processStat != nil {
			symbols := processStat.FindSymbols(stacks, "MISSING")
			fmt.Printf("user statck: \n")
			for _, s := range symbols {
				fmt.Printf("%s\n", s)
			}
			fmt.Printf("---------------\n")
		}
		if err = objs.Stacks.Lookup(event.KernelStackId, stacks); err == nil && kernelStat != nil {
			symbols := kernelStat.FindSymbols(stacks, "MISSING")
			fmt.Printf("kernel statck: \n")
			for _, s := range symbols {
				fmt.Printf("%s\n", s)
			}
			fmt.Printf("---------------\n")
		}
	}
}

func closeAllUprobes(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}

func allMemoryAlloc(files []string) (map[string][]string, error) {
	result := make(map[string][]string)
	for _, file := range files {
		alloc, err := findoutAlloc(file)
		if err != nil {
			return nil, fmt.Errorf("find the alloc symbol error: %v", err)
		}
		if len(alloc) > 0 {
			result[file] = alloc
		}
	}

	return result, nil
}

func findoutAlloc(file string) ([]string, error) {
	elfFile, err := elf.Open(file)
	if err != nil {
		os.Exit(1)
	}
	defer elfFile.Close()

	symbols, err := elfFile.Symbols()
	if err != nil {
		if err == elf.ErrNoSymbols {
			return nil, nil
		}
		return nil, err
	}

	result := make([]string, 0)
	for _, sym := range symbols {
		for _, ac := range allocFuncs {
			if sym.Name == ac {
				result = append(result, sym.Name)
			}
		}
	}
	return result, nil
}

func readLinks(path string) ([]string, error) {
	f := make([]string, 0)
	f = append(f, path)
	return List(f)
}

// Follow starts at a pathname and adds it
// to a map if it is not there.
// If the pathname is a symlink, indicated by the Readlink
// succeeding, links repeats and continues
// for as long as the name is not found in the map.
func follow(l string, names map[string]*FileInfo) error {
	if names[l] != nil {
		return nil
	}

	stat, err := os.Lstat(l)
	if err != nil {
		return err
	}

	if stat.Mode().IsRegular() {
		names[l] = &FileInfo{FullName: l, FileInfo: stat}
		return nil
	}

	next, err := os.Readlink(l)
	if err != nil {
		return err
	}
	// It may be a relative link, so we need to
	// make it abs.
	if filepath.IsAbs(next) {
		names[l] = &FileInfo{FullName: l, FileInfo: stat}
		return nil
	}

	return follow(filepath.Join(filepath.Dir(l), next), names)
}

// runinterp runs the interpreter with the --list switch
// and the file as an argument. For each returned line
// it looks for => as the second field, indicating a
// real .so (as opposed to the .vdso or a string like
// 'not a dynamic executable'.
func runinterp(interp, file string) ([]string, error) {
	var names []string
	o, err := exec.Command(interp, "--list", file).Output()
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Split(string(o), "\n") {
		f := strings.Split(p, " ")
		if len(f) < 3 {
			continue
		}
		if f[1] != "=>" || len(f[2]) == 0 {
			continue
		}
		names = append(names, f[2])
	}
	return names, nil
}

type FileInfo struct {
	FullName string
	os.FileInfo
}

func GetInterp(file string) (string, error) {
	r, err := os.Open(file)
	if err != nil {
		return "fail", err
	}
	defer r.Close()
	f, err := elf.NewFile(r)
	if err != nil {
		return "", nil
	}
	s := f.Section(".interp")
	var interp string
	if s != nil {
		// If there is an interpreter section, it should be
		// an error if we can't read it.
		i, err := s.Data()
		if err != nil {
			return "fail", err
		}
		// Ignore #! interpreters
		if len(i) > 1 && i[0] == '#' && i[1] == '!' {
			return "", nil
		}
		// annoyingly, s.Data() seems to return the null at the end and,
		// weirdly, that seems to confuse the kernel. Truncate it.
		interp = string(i[:len(i)-1])
	}
	if interp == "" {
		if f.Type != elf.ET_DYN || f.Class == elf.ELFCLASSNONE {
			return "", nil
		}
		bit64 := true
		if f.Class != elf.ELFCLASS64 {
			bit64 = false
		}

		// This is a shared library. Turns out you can run an
		// interpreter with --list and this shared library as an
		// argument. What interpreter do we use? Well, there's no way to
		// know. You have to guess.  I'm not sure why they could not
		// just put an interp section in .so's but maybe that would
		// cause trouble somewhere else.
		interp, err = LdSo(bit64)
		if err != nil {
			return "fail", err
		}
	}
	return interp, nil
}

// Ldd returns a list of all library dependencies for a set of files.
//
// If a file has no dependencies, that is not an error. The only possible error
// is if a file does not exist, or it says it has an interpreter but we can't
// read it, or we are not able to run its interpreter.
//
// It's not an error for a file to not be an ELF.
func Ldd(names []string) ([]*FileInfo, error) {
	var (
		list    = make(map[string]*FileInfo)
		interps = make(map[string]*FileInfo)
		libs    []*FileInfo
	)
	for _, n := range names {
		if err := follow(n, list); err != nil {
			return nil, err
		}
	}
	for _, n := range names {
		interp, err := GetInterp(n)
		if err != nil {
			return nil, err
		}
		if interp == "" {
			continue
		}
		loopFind(interp, n, interps, list)
		//// We could just append the interp but people
		//// expect to see that first.
		//if interps[interp] == nil {
		//	err := follow(interp, interps)
		//	if err != nil {
		//		return nil, err
		//	}
		//}
		//// oh boy. Now to run the interp and get more names.
		//n, err := runinterp(interp, n)
		//if err != nil {
		//	return nil, err
		//}
		//for i := range n {
		//	if err := follow(n[i], list); err != nil {
		//		log.Fatalf("ldd: %v", err)
		//	}
		//}
	}

	for i := range interps {
		libs = append(libs, interps[i])
	}

	return libs, nil
}

func loopFind(interp string, from string, interps map[string]*FileInfo, list map[string]*FileInfo) error {
	// We could just append the interp but people
	// expect to see that first.
	if interps[interp] == nil {
		err := follow(interp, interps)
		if err != nil {
			return err
		}
	}
	// oh boy. Now to run the interp and get more names.
	n, err := runinterp(interp, from)
	if err != nil {
		return err
	}
	for i := range n {
		if err := follow(n[i], list); err != nil {
			log.Fatalf("ldd: %v", err)
		}

		if err = loopFind(n[i], interp, interps, list); err != nil {
			return err
		}
	}
	return nil
}

// List returns the dependency file paths of files in names.
func List(names []string) ([]string, error) {
	var list []string
	l, err := Ldd(names)
	if err != nil {
		return nil, err
	}
	for i := range l {
		list = append(list, l[i].FullName)
	}
	return list, nil
}

// LdSo finds the loader binary.
func LdSo(bit64 bool) (string, error) {
	bits := 32
	if bit64 {
		bits = 64
	}
	choices := []string{fmt.Sprintf("/lib%d/ld-*.so.*", bits), "/lib/ld-*.so.*"}
	for _, d := range choices {
		n, err := filepath.Glob(d)
		if err != nil {
			return "", err
		}
		if len(n) > 0 {
			return n[0], nil
		}
	}
	return "", fmt.Errorf("could not find ld.so in %v", choices)
}
