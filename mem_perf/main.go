package main

import (
	"debug/elf"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

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

	links, err := readLinks(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("total links:\n")
	for _, va := range links {
		fmt.Printf("%s\n", va)
	}
}

func readLinks(file string) ([]string, error) {
	fd, err := os.OpenFile(file, os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open file error: %v", err)
	}

	// Populate ELF fields
	bin, err := elf.NewFile(fd)
	if err != nil {
		return nil, fmt.Errorf("elf file error: %v", err)
	}

	searchPath := make([]string, 0)

	// Check ELF Class
	if bin.Class == elf.ELFCLASS32 {
		searchPath = append(searchPath, "/lib/")
	} else if bin.Class == elf.ELFCLASS64 {
		searchPath = append(searchPath, "/lib64/")
	} else {
		return nil, fmt.Errorf("unknown ELF Class")
	}

	// env parse LD_LIBRARY_PATH
	env := os.Getenv("LD_LIBRARY_PATH")
	paths := strings.Split(env, ":")
	searchPath = append(searchPath, paths...)
	// SO files are searched through LD_LIBRARY_PATH and lib/lib64

	// Get list of needed shared libraries
	dynSym, err := bin.DynString(elf.DT_NEEDED)
	if err != nil {
		return nil, fmt.Errorf("read needes error: %v", err)
	}

	fmt.Printf("111\n")
	// Recurse
	soPath := recurseDynStrings(dynSym, searchPath)

	fmt.Printf("222\n")
	result := make([]string, 0)
	for _, v := range soPath {
		result = append(result, v)
	}

	return result, nil
}

func recurseDynStrings(dynSym []string, searchPath []string) map[string]string {
	soPath := make(map[string]string, 0)
	for _, el := range dynSym {
		// fmt.Println(el)
		// check file path here for library if it doesnot exists panic
		var fd *os.File
		for _, entry := range searchPath {
			path := entry + el
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				fd, err = os.OpenFile(path, os.O_RDONLY, 0644)
				if err != nil {
					log.Fatal(err)
				} else {
					soPath[el] = path
				}
			} else {
				// Nothing
			}
		}

		bint, err := elf.NewFile(fd)
		if err != nil {
			log.Fatal(err)
		}

		bDynSym, err := bint.DynString(elf.DT_NEEDED)
		if err != nil {
			log.Fatal(err)
		}

		dynStrings := recurseDynStrings(bDynSym, searchPath)
		for k, v := range dynStrings {
			soPath[k] = v
		}
	}
	return soPath
}
