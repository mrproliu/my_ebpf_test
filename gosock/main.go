package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
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

	files, err := ioutil.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		log.Fatalf("read files error: %v", err)
	}
	for _, file := range files {
		fd, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}
		link := fmt.Sprintf("/proc/%d/fd/%s", pid, file.Name())
		dest, err := os.Readlink(link)
		if err != nil {
			log.Fatalf("read link error: %s, %v", link, err)
			continue
		}
		fmt.Printf("%d: %s\n", fd, dest)
	}
}
