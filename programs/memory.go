package main

import (
	"time"
)

//go:noinline
func test() {
	buf := []byte{}
	mb := 1024 * 1024

	for {
		buf = append(buf, make([]byte, mb)...)
		time.Sleep(time.Second)
	}
}
func main() {
	test()
}
