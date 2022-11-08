package main

import (
	"fmt"
	"time"
)

func main() {
	for {
		now := time.Now()
		fmt.Printf("current second: %d, nano: %d", now.Unix(), now.Nanosecond())

		time.Sleep(time.Second)
	}
}
