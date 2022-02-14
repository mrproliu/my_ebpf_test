package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	for {
		d1 := []byte("hello\ngo\n")
		err := os.WriteFile("/tmp/dat1", d1, 0644)
		if err != nil {
			fmt.Printf("error: %v", err)
			break
		}

		time.Sleep(time.Second * 1)
	}
}
