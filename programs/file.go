package main

import (
	"fmt"
	"os"
)

func main() {
	d1 := []byte("hello\ngo\n")
	for {
		err := os.WriteFile("/tmp/dat1", d1, 0644)
		if err != nil {
			fmt.Printf("error: %v", err)
			break
		}

		//time.Sleep(time.Second * 1)
	}
}
