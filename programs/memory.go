package main

import "fmt"

func main() {
	for true {
		array := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			array[i] = fmt.Sprintf("%d---", i)
		}
	}
}
