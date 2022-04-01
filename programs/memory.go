package main

import (
	"math"
)

//go:noinline
func test() {
	math.Sqrt(1000)
}
func main() {
	for true {
		//array := make([]string, 1000)
		//for i := 0; i < 1000; i++ {
		//	array[i] = fmt.Sprintf("%d---", i)
		//}
		test()
	}
}
