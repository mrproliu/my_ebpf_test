package main

/*
#include "load_so.h"
#cgo LDFLAGS: -ldl
*/
import "C"
import "fmt"

func main() {
	fmt.Println("20*30=", C.do_test_so_func(20, 30, 10))
}
