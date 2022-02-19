package main

/*
#cgo CFLAGS: -I/usr/src/linux-headers-4.19.0-18-cloud-amd64/include/config
#include <kallsyms.h>
*/
import "C"
import "fmt"

func main() {
	//buffer := C.CString("")
	//result := C.sprint_symbol(buffer, 111)
	//fmt.Printf("%d", result)
	fmt.Printf("a")
	buffer := C.CString("")
	result := C.sprint_symbol(buffer, 111)
	fmt.Printf("%d", result)
}
