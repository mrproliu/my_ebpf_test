package main

/*
#cgo CFLAGS: -I/usr/src/linux-headers-4.19.0-18-cloud-amd64/include/config
#include <kallsyms.h>
*/
import "C"
import "fmt"

func main() {
	buffer := C.CString("")
	d := C.uint64(18446744071901140000)
	result := C.sprint_symbol(buffer, d)
	fmt.Printf("%d", result)
}
