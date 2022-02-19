package main

/*
#cgo CFLAGS: -I/usr/src/linux-headers-4.19.0-18-cloud-amd64/include/config
#include <kallsyms.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
	s := ""
	buffer := C.CString(s)
	result := C.sprint_symbol(buffer, 0)
	fmt.Printf("%d\n", result)
	fmt.Printf("%s", buffer)
	C.free(unsafe.Pointer(buffer))
}
