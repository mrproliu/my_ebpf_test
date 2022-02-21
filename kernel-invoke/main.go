package main

/*
#cgo LDFLAGS: -lelf -lz
#cgo CFLAGS: -I/usr/include
#include <linux/kallsyms.h>
extern int sprint_symbol(char *buffer, unsigned long address);

int symbol_query(char *buffer, unsigned long address) {
	return sprint_symbol(buffer, address);
}
*/
import "C"
import "fmt"

func main() {
	//buffer := C.CString("")
	//result := C.sprint_symbol(buffer, 111)
	//fmt.Printf("%d", result)
	fmt.Printf("a")
	buffer := C.CString("")
	result := C.symbol_query(buffer, 111)
	fmt.Printf("%d", result)
}