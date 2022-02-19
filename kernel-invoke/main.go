package main

/*
extern int sprint_symbol(char *buffer, unsigned long address);
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
