package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

func InetNtop(src unsafe.Pointer) string {
	return net.IP((*(*[net.IPv4len]byte)(src))[:]).String()
}

func main() {
	var ip uint32 = 33558956
	var port uint16 = 45418
	fmt.Printf("%d\n", binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&port)))[:]))
	fmt.Printf("%s", InetNtop(unsafe.Pointer(&ip)))
}
