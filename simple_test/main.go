package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func BytesToInt(bys []byte) int {
	bytebuff := bytes.NewBuffer(bys)
	var data int64
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}

func main() {
	bytes := make([]byte, 4)
	bytes[0] = 92
	bytes[1] = 40
	bytes[2] = 0
	bytes[3] = 0

	binary.ByteOrder.Uint32(bytes)
	fmt.Printf("%d", BytesToInt(bytes))
}
