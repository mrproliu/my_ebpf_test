package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"os"
)

func main() {
	explicitNonceLen := 8                                                                  // config: recordIvSize
	key := []byte{166, 173, 151, 86, 154, 34, 247, 81, 134, 166, 240, 4, 235, 63, 252, 95} // config: key
	tagSize := 16                                                                          // config: tagSize
	fixIv := []byte{157, 219, 131, 97}                                                     // cofnig: fix IV

	aesCipher, err := aes.NewCipher(key)
	file, _ := os.ReadFile("/root/test/1")
	data := file[:211] // 只读取真实的数据内容

	payload := data[5:]
	nonce := payload[:explicitNonceLen]
	payload = payload[explicitNonceLen:]

	var additionalData = []byte{0, 0, 0, 0, 0, 0, 0, 1}  // 序列号, 1 for test
	additionalData = append(additionalData, data[:3]...) // 增加头信息
	n := len(payload) - tagSize
	additionalData = append(additionalData, byte(n>>8), byte(n))

	if err != nil {
		log.Fatalf("aes error: %v", err)
	}
	gcm, err := cipher.NewGCMWithTagSize(aesCipher, tagSize)
	if err != nil {
		log.Fatalf("gcm error: %v", err)
	}
	nonce = append(fixIv, nonce...)
	open, err := gcm.Open(payload[:0], nonce, payload, additionalData)
	if err != nil {
		log.Fatalf("decrypt error: %v", err)
	}
	fmt.Printf("result: %s", string(open))
}
