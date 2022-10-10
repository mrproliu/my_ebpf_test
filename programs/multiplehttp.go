package main

import (
	"net/http"
	"time"
)

func main() {
	for i := 0; i < 3; i++ {
		go func() {
			for true {
				t, _ := http.Get("http://www.baidu.com")
				t.Body.Close()
				time.Sleep(1 * time.Second)
			}
		}()
	}
	s := make(chan bool, 1)
	<-s
}
