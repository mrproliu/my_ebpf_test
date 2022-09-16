package main

import (
	"log"
	"net/http"
	"time"
)

// nolint
func doRequest() {
	for true {
		t, err := http.Get("http://www.baidu.com")
		if err != nil {
			log.Fatalln(err)
		}
		t.Body.Close()
		time.Sleep(1 * time.Second)
	}
}

func main() {
	doRequest()
}
