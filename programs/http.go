package main

import (
	"net/http"
	"time"
)

// nolint
func doRequest() {
	for true {
		t, err := http.Get("http://www.baidu.com")
		if err != nil {
			continue
			//log.Fatalln(err)
		}
		t.Body.Close()
		time.Sleep(1 * time.Second)
	}
}

func main() {
	doRequest()
}
