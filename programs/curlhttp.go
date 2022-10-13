package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	for true {
		get, err := http.Get("http://www.baidu.com")
		if err != nil {
			log.Fatal(err)
		}
		_, _ = ioutil.ReadAll(get.Body)
		get.Body.Close()

		time.Sleep(time.Second * 3)
	}
}
