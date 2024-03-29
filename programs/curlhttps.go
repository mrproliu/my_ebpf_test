package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	time.Sleep(time.Second * 3)
	for true {
		get, err := http.Get("https://www.google.com")
		if err != nil {
			log.Fatal(err)
		}
		_, _ = ioutil.ReadAll(get.Body)
		get.Body.Close()

		time.Sleep(time.Second * 1)
	}
}
