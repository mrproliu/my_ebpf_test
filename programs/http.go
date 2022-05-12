package main

import (
	"log"
	"net/http"
	"time"
)

// nolint
func doRequest() {
	for true {
		_, err := http.Get("http://www.google.com")
		if err != nil {
			log.Fatalln(err)
		}
		time.Sleep(1 * time.Second)
	}
}

func main() {
	doRequest()
}
