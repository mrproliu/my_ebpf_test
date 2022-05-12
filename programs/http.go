package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	for true {
		_, err := http.Get("http://www.google.com")
		if err != nil {
			log.Fatalln(err)
		}
		time.Sleep(1 * time.Second)
	}
}
