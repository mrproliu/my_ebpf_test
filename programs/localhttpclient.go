package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	for {
		resp, err := http.Get("http://localhost:9999/provider")

		if err != nil {
			log.Fatal(err)
		}
		_, _ = ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		time.Sleep(time.Second * 1)
	}
}
