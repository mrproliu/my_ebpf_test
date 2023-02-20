package main

import (
	"log"
	"math/rand"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/provider", func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if rand.Float32() > 0.5 {
			writer.WriteHeader(500)
			return
		}
		time.Sleep(time.Second * 2)
		writer.Write([]byte("ok"))
	})

	err := http.ListenAndServe(":9999", nil)
	log.Fatal(err)
}
