package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/provider", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("ok"))
		_ = request.Body.Close()
	})

	err := http.ListenAndServe(":9999", nil)
	log.Fatal(err)
}
