package main

import (
	"math"
	"net/http"
)

func hello(w http.ResponseWriter, req *http.Request) {
	for {
		math.Sqrt(1000000000000)
	}
}

func main() {
	http.HandleFunc("/", hello)
	http.ListenAndServe(":8080", nil)
	bools := make(chan bool)
	<-bools
}
