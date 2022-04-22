package main

import (
	"math"
	"net/http"
)

func hello(w http.ResponseWriter, req *http.Request) {
	for {
		math.Sqrt(100000000000000.0)
	}
}

func main() {
	http.HandleFunc("/", hello)
	http.ListenAndServe(":8000", nil)
}
