package main

import (
	"fmt"
	"math"
	"net/http"
)

func sqrt(x float64) float64 {
	var r = x
	var precision = 1e-10
	var eps = math.Abs(x - r*r)
	for eps > precision {
		r = (r + x/r) / 2
		eps = math.Abs(x - r*r)
	}
	return r
}

func hello(w http.ResponseWriter, req *http.Request) {
	for {
		var x = 100000000000000.0
		sqrt(x)
	}
	w.Write([]byte(fmt.Sprintf("Hello, world!")))
}

func main() {
	http.HandleFunc("/", hello)
	http.ListenAndServe(":8000", nil)
}
