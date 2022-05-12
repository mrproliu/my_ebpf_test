package main

import (
	"math"
)

// nolint
func sqrtGo() {
	for {
		math.Sqrt(100000000000000.0)
	}
}

func main() {
	sqrtGo()
}
