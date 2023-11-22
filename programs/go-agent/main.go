package main

import (
	"github.com/gin-gonic/gin"

	_ "github.com/apache/skywalking-go"
)

func main() {
	engine := gin.New()
	engine.Handle("GET", "/", func(context *gin.Context) {
		context.Status(200)
	})

	_ = engine.Run(":8080")
}
