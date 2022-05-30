package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
)

func main() {
	if len(os.Args) <= 1 {
		log.Fatal("please input the thread count")
		return
	}

	count, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal("could not reconized the count: %s", os.Args[1])
		return
	}
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	c := make(chan bool, 1)

	server := &http.Server{
		Addr: ":5415",
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			defer request.Body.Close()
			writer.Write([]byte("ok"))
		}),
	}

	go func() {
		<-quit
		close(c)
		if err := server.Close(); err != nil {
			log.Fatal("Close server:", err)
		}
	}()

	go func() {
		for i := 0; i < count; i++ {
			go func() {
				for true {
					select {
					case <-c:
						return
					default:
						localhttpRequest()
					}
				}
			}()
		}
	}()

	log.Println("Starting httpserver")
	err = server.ListenAndServe()
	if err != nil {
		// 正常退出
		if err == http.ErrServerClosed {
			log.Fatal("Server closed under request")
		} else {
			log.Fatal("Server closed unexpected", err)
		}
	}
}

func localhttpRequest() {
	get, e := http.Get("http://localhost:5415")
	if e != nil {
		log.Printf("read error: %v", e)
	}
	if get == nil || get.Body == nil {
		return
	}
	defer get.Body.Close()
	_, e = ioutil.ReadAll(get.Body)
	if e != nil {
		log.Printf("read error: %v", e)
	}
}
