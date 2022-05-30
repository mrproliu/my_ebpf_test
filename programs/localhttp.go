package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"time"
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

	s := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			defer request.Body.Close()
			writer.Write([]byte("ok"))
		}),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go log.Fatal(s.ListenAndServe())

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	c := make(chan bool, 1)

	go func() {
		<-quit
		close(c)
		if err := s.Close(); err != nil {
			log.Fatal("Close server:", err)
		}
	}()

	log.Printf("starting send requests...")
	var counter int64
	go func() {
		for i := 0; i < count; i++ {
			go func() {
				for true {
					select {
					case <-c:
						return
					default:
						localhttpRequest(counter)
					}
				}
			}()
		}
	}()

	go func() {
		timer := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-c:
				return
			case <-timer.C:
				log.Printf("total send request count: %d", counter)
			}
		}
	}()
}

func localhttpRequest(counter int64) {
	resp, err := http.Get("http://localhost:5415")
	if err != nil {
		// handle error
		log.Printf("get error: %v", err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	atomic.AddInt64(&counter, 1)
}
