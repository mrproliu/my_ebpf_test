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
		Addr: ":5415",
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte("ok"))
			_ = request.Body.Close()
		}),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		log.Fatal(s.ListenAndServe())
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	c := make(chan bool, 1)

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
						counter = atomic.AddInt64(&counter, 1)
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
				swapInt64 := atomic.SwapInt64(&counter, 0)
				log.Printf("total send request count in 5 secs: %d", swapInt64)
			}
		}
	}()

	<-quit
	close(c)
	if err := s.Close(); err != nil {
		log.Fatal("Close server:", err)
	}
}

func localhttpRequest(counter int64) {
	resp, err := http.Get("http://localhost:5415")
	if err != nil {
		// handle error
		log.Printf("get error: %v", err)
		return
	}
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
}