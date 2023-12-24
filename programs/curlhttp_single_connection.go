package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	for {
		sendSingleConnectionRequest()
		time.Sleep(time.Second)
	}
}

func sendSingleConnectionRequest() {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "http://www.baidu.com.com", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Ensure the connection is closed after completion
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
}
