package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"test/service"
	"time"

	"google.golang.org/grpc/credentials/insecure"

	"google.golang.org/grpc"
)

var (
	httpPort = 8080
	gRPCPort = 9000
	gRPCConn *grpc.ClientConn
)

type Provider struct {
	service.UnimplementedServiceServer
}

func singleCall(w http.ResponseWriter, req *http.Request) {
	if gRPCConn == nil {
		dial, err := grpc.Dial(fmt.Sprintf("localhost:%d", gRPCPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Printf("init gRPC client failure: %v", err)
			_, _ = w.Write([]byte("error"))
			return
		}
		gRPCConn = dial
	}

	client := service.NewServiceClient(gRPCConn)
	resp, err := client.SingleCall(context.Background(), &service.CallRequest{})
	if err != nil {
		log.Printf("send single call request failure: %v", err)
		_, _ = w.Write([]byte("error"))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(resp.Message))
}

func (p *Provider) SingleCall(context.Context, *service.CallRequest) (*service.CallReply, error) {
	return &service.CallReply{Message: "response success"}, nil
}

func (p *Provider) StreamCall(s service.Service_StreamCallServer) error {
	for true {
		_, err := s.Recv()
		if err == io.EOF {
			s.SendAndClose(&service.StreamReply{})
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	server := grpc.NewServer()
	service.RegisterServiceServer(server, &Provider{})
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", gRPCPort))
	if err != nil {
		log.Fatalf("listen gRPC port failure: %v", err)
		return
	}
	go func() {
		if err := server.Serve(listen); err != nil {
			log.Fatalf("startup gRPC server failure")
		}
	}()

	if gRPCConn == nil {
		dial, err := grpc.Dial(fmt.Sprintf("localhost:%d", gRPCPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatal(err)
			return
		}
		gRPCConn = dial
	}

	client := service.NewServiceClient(gRPCConn)
	//_, err := client.SingleCall(context.Background(), &service.CallRequest{})
	call, err := client.StreamCall(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	i := 0
	for true {
		i++
		if i == 10 {
			_, _ = call.CloseAndRecv()
			i = 0
			call, err = client.StreamCall(context.Background())
			if err != nil {
				log.Fatal(err)
			}
		}
		err := call.Send(&service.StreamRequest{})
		if err != nil {
			log.Fatal(err)
			return
		}
		time.Sleep(time.Second)
	}

	//http.HandleFunc("/singleCall", singleCall)
	//err1 := http.ListenAndServe(fmt.Sprintf(":%d", httpPort), nil)
	//log.Fatal(err1)
}
