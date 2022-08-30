FROM golang:1.17

COPY grpc/ /service

WORKDIR /
RUN apt update && apt install -y zip && \
    mkdir protoc && cd protoc && \
    curl -sL https://github.com/protocolbuffers/protobuf/releases/download/v21.5/protoc-21.5-linux-x86_64.zip -o protoc.zip && \
    unzip protoc.zip

WORKDIR /service

RUN go get -u google.golang.org/protobuf/cmd/protoc-gen-go@v1.26.0 && \
    go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0 && \
    /protoc/bin/protoc --go_out=. --go-grpc_out=. service.proto
