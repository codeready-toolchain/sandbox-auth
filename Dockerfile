# syntax=docker/dockerfile:1
FROM golang:latest
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go test -v ./...
