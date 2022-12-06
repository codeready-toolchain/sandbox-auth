# syntax=docker/dockerfile:1
FROM golang:1.19-buster
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go build -v -o sandbox-auth
RUN ls -l
