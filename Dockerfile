# syntax=docker/dockerfile:1
FROM docker.io/golang:1.18
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go install goa.design/goa/v3/cmd/goa@v3
RUN goa gen github.com/codeready-toolchain/sandbox-auth/design
RUN go build -v -o sandbox-auth
RUN ls -l
RUN cp -r gen/* /gen