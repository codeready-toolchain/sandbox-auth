SHELL := /bin/bash
UID := $(shell id -u)

.PHONY: build
build:
	mkdir -p $(PWD)/gen
	podman build --volume $(PWD)/gen:/gen:z,U -t sandbox-auth .

.PHONE: test
test: build
	DOCKER_HOST=unix:///run/user/${UID}/podman/podman.sock \
	go test -v ./...