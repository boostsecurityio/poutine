SHELL=/usr/bin/env bash
.SHELLFLAGS=-o pipefail -ec
.DEFAULT_GOAL := test

.PHONY: build
build:
	go build -o poutine .

ci: fmt test lint

test:
	go test ./... -cover

fmt:
	go fmt ./...

lint:
	golangci-lint run
