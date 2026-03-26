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

.PHONY: lint-branch
lint-branch:
	golangci-lint run --new-from-merge-base main

.PHONY: snapshot
snapshot:
	go test -v -run TestSnapshot -timeout 10m ./test/snapshot/

.PHONY: update-snapshots
update-snapshots:
	UPDATE_SNAPS=true go test -v -run TestSnapshot -timeout 10m ./test/snapshot/

.PHONY: update-vulndb
update-vulndb:
	go test -tags build_platform_vuln_database -run TestPopulateBuildPlatformVulnDatabase -timeout 10m ./opa/
	opa fmt -w opa/rego/external/build_platform.rego
