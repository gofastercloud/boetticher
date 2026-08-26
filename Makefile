.PHONY: test build vet fmt

GOCACHE ?= /tmp/labinabox-gocache

fmt:
	gofmt -w cmd internal

test:
	GOCACHE=$(GOCACHE) go test ./...

vet:
	GOCACHE=$(GOCACHE) go vet ./...

build:
	GOCACHE=$(GOCACHE) go build -o bin/homelab ./cmd/homelab
