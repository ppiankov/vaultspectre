BINARY    := vaultspectre
MODULE    := github.com/ppiankov/vaultspectre
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION_NUM := $(VERSION:v%=%)
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS   := -X $(MODULE)/internal/commands.Version=$(VERSION_NUM) -X $(MODULE)/internal/commands.Commit=$(COMMIT)

.PHONY: build test lint clean

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/vaultspectre

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ dist/

.DEFAULT_GOAL := build
