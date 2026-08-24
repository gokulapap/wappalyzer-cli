APP := wappy
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/gokulapap/wappalyzer-cli/internal/buildinfo.Version=$(VERSION) \
	-X github.com/gokulapap/wappalyzer-cli/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/gokulapap/wappalyzer-cli/internal/buildinfo.Date=$(BUILD_DATE)

.PHONY: build install fmt fmt-check vet test check

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/wappy

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/wappy

fmt:
	gofmt -w cmd internal

fmt-check:
	test -z "$$(gofmt -l cmd internal)"

vet:
	go vet ./...

test:
	go test -race -coverprofile=coverage.out ./...

check: fmt-check vet test build
