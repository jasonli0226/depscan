.PHONY: build run test clean install fmt lint help

BINARY_NAME=depscan
GO=go
GOFLAGS=-v

build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

run:
	$(GO) run .

test:
	$(GO) test ./... -v

clean:
	rm -f $(BINARY_NAME)
	$(GO) clean

install:
	$(GO) install .

fmt:
	$(GO) fmt ./...

lint:
	golangci-lint run ./...

help:
	@echo "Available targets:"
	@echo "  build   - Build the $(BINARY_NAME) binary"
	@echo "  run     - Run the application"
	@echo "  test    - Run tests"
	@echo "  clean   - Remove build artifacts"
	@echo "  install - Install binary to GOPATH/bin"
	@echo "  fmt     - Format code"
	@echo "  lint    - Run golangci-lint"
	@echo "  help    - Show this help message"
