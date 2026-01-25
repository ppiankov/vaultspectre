.PHONY: build test clean install fmt vet

BINARY_NAME=vaultspectre
BUILD_DIR=./bin
CMD_DIR=./cmd/vaultspectre

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

install:
	@echo "Installing $(BINARY_NAME)..."
	@go install $(CMD_DIR)

test:
	@echo "Running tests..."
	@go test -v ./...

fmt:
	@echo "Formatting code..."
	@go fmt ./...

vet:
	@echo "Vetting code..."
	@go vet ./...

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

all: fmt vet test build
