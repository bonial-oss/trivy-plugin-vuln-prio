# SPDX-FileCopyrightText: 2026 Bonial International GmbH
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help

TEST_FLAGS ?= -race
PKGS       ?= $(shell go list ./... | grep -v /vendor/)
BINARY     := vuln-prio

.PHONY: all clean

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build    - Build the vuln-prio binary (rebuilds on Go file or go.mod/go.sum changes)"
	@echo "  test     - Run all Go tests with race detection"
	@echo "  vet      - Run go vet on all packages"
	@echo "  coverage - Generate code coverage report"
	@echo "  lint     - Run golangci-lint on the codebase"
	@echo "  serve    - Serve documentation locally via mkdocs"
	@echo "  clean    - Remove build artifacts"

.PHONY: build
build: $(BINARY)

$(BINARY): $(shell find . -type f -name '*.go') go.mod go.sum
	go build \
		-ldflags "-s -w" \
		-o $(BINARY) \
		main.go

.PHONY: test
test:
	go test $(TEST_FLAGS) $(PKGS)

.PHONY: vet
vet:
	go vet $(PKGS)

.PHONY: coverage
coverage:
	go test $(TEST_FLAGS) -covermode=atomic -coverprofile=coverage.txt $(PKGS)
	go tool cover -func=coverage.txt

.PHONY: lint
lint:
	golangci-lint run

.PHONY: serve
serve:
	mkdocs serve

clean:
	rm -f $(BINARY) coverage.txt
