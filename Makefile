GO ?= go
VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build windows linux darwin test vet clean

all: vet test windows

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o dist/husmea ./cmd/husmea

windows:
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/husmea.exe ./cmd/husmea
	GOOS=windows GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/husmea-arm64.exe ./cmd/husmea

linux:
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/husmea-linux ./cmd/husmea

darwin:
	GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/husmea-darwin ./cmd/husmea

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...
	GOOS=windows $(GO) vet ./...

clean:
	rm -rf dist husmea-reports
