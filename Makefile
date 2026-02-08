VERSION := 0.1.0
BINARY  := diffy
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/diffy

test:
	go test ./...

clean:
	rm -f $(BINARY)
