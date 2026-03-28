.PHONY: all clean test

all: bin/sknockd bin/sknock

bin/sknockd:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/sknockd ./cmd/sknockd

bin/sknock:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/sknock ./cmd/sknock

test:
	go test ./...

clean:
	rm -rf bin/
