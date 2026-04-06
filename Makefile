.PHONY: build run clean

build:
	go build -o bin/godoip ./cmd/server

run:
	go run ./cmd/server

clean:
	rm -rf bin/