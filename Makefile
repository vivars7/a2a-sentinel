.PHONY: build test run docker-build validate lint

build:
	go build -o bin/sentinel ./cmd/sentinel

test:
	go test -race -v ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

run:
	go run ./cmd/sentinel --config sentinel.yaml

validate:
	go run ./cmd/sentinel validate --config sentinel.yaml

docker-build:
	docker build -t a2a-sentinel:latest .

lint:
	gofmt -l .
	go vet ./...
