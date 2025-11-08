BINARY_NAME=smtp-local
MAIN=cmd/smtp-local/main.go

.PHONY: run build dev

run:
	go run $(MAIN)

build:
	go build -o bin/$(BINARY_NAME) $(MAIN)

dev:
	go run -mod=mod github.com/air-verse/air
