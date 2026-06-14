.PHONY: build test test-integration lint clean run

BIN := bin/surfshark-control
PKG := ./...

build:
	go build -o $(BIN) ./cmd/surfshark-control

test:
	go test -race -count=1 $(PKG)

test-integration:
	cd test/integration && docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from runner

lint:
	go vet $(PKG)

run: build
	./$(BIN)

clean:
	rm -rf bin/ dist/
