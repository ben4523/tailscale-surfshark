.PHONY: build test smoke image lint clean run

BIN := bin/surfshark-control
PKG := ./...
IMAGE := tailscale-surfshark:dev

build:
	go build -o $(BIN) ./cmd/surfshark-control

test:
	go test -race -count=1 $(PKG)

image:
	docker build -t $(IMAGE) .

smoke: image
	bash test/integration/smoke.sh

lint:
	go vet $(PKG)

run: build
	./$(BIN)

clean:
	rm -rf bin/ dist/
