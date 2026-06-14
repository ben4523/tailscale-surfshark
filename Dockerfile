# syntax=docker/dockerfile:1.6

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/surfshark-control ./cmd/surfshark-control

FROM alpine:3.20
RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    ca-certificates \
    curl \
    bash \
    tailscale

COPY --from=build /out/surfshark-control /app/surfshark-control
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
