# syntax=docker/dockerfile:1.6

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/surfshark-control ./cmd/surfshark-control

# Tailscale static binary stage — pinned to current latest, not alpine's lagging package.
FROM alpine:3.20 AS tailscale-stage
ARG TS_VERSION=1.98.4
ARG TS_ARCH=amd64
RUN apk add --no-cache curl tar ca-certificates && \
    curl -fsSL "https://pkgs.tailscale.com/stable/tailscale_${TS_VERSION}_${TS_ARCH}.tgz" \
      | tar -xz -C /tmp && \
    mv "/tmp/tailscale_${TS_VERSION}_${TS_ARCH}/tailscale" /tailscale && \
    mv "/tmp/tailscale_${TS_VERSION}_${TS_ARCH}/tailscaled" /tailscaled

FROM alpine:3.20
RUN apk add --no-cache \
    wireguard-tools \
    nftables \
    iptables \
    ip6tables \
    iproute2 \
    ca-certificates \
    curl \
    bash

COPY --from=tailscale-stage /tailscale /usr/bin/tailscale
COPY --from=tailscale-stage /tailscaled /usr/sbin/tailscaled
COPY --from=build /out/surfshark-control /app/surfshark-control
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
