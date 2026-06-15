# syntax=docker/dockerfile:1.6

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/surfshark-control ./cmd/surfshark-control

# Build wireguard-go (userspace WireGuard) — DSM kernels typically miss the
# wireguard.ko module, so we ship our own userspace implementation.
FROM golang:1.25-alpine AS wg-build
RUN apk add --no-cache git
RUN CGO_ENABLED=0 go install golang.zx2c4.com/wireguard@latest

# Tailscale static binary stage — pinned to current latest.
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
    docker-cli \
    docker-cli-compose \
    wireguard-tools \
    nftables \
    iptables \
    iptables-legacy \
    ip6tables \
    iproute2 \
    ca-certificates \
    curl \
    bash \
    socat

COPY --from=tailscale-stage /tailscale /usr/bin/tailscale
COPY --from=tailscale-stage /tailscaled /usr/sbin/tailscaled
COPY --from=wg-build /go/bin/wireguard /usr/bin/wireguard-go
COPY --from=build /out/surfshark-control /app/surfshark-control
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/entrypoint-front.sh /entrypoint-front.sh
RUN chmod +x /entrypoint.sh /entrypoint-front.sh

# Force iptables/ip6tables to point at the legacy backend. DSM kernels lack
# the nf_tables module, so iptables-nft fails with "Could not fetch rule set
# generation id". Tailscale in kernel-TUN mode calls /sbin/iptables directly
# to set up its ts-input / ts-forward chains; without this symlink, tailscaled
# can't bring up its router and the kernel TUN device never appears.
RUN ln -sf /sbin/iptables-legacy /sbin/iptables \
 && ln -sf /sbin/ip6tables-legacy /sbin/ip6tables \
 && ln -sf /sbin/iptables-legacy-save /sbin/iptables-save \
 && ln -sf /sbin/iptables-legacy-restore /sbin/iptables-restore \
 && mkdir -p /etc/iproute2 \
 && echo "200 tss-egress" > /etc/iproute2/rt_tables

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
