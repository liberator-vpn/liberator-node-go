# ---- xray-core ----
# Нода запускает Xray как дочерний процесс для VLESS+REALITY/Hysteria2.
FROM alpine:3.22 AS xray
ARG XRAY_VERSION=v26.11.9
ARG TARGETARCH=amd64
RUN apk add --no-cache curl unzip && \
    case "$TARGETARCH" in \
      amd64) asset="Xray-linux-64.zip" ;; \
      arm64) asset="Xray-linux-arm64-v8a.zip" ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${asset}" && \
    unzip -q /tmp/xray.zip -d /xray

# ---- build stage ----
FROM golang:1.26.2-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# sqlite убран -> CGO не нужен, бинарь чистый статический.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/vpn-router ./cmd/node

# ---- runtime stage ----
FROM alpine:3.22

# iptables + корневые CA (нода ходит по HTTPS к IP-API и в будущем к API).
RUN apk add --no-cache iptables ca-certificates

COPY --from=builder /out/vpn-router /usr/local/bin/vpn-router
COPY --from=xray /xray/xray /usr/local/bin/xray
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/vpn-router /usr/local/bin/xray

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
