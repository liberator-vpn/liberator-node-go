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
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/vpn-router

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
