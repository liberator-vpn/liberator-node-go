FROM golang:1.26.2-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Копируем весь код
COPY . .

# Собираем, указывая путь к пакету с main (замените на ваш)
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o vpn-router ./cmd/node/main.go

FROM alpine:3.22



RUN apk add --no-cache iptables

COPY --from=builder /app/vpn-router /usr/local/bin/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /usr/local/bin/vpn-router

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]