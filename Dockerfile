FROM golang AS builder

ENV CGO_ENABLED 0
ENV GOOS linux

RUN apt update
RUN apt install tzdata
RUN apt install git

WORKDIR /build

ADD go.mod .
ADD go.sum .
RUN go mod download
COPY . .


RUN go build -ldflags="-s -w" -o /app/exec ./main.go

FROM alpine


WORKDIR /app

COPY --from=builder /app/exec /app/exec

CMD ["./exec"]