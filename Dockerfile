FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY README.md ./
COPY templates/ ./templates/
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /pi-session-share-server .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /pi-session-share-server /usr/local/bin/pi-session-share-server

EXPOSE 8080
ENTRYPOINT ["pi-session-share-server"]
