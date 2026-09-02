# Multi-stage Dockerfile for Consteon QR Generator
# Stage 1: Build binary
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install ca-certificates and git
RUN apk add --no-cache ca-certificates git

# Cache dependencies
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source
COPY . .

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /qr-server ./cmd/server

# Stage 2: Minimal runtime image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /

COPY --from=builder /qr-server /qr-server

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/qr-server"]
