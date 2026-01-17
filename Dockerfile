# Multi-stage build for optimized Go application
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o phishing-scanner ./cmd/server

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/phishing-scanner .

# Copy data directory with linguistic stats and test emails
COPY --from=builder /app/data ./data

# Copy templates
COPY --from=builder /app/cmd/server/templates ./templates

# Copy static assets (CSS, etc.)
COPY --from=builder /app/cmd/server/static ./static

# Expose port
EXPOSE 8080

# Run the application
CMD ["./phishing-scanner"]
