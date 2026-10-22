FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o server .

FROM scratch
# CA bundle for HTTPS calls to ntfy and Dex
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/server /server
ENV SCRIPTS_DIR=/data PORT=8080
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/server"]
