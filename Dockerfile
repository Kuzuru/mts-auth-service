FROM golang:1.18-buster as builder

WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o application ./...

FROM alpine:3.15.4
COPY --from=builder /app/application /app/application
CMD ["/app/application"]
