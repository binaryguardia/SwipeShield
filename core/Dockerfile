# Build the SentinelWAF gateway binary and ship it in a minimal image. The
# config file is supplied at runtime (mounted by compose/k8s), not baked in.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /sentinelwaf ./cmd/sentinelwaf

FROM alpine:3.20
RUN adduser -D -u 10001 sentinelwaf
COPY --from=build /sentinelwaf /usr/local/bin/sentinelwaf
USER sentinelwaf
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/sentinelwaf"]
