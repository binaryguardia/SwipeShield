# Build the SwipeShield gateway binary and ship it in a minimal image. The
# config file is supplied at runtime (mounted by compose/k8s), not baked in.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /swipeshield ./cmd/swipeshield

FROM alpine:3.20
RUN adduser -D -u 10001 swipeshield
COPY --from=build /swipeshield /usr/local/bin/swipeshield
USER swipeshield
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/swipeshield"]
