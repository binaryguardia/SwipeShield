FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /demoapp .

FROM scratch
COPY --from=build /demoapp /demoapp
EXPOSE 9000
ENTRYPOINT ["/demoapp"]
