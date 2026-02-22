# syntax=docker/dockerfile:1

FROM golang:1.25.6 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/monarch .


FROM alpine:3.21

RUN addgroup -S monarch && adduser -S -G monarch monarch \
  && apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=build /out/monarch /app/monarch

USER monarch

EXPOSE 8080

ENTRYPOINT ["/app/monarch"]
