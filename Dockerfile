# syntax=docker/dockerfile:1

# ---- build stage ----------------------------------------------------------
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/mpegts-audit ./cmd/server

# ---- runtime stage --------------------------------------------------------
FROM alpine:3.20 AS runtime
RUN adduser -D -u 10001 appuser
COPY --from=build /out/mpegts-audit /usr/local/bin/mpegts-audit
USER appuser
ENV PORT=8080
EXPOSE 8080
# Shell form so ${PORT} expands inside the container; busybox wget is in alpine.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/healthz" || exit 1
ENTRYPOINT ["/usr/local/bin/mpegts-audit"]

# ---- one-shot verification stage ------------------------------------------
# Contains the full source and toolchain: runs tests, rebuilds the app, waits
# for the app service to report healthy, then exercises legal and broken
# streams. Reports via its own exit code and terminates.
FROM golang:1.27-alpine AS verify
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
CMD ["go", "run", "./cmd/verify"]
