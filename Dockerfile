# syntax=docker/dockerfile:1
#
# CipherHorizon container image: the same static binary as the release archives, on a distroless
# base (no shell, no package manager, no libc), running as a non-root user.
#
#   docker build -t cipherhorizon --build-arg VERSION=0.1.0 .
#   docker run --rm -p 8080:8080 -e CIPHERHORIZON_TOKEN="$(openssl rand -hex 24)" -v ch-data:/data cipherhorizon
#
# The build stage always runs on the builder's native platform and cross-compiles, so a
# multi-arch image needs no emulation.

FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS
ARG TARGETARCH
ARG MODULE=github.com/example/cipherhorizon
ARG VERSION=0.0.0-dev
ARG COMMIT=
ARG DATE=
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X ${MODULE}/internal/version.Version=${VERSION} -X ${MODULE}/internal/version.Commit=${COMMIT} -X ${MODULE}/internal/version.Date=${DATE}" \
      -o /out/cipherhorizon ./cmd/cipherhorizon
# distroless has no shell to mkdir with, so the writable data directory is made here.
RUN mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=0.0.0-dev
ARG COMMIT=
LABEL org.opencontainers.image.title="CipherHorizon" \
      org.opencontainers.image.description="A cryptographic inventory that ranks your systems for the move to post-quantum cryptography" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
COPY --from=build /out/cipherhorizon /cipherhorizon
# The SQLite database lives in /data (owned by uid 65532, distroless "nonroot"); mount a volume to keep it.
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME ["/data"]
WORKDIR /data
EXPOSE 8080
# Sign-in is required (ADR-0018): on first start the log prints a one-time setup code for the
# administrator (`docker logs cipherhorizon`). --plain-http is right when the port is published
# only on the host (as docker-compose.yml does) or a TLS-terminating proxy is in front; to serve
# HTTPS directly, mount a certificate and override CMD with --tls-cert/--tls-key instead.
ENTRYPOINT ["/cipherhorizon"]
CMD ["serve", "--addr", "0.0.0.0:8080", "--plain-http", "--db", "/data/cipherhorizon.db"]
# The base image has no shell, curl or wget, so the binary checks its own /api/v1/health.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD ["/cipherhorizon", "healthcheck", "--addr", "127.0.0.1:8080"]
