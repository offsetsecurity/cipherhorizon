# syntax=docker/dockerfile:1
#
# CipherHorizon container image: the same static binary as the release archives, on a distroless
# base (no shell, no package manager, no libc), running as a non-root user.
#
#   docker build -t cipherhorizon --build-arg VERSION=0.1.0 .
#   docker run --rm -p 8080:8080 -e CIPHERHORIZON_TOKEN="$(openssl rand -hex 24)" -v ch-data:/data cipherhorizon
#
# Another port: set CIPHERHORIZON_PORT and publish that port; the health check follows it.
#   docker run --rm -p 127.0.0.1:9000:9000 -e CIPHERHORIZON_PORT=9000 -v ch-data:/data cipherhorizon
#
# The build stage always runs on the builder's native platform and cross-compiles, so a
# multi-arch image needs no emulation.

FROM --platform=$BUILDPLATFORM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS build
ARG TARGETOS
ARG TARGETARCH
ARG MODULE=github.com/offsetsecurity/cipherhorizon
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=0.0.0-dev
ARG COMMIT=
LABEL org.opencontainers.image.title="CipherHorizon" \
      org.opencontainers.image.description="Post-quantum readiness for the protocols your organisation runs on: TLS, SSH and, next, VPN. A deep scan of each, a readiness level from L0 to L4, and one CycloneDX CBOM, self-hosted." \
      org.opencontainers.image.vendor="Offset Security" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
COPY --from=build /out/cipherhorizon /cipherhorizon
# The SQLite database lives in /data (owned by uid 65532, distroless "nonroot"); mount a volume to keep it.
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME ["/data"]
WORKDIR /data
# The port is CIPHERHORIZON_PORT (serve and healthcheck both read it); 8080 unless set.
ENV CIPHERHORIZON_PORT=8080
EXPOSE 8080
# Sign-in is off by default, as everywhere (turn it on in Settings, or run with --sign-in on, which
# prints a one-time setup code to `docker logs`). Inside a container the server must listen on
# 0.0.0.0, so --open-network says that is intended: publish the port on the host's loopback only
# (-p 127.0.0.1:8080:8080, as docker-compose.yml does), or turn sign-in on before exposing it.
# --plain-http is right for that, or behind a TLS-terminating proxy; to serve HTTPS directly, mount a
# certificate and override CMD with --tls-cert/--tls-key instead.
ENTRYPOINT ["/cipherhorizon"]
CMD ["serve", "--addr", "0.0.0.0", "--plain-http", "--open-network", "--db", "/data/cipherhorizon.db"]
# The base image has no shell, curl or wget, so the binary checks its own /api/v1/health.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD ["/cipherhorizon", "healthcheck"]
