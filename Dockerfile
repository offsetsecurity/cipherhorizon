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
      org.opencontainers.image.description="PQC readiness and TLS posture workbench" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
COPY --from=build /out/cipherhorizon /cipherhorizon
# The SQLite database lives in /data (owned by uid 65532, distroless "nonroot"); mount a volume to keep it.
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME ["/data"]
WORKDIR /data
EXPOSE 8080
# Listening beyond loopback requires an access token: pass CIPHERHORIZON_TOKEN (or --token).
ENTRYPOINT ["/cipherhorizon"]
CMD ["serve", "--addr", "0.0.0.0:8080", "--db", "/data/cipherhorizon.db"]
