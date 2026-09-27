# Build and distribution

What a release contains, how it is built, where users get it, and how they check it is genuine.

## How it is built

CipherHorizon is two Go programs (below), each **one static binary per platform, no runtime, no C library, no
installer dependencies**. `CGO_ENABLED=0` is a hard rule (the SQLite driver is the pure-Go `modernc.org/sqlite`), which
is what makes cross-compiling from a single Linux runner possible and the binaries run on a bare host or in a
`scratch`-class container. The UI is compiled into the binary with `go:embed`, so there is no separate web
build and nothing to serve from disk.

| Where | Command | Result |
|---|---|---|
| a developer's machine | `make build` / `make collector` (or `go build ./cmd/cipherhorizon`, `./cmd/cipherhorizon-collector`) | stamped binaries in `dist/` |
| CI on every PR | `goreleaser release --snapshot` + `docker build` | proves the release build works; nothing published |
| a release tag | `release.yml` → GoReleaser + buildx | the artifacts below |

The version, commit and commit date are stamped into the binary by the linker (`internal/version`). Timestamps
inside archives come from the commit, and builds use `-trimpath`, so building the same tag twice yields the same
archives.

## Two programs: the collector and the product

| Program | Contains | Deploy it on |
|---|---|---|
| **`cipherhorizon-collector`** (about 4 MB) | the host inventory only: `run`, `plugins`, `version`. Read-only, no subprocess, no network. No web server, no database, no TLS scanner. | **every machine you want inventoried** |
| `cipherhorizon` (about 13 MB) | everything: the collector's `run`, the TLS scanner, the web server and UI, the SQLite store | the machine that **receives and views** results (and scans endpoints) |

The collector is deliberately separate ([ADR-0011](../decisions/ADR-0011-separate-endpoint-collector.md)): an endpoint
should carry the least code that does the job, and a test (`internal/archtest`) fails the build if the collector
ever links the server, the store or the scanner. A machine being inventoried needs one file and no configuration:

```sh
./cipherhorizon-collector run -o host.cbom.json      # then upload host.cbom.json on the Hosts page
```

### Handing the collector to a fleet from the running server

The collector and the product are separate release archives, so a fresh install of `cipherhorizon` does not have
`cipherhorizon-collector` sitting beside it. If an operator puts one there anyway (having downloaded it once, or
built it), the server offers it to anyone who opens the UI, instead of everyone finding it themselves:

- a same-platform companion file next to the server's own executable, named `cipherhorizon-collector` (or
  `cipherhorizon-collector.exe` on Windows) — the common case, since the two archives usually get unpacked
  together; or
- a `collectors/` folder next to the executable holding one binary per platform, named the way goreleaser's own
  archives are (`cipherhorizon-collector_<os>_<arch>[.exe]`), for a server that inventories more than one kind of
  machine.

`GET /api/v1/collector/binaries` lists what is present (platform, size, SHA-256), and `GET
/api/v1/collector/binaries/{name}` streams one by its exact listed filename. Neither builds, downloads or embeds
anything: with nothing on disk the list is simply empty, and the UI says so and falls back to the manual build
instructions. Nothing here executes a file — each one is only read and streamed as bytes, like the CBOM downloads
already on this server.

## What a release contains

On the GitHub Releases page (`https://github.com/<owner>/cipherhorizon/releases`):

| File | What |
|---|---|
| `cipherhorizon-collector_<version>_<os>_<arch>` (`.tar.gz`, `.zip` on Windows) | **the endpoint collector**, same six platforms (about 1.7 MB) |
| `cipherhorizon_<version>_linux_amd64.tar.gz`, `_linux_arm64.tar.gz` | the full product, Linux |
| `cipherhorizon_<version>_darwin_amd64.tar.gz`, `_darwin_arm64.tar.gz` | macOS (Intel, Apple silicon) |
| `cipherhorizon_<version>_windows_amd64.zip`, `_windows_arm64.zip` | Windows |
| `checksums.txt` | SHA-256 of every archive |
| `checksums.txt.sigstore.json` | keyless cosign signature (Sigstore bundle) over `checksums.txt` |
| `*.sbom.json` | software bill of materials (SPDX) for each archive |
| release notes | the version's section of `CHANGELOG.md` |

Each full-product archive holds `cipherhorizon[.exe]` (a collector archive holds `cipherhorizon-collector[.exe]`), `LICENSE`, `README.md`, `CHANGELOG.md`, `SECURITY.md` and
`docs/config.example.yaml`. The demo servers (`cmd/demo-targets`) are development tooling and are **not**
shipped.

Container image: `ghcr.io/<owner>/cipherhorizon:<version>` (multi-arch: `linux/amd64`, `linux/arm64`),
built from the `Dockerfile`: distroless `static` base, non-root (uid 65532), data in `/data`. Tags: exact
version always; `<major>.<minor>` and `latest` only for stable (non-0.x, non-pre-release) versions, so
**`latest` does not exist until 1.0**. Pin an exact version.

## Install

```sh
# binary (Linux/macOS): download, verify (below), extract, run
tar -xzf cipherhorizon_0.1.0_linux_amd64.tar.gz
./cipherhorizon serve            # http://127.0.0.1:8080, data in ./cipherhorizon.db

# container: listening beyond loopback requires a token
docker run -d --name cipherhorizon -p 8080:8080 \
  -e CIPHERHORIZON_TOKEN="$(openssl rand -hex 24)" \
  -v cipherhorizon-data:/data \
  ghcr.io/<owner>/cipherhorizon:0.1.0

# from source, with Go installed
go install github.com/<owner>/cipherhorizon/cmd/cipherhorizon@v0.1.0
```

Windows: unzip and run `cipherhorizon.exe serve`. Upgrade by replacing the binary; the database migrates
forward on start. **Back up the `.db` file before upgrading a 0.x release**: 0.x does not promise a downgrade
path.

## Verifying a download

Three independent checks, from cheapest to strongest. Replace `<owner>/cipherhorizon` and the version.

**1. Checksum** (catches corruption, not tampering on its own):
```sh
sha256sum --check --ignore-missing checksums.txt
```

**2. Signature on the checksums** (proves `checksums.txt` was produced by this repository's release
workflow; needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v2+):
```sh
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/<owner>/cipherhorizon/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
There is no public key to distribute or rotate: the signing identity is the workflow file at a release tag,
recorded in the Sigstore transparency log.

**3. Build provenance** (proves *which commit and workflow* built the file; needs the GitHub CLI):
```sh
gh attestation verify cipherhorizon_0.1.0_linux_amd64.tar.gz --repo <owner>/cipherhorizon
```

**Container image:**
```sh
cosign verify ghcr.io/<owner>/cipherhorizon:0.1.0 \
  --certificate-identity-regexp '^https://github.com/<owner>/cipherhorizon/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/<owner>/cipherhorizon:0.1.0 --repo <owner>/cipherhorizon
```

Air-gapped users: the archives are self-contained, so download on a connected machine, verify there, and move
the files across. The product itself makes no outbound requests except the scans you ask for.

## A CBOM and SBOM for CipherHorizon itself

Two different questions, two different documents:

- **SBOM** (what software is in the release): produced per archive by the release build (`*.sbom.json`).
- **CBOM** (what cryptography the release uses): CipherHorizon inventories other systems' cryptography, so its
  own should be inspectable too. The cryptography in the binary is Go's standard library (`crypto/tls`,
  `crypto/x509`) plus the project's own TLS wire code, used to *observe* servers, not to secure them. Planned:
  generate it in the release with `cipherhorizon run` against the release container image and attach it
  (tracked as an improvement, not part of 0.1.0).

## Channels: now and later

| Channel | Status | Notes |
|---|---|---|
| GitHub Releases (archives) | **0.1.0** | primary; everything else derives from it |
| GHCR container image | **0.1.0** | multi-arch, signed |
| `go install` from source | **0.1.0** | works because the module path is the repository path |
| Homebrew tap, Scoop bucket | later | GoReleaser can publish both once a `homebrew-tap` / `scoop-bucket` repo exists |
| `.deb` / `.rpm`, systemd unit | later | GoReleaser `nfpms`; needs a hardened unit and a decision on the default token/config location |
| winget, Chocolatey | later | after 1.0; both need a stable, non-pre-release version |
| Helm chart / Kubernetes manifests | later | when there is a multi-user story (see the product roadmap) |
| Docker Hub mirror | not planned | GHCR is enough; avoids a second set of credentials |

## Runtime footprint and operations notes

- Listens on `127.0.0.1:8080` by default; **refuses to bind elsewhere without a token**. Put a TLS-terminating
  reverse proxy in front if the UI is shared.
- State is one SQLite file (plus `-wal`/`-shm`): back it up with the process stopped or with `sqlite3 .backup`.
- No telemetry, no update check, no external requests at runtime. Version awareness is by watching the
  repository's Releases (Atom feed: `/releases.atom`).
- Resource use is small (a few scans in flight); the limit is how many concurrent connections your network and
  the targets' rate limits tolerate: `--max-concurrent-scans`, `--concurrency`.
