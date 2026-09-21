# cbom-scan

> **Working name.** `cbom-scan` and the module path `github.com/example/cbom-scan` are placeholders.

A vendor-neutral, open-source tool for **cryptographic posture**: one place to see what cryptography your
endpoints and hosts use, how well it is configured, and how exposed it is to a future quantum computer.

- **Web UI**: add TLS endpoints, scan them, watch progress, read each endpoint's **PQC readiness** (L0-L4) and
  **TLS hygiene** score, and see how it changed since the last scan.
- **Active TLS/SSL scanner**: protocol versions (SSLv2 to TLS 1.3), every cipher suite, key-exchange groups
  including post-quantum hybrids such as `X25519MLKEM768`, certificates, with a cited finding for every problem.
- **CBOM inventory**: what cryptography is installed on a host, as a [CycloneDX](https://cyclonedx.org/capabilities/cbom/)
  1.6 **CBOM** with evidence-based post-quantum classifications. Upload one to the UI to see its verdicts.

**Status: pre-alpha (release R1 of the workbench).** See the [release report](docs/product/RELEASE-REPORT-001.md)
for what is in, what is not, and what was found in testing.

## Tech stack

| Layer | What is used |
|---|---|
| Language and build | **Go** (module targets Go 1.25). One statically linked binary, `CGO_ENABLED=0`, no runtime to install. |
| Web server and API | Go standard library `net/http` (method-aware `ServeMux`); a JSON API under `/api/v1`. |
| Web UI | Plain **HTML, CSS and JavaScript ES modules**, hand-drawn SVG charts. No framework, no npm, no build step. The files in `web/static` are compiled into the binary with `go:embed`, so the UI works offline. |
| Storage | **SQLite** through the pure-Go driver `modernc.org/sqlite` (no C compiler needed), WAL mode, embedded forward-only migrations. The whole state is one file. |
| TLS scanning | An **own TLS wire-protocol implementation** (`internal/tlsprobe/wire`) so it can offer what Go's `crypto/tls` cannot (SSLv2/3, export and anonymous suites, arbitrary groups). Go's `crypto/tls` is used only to fetch certificates and to show what a current client negotiates. IANA cipher-suite and group registries are generated from the registry CSVs. |
| CBOM | `github.com/CycloneDX/cyclonedx-go` (CycloneDX 1.6), `github.com/package-url/packageurl-go`; output validated against the vendored CycloneDX JSON schema in tests (`santhosh-tekuri/jsonschema`). |
| Config | YAML (`go.yaml.in/yaml/v3`) for the host inventory command. |
| Tests and tooling | `go test` (unit, integration against in-process servers, fuzzing), `golangci-lint`, and a browser end-to-end script (Node 22+, no dependencies, drives Chrome/Edge over the DevTools protocol). GitHub Actions for CI. |

Security choices worth knowing: the server binds to loopback and needs an access token for anything else; scan
targets are checked in the dialer against link-local, cloud-metadata and (by default) loopback addresses; the UI
sends a strict Content-Security-Policy and renders everything it received from a scanned server as text.

## How to start

### What you need

- **Go 1.25 or newer** to build. Nothing else: no C compiler, no Node, no database server.
- A modern browser to use the UI. (Node 22+ is needed only to run the browser end-to-end test.)

### Build and run

```sh
git clone <this repository> && cd <it>
go build -o cbom-scan ./cmd/cbom-scan       # on Windows: go build -o cbom-scan.exe ./cmd/cbom-scan
./cbom-scan serve                            # on Windows: .\cbom-scan.exe serve
```

Then open **http://127.0.0.1:8080**. Stop it with Ctrl+C (running scans are cancelled cleanly).
The data is kept in `./cbom-scan.db` in the directory you started it from (SQLite also creates `-wal` and `-shm`
files next to it). Delete those to start over.

### First use

1. Choose **Add endpoints**. Add one `host[:port]` (443 by default), or paste a list, one per line. A pasted URL is
   reduced to its host and port, and one bad line never blocks the others.
2. Choose **Scan all** (or **Scan** on a row). Open an endpoint to watch the stage, percentage, connection count and
   log, and **Cancel** if you need to.
3. Read the result: **PQC readiness**, **TLS hygiene**, the TLS details, and the findings with their sources.
4. Scan again later (or set an automatic rescan) and open the **History** tab to compare two scans.
5. **Hosts** takes a CBOM made by `cbom-scan run` and shows a quantum verdict for each algorithm in it.

Scan only systems you own or are authorised to test: a scan makes a few dozen to a few hundred short TLS
handshakes per endpoint.

### Try it without touching anyone else's systems

```sh
go run ./cmd/demo-targets                    # servers of known posture on 127.0.0.1:9440-9447; prints what to expect
./cbom-scan serve --allow-loopback           # scans of loopback addresses are refused unless you say so
```

Add the addresses `demo-targets` prints. They cover a hybrid post-quantum server (L3), a classical TLS 1.3 server
(L1), a TLS 1.2-only server (L0), a deliberately terrible SSLv3 server, a closed port, a slow server (to watch
progress and cancel), and a server you can switch between classical and hybrid with
`curl -X POST http://127.0.0.1:9447/pq/on` to produce a real history change. The demo servers use self-signed
certificates, so their TLS hygiene scores include the untrusted-certificate finding.

### Options for `serve`

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `127.0.0.1:8080` | Address to listen on. Any address other than loopback needs a token. |
| `--db` | `cbom-scan.db` | SQLite file (created if missing). |
| `--token`, env `CBOM_SCAN_TOKEN` | none | Require `Authorization: Bearer <token>` on every API call; the UI asks for it once per browser tab. |
| `--allow-loopback` | off | Let scans target loopback addresses (for testing). |
| `--allowed-host` | none | Extra `Host` header accepted when no token is set (repeatable). |
| `--max-concurrent-scans` | 2 | Scans that may run at once. |
| `--concurrency` | 4 | Connections in flight to one endpoint at once. |
| `--timeout` | 8s | Per-connection timeout during a scan. |

To use it from other machines, set a token and put it behind a TLS-terminating reverse proxy; the server itself
speaks plain HTTP.

```sh
CBOM_SCAN_TOKEN='a-long-random-secret' ./cbom-scan serve --addr 0.0.0.0:8080
```

### Command line

```sh
./cbom-scan tls scan example.internal:443    # probe one endpoint, print the raw probe report (see docs/tls-scanning.md)
./cbom-scan run                              # inventory this host, CBOM JSON to stdout
./cbom-scan run --config config.yaml -o host.cbom.json
./cbom-scan plugins                          # list built-in collectors
./cbom-scan version
```

Example [`config.yaml`](docs/config.example.yaml) for `run`:

```yaml
output:
  path: host.cbom.json # empty = stdout
host:
  root: /              # use /host when running in a container with the host FS mounted
plugins:
  disabled: []
pqc:
  enabled: true
```

Exit codes: `0` success · `1` fatal error · `2` result produced, but a collector failed or a scan was incomplete.

## How to read the results

**PQC readiness** answers "would recorded traffic survive a future quantum computer?"

| Level | Meaning |
|---|---|
| **L0 Not ready** | No TLS 1.3, so no post-quantum key exchange is possible |
| **L1 Exposed** | TLS 1.3 available, no post-quantum key exchange offered |
| **L2 Hybrid available** | A hybrid group is accepted but a current client does not end up using it |
| **L3 Hybrid negotiated** | A current client negotiates a hybrid post-quantum key exchange |
| **L4 PQ-authenticated** | Post-quantum key exchange and a post-quantum certificate signature |
| **?** Undetermined | The scan could not establish it, so no level is given rather than a guess |

**TLS hygiene** answers "how well is this endpoint configured today?" It is a 0 to 100 score with a band:
**Strong** (90+), **Sound** (75+), **Fair** (55+), **Weak** (30+), **Broken** (below 30). It starts at 100 and takes
points off for each cited finding (critical 40, high 20, medium 10, low 4), and a critical or high finding caps the
score. Every point taken off is listed on the endpoint page with the finding it came from. Post-quantum findings
are not counted, so the two measures stay independent.

Both scales are this project's own and are not standards or another scanner's ratings. The facts they rest on cite
their sources (FIPS 203/204, RFC 9325, IANA registries, NIST IR 8547 draft, ...). The full rules are in
[docs/methodology.md](docs/methodology.md) and on the UI's *About* page.

## Project layout

| Path | What |
|---|---|
| `cmd/cbom-scan` | the program; `cmd/demo-targets` is a development-only set of demo servers |
| `internal/app` | command-line entry points (`run`, `tls scan`, `serve`) |
| `internal/server` | HTTP API, scan runner and scheduler, target safety checks |
| `internal/store` | SQLite storage, history, fleet summaries |
| `internal/eval` | findings, PQC readiness, TLS hygiene, scan-to-scan diff |
| `internal/tlsprobe` | the TLS scanner, its wire protocol code, registries, and test servers |
| `internal/collector`, `internal/plugins`, `internal/scan`, `internal/cbom`, `internal/pqc`, `internal/algo` | host inventory and CBOM |
| `web/static` | the UI (embedded into the binary) |
| `docs` | architecture, TLS scanning, methodology, plugin guide, product documents |
| `testing` | golden CBOMs, fixtures, schemas, and the browser end-to-end scripts |

## Design principles

1. **Push, not pull, for hosts.** The agent runs on the host; nothing logs in to your machines. (Active TLS
   scanning is the deliberate exception: it connects out to the endpoints you list.)
2. **Single static binary**, UI embedded, works air-gapped, no telemetry.
3. **Plugin-first.** Every collector implements one small interface; the core never contains collector logic.
4. **CycloneDX-native.** 1.6 baseline. Closed enumerations go through total lookup tables; unmappable values are
   *omitted*, never guessed.
5. **Complexity is opt-in.** No queues, no multi-region: SQLite and one process.
6. **Evidence-based.** Every verdict cites a standard or OID; every fact says whether it was observed, inferred,
   taken from a registry, or not measured. No citation, no verdict.
7. **Safe by default.** Loopback bind, token for anything else, SSRF guard on scan targets, strict CSP.

See [docs/architecture.md](docs/architecture.md), [docs/tls-scanning.md](docs/tls-scanning.md),
[docs/methodology.md](docs/methodology.md) and [docs/writing-a-plugin.md](docs/writing-a-plugin.md). The product
documents are in [docs/product](docs/product): PRD, engineering handoff, QA plan, QA report and release report.

## Testing

```sh
go test ./...                                  # unit, integration (real scanner vs in-process servers), UI asset checks
golangci-lint run ./...
go test ./internal/tlsprobe/wire -run '^$' -fuzz FuzzReadFlight -fuzztime 30s
node testing/e2e/journey.mjs                   # browser journey against a running server, see testing/README.md
```

`go test -race` needs a C compiler; CI runs it on Linux. The browser journey and the live security checks are
described in [testing/README.md](testing/README.md).

## Not in scope for R1

Alerts and webhooks, HTTP-layer checks (HSTS), STARTTLS, multi-user auth, an agent daemon that pushes to the
server, CBOM export for TLS endpoints, custom CA bundles, PDF reports, SSH probing. Source-code analysis belongs to
CBOMkit / sonar-cryptography and image scanning to Trivy.

## License

[Apache 2.0](LICENSE).
