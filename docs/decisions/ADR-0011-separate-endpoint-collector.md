# ADR-0011 — A separate, small collector program for endpoints

- **Status:** Accepted (user challenge, 2026-09-24: "why ship all this code when it's not needed for collection?")
- **Date:** 2026-09-24
- **Related:** ADR-0004, ADR-0005, ADR-0007

## Context

The project was built as one static binary, `cipherhorizon`, containing the web server, the SQLite store, the active
TLS scanner and the host collector. That was chosen for distribution convenience. But the host collector is the one
part meant to run on *other people's machines*, and the product boundary says host inventory (`run`) and network
scanning (`tls scan`) are different systems. Shipping the server, database driver and scanner to every endpoint:

- enlarges what an endpoint owner must audit and trust (13 MB of code, most of it irrelevant to a read-only inventory);
- enlarges the attack surface and the malware-scanner footprint (a network scanner and an HTTP server look alarming
  on a workstation);
- contradicts the collector's own stated properties: read-only, no subprocess, no network.

## Options considered

1. **Keep one binary** and document that `run` ignores the rest.
2. **Build tags** to strip the server/scanner from a "collector build" of the same `main`.
3. **A second program**, `cmd/cipherhorizon-collector`, whose dependencies are only the host-discovery packages;
   the full binary keeps `run` by calling the same code.

## Evidence

- `go list -deps` of the host-discovery packages showed exactly one leak: `internal/cbom` imported the TLS scanner
  (its `FromTLSReport` builder), which dragged `tlsprobe` into anything that touched a CBOM. A second leak: the
  UUID library used for the CBOM serial number links the `net` package (to read MAC addresses).
- After separating them, the collector is **4.0-4.3 MB** stripped versus **13.3-13.5 MB** for the full product, and
  links no `net/http`, `crypto/tls`, `database/sql` or SQLite (and, off Windows, not even `net`).
- Option 2 keeps one `main` whose *default* build is still the large one; a forgotten tag would ship it.

## Decision

Option 3.

- `cmd/cipherhorizon-collector` (`run`, `plugins`, `version`, `help` only) uses `internal/hostcmd`; the full binary's
  `run` and `plugins` call the same package, so behaviour is identical.
- The TLS CBOM builder moved to `internal/tlscbom`; `internal/cbom` no longer imports the scanner.
- The UUID dependency was replaced by a small `crypto/rand` version-4 generator (one dependency fewer).
- **`internal/archtest` enforces it:** the linked dependency set of the collector, on Linux and Windows, must not
  contain `net/http`, `crypto/tls`, `database/sql`, `modernc.org/*`, `golang.org/x/net`, or the server, store,
  scanner, TLS-CBOM builder, evaluation or app packages (and `net` itself off Windows). A planted import was detected
  (negative control).
- Releases publish both: `cipherhorizon-collector_<version>_<os>_<arch>` (about 1.7 MB archives) and the full
  `cipherhorizon_...` archives.

## Why

The endpoint should carry the least code that does the job, and the guarantee should be a failing test, not a
promise.

## Trade-offs

Two programs to build, sign and document; the full binary still contains the collector (so `cipherhorizon run` keeps
working for people who already have it). On Windows, `net` is linked because the official `x/sys/windows` package
declares socket types; nothing calls it.

## Consequences

- **What to deploy to a machine being inventoried is `cipherhorizon-collector` and nothing else.** The server, UI
  and scanner belong on the machine that receives and views results.
- Signing (ADR-0007) now applies to a 4 MB program that is far easier to review than the 13 MB one.
- Any new dependency of a sensor is visible in the collector's linked set and must pass the same test.
