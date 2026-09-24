# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project intends to
follow [Semantic Versioning](https://semver.org/). Until 1.0 (`0.x`) the interfaces (CLI flags, the JSON API,
the CBOM/report/eval schema versions, the database) can change in a minor release; see
[docs/engineering/RELEASING.md](docs/engineering/RELEASING.md#versioning-policy). The first tagged release is
`0.1.0`, a pre-release. Everything before it is under `Unreleased` until `scripts/prepare-release.sh` cuts it.

## [Unreleased]

## [0.1.0] - 2026-09-24

### Added

- Host inventory: plugin registry and collector interface, an `apt` collector, a CycloneDX 1.6 CBOM builder
  with closed-vocabulary enforcement, cited post-quantum algorithm verdicts (`internal/pqc`), a one-shot CLI
  (`cipherhorizon run`).
- Active TLS/SSL scanner (`cipherhorizon tls scan`): an own TLS/SSLv2 wire-protocol implementation
  (`internal/tlsprobe/wire`), so it can probe what a linked TLS library cannot (SSLv2/3, export/NULL/anonymous
  suites, arbitrary key-exchange groups); protocol version detection, full cipher-suite and group enumeration
  including post-quantum hybrids (`X25519MLKEM768` and others), certificate retrieval and trust/name checks,
  IANA registries generated from the official CSVs.
- Evaluation (`internal/eval`): cited findings, a PQC readiness level (L0-L4) with harvest-now-decrypt-later
  exposure, a TLS hygiene score (0-100, five bands) derived only from the findings on a result, scan-to-scan
  diff. Both scales are this project's own and share no terminology or tables with another scanner's rating.
- **CBOM export for TLS endpoints** (`cipherhorizon tls scan --cbom`): turns an active scan into a CycloneDX
  1.6 CBOM (protocols, cipher suites, key-exchange groups including hybrid post-quantum combiners,
  certificates), PQC-annotated the same way a host inventory's CBOM is.
- Web server and UI (`cipherhorizon serve`): a JSON API, a scan runner and scheduler, SQLite storage,
  loopback-by-default with token auth and CSRF/SSRF protections, and a dependency-free web UI (dashboard,
  endpoints, scans, hosts, about) embedded in the binary.
- `cmd/demo-targets`: development-only servers of known TLS posture, for trying the product and for QA without
  scanning a third party.
- A browser end-to-end test (`testing/e2e/journey.mjs`) and a live security check script
  (`testing/e2e/security.sh`), both run in CI.

- Release engineering: tag-triggered release workflow (GoReleaser archives for Linux/macOS/Windows on
  amd64/arm64, SHA-256 checksums, SBOMs, keyless cosign signature, build-provenance attestation, multi-arch
  distroless container image on GHCR), CI expanded (Windows/macOS tests, govulncheck, release dry run), CodeQL,
  dependency review, Dependabot, `Makefile`, `cipherhorizon version` reporting commit and build date, and the
  branching/release/distribution documentation under `docs/engineering`.
- UI polish: a restrained motion system (one-shot page and tab entrance, chart draw-in, count-up figures,
  animated dialogs and toasts, live-state indicators) that honours `prefers-reduced-motion` and never replays on
  the timed refreshes, a copy-to-clipboard control on certificate serials and fingerprints, and the running
  version in the sidebar.

- Endpoint CBOM model, reworked after review (see `docs/cbom-model.md`): bulk ciphers are key-size-and-mode
  variants with NIST OIDs (`AES-128-GCM`, `AES-256-CBC`, ...) instead of one `AES`; a certificate's
  `subjectPublicKeyRef` now points at a `related-crypto-material` public key with its size and algorithm
  (`RSA-2048`, `ECDSA-P256`) rather than at an algorithm; the endpoint depends on its protocols and certificates;
  certificates carry their chain role; the negotiated flag now covers the negotiated suite's cipher, key exchange
  and authentication; and the document states what its edges mean.

- Host discovery rebuilt as an **evidence pipeline** (`docs/host-discovery-program.md`, ADR-0001 to ADR-0010):
  sensors observe and never infer; capability is applied afterwards from cited knowledge; no claim is stronger than
  the weakest evidence it rests on; the document states its coverage, blind spots and privilege. `cipherhorizon run`
  now also works on **Windows** (`pe-files` sensor: loose crypto libraries such as a bundled OpenSSL, read from
  their version resource by a hand-written, fuzzed PE reader; no key or credential file is ever opened), warns when
  it runs without Administrator/root (results may be incomplete), and has `--redact-host`. Debian/Ubuntu output is
  unchanged (proven against the frozen pre-refactor output).
- `docs/decisions` (architecture decision records), `testing/hostdiscovery` (ground-truth scripts) and
  `artifacts/agent-*`, `gate-decision-level-1.md` (the research, review and test record).

- **`cipherhorizon-collector`**: a separate ~4 MB program for endpoints (`run`, `plugins`, `version` only) that links no
  web server, database, TLS scanner or HTTP/TLS client, enforced by a test (ADR-0011). Published for the same six
  platforms next to the full product. The TLS CBOM builder moved to `internal/tlscbom` and the UUID library was
  replaced by `crypto/rand`, which removed the scanner and the network package from the collector's dependency set.

- **A guided first run.** The empty dashboard now offers two clear ways to begin (check a server's TLS, inventory
  a machine); the Hosts page teaches the three-step collector loop with copyable Linux and Windows commands and an
  upload command for automation; the dashboard states one **next step** chosen from the data; the servers' and the
  collector's command-line output ends by saying what to do next.
- **Inventory coverage on the host page.** The privilege tier, operating system, per-sensor result, unreadable
  locations and blind spots the collector records are now shown (and on the Hosts list as *Full access* / *Limited
  access* / *Not recorded*), with a plain route to re-run with full rights. A CBOM that records none of this is
  shown as *Not recorded*, never as complete.
- A design refinement in the spirit of calm, clear interfaces: softer surfaces and shadows, larger radii, quieter
  navigation, six KPI cards as three by two (two per row on a phone), disclosure for long rationale, and
  jargon explained where it first appears. Tokens and new components only; the strict CSP and every route are
  unchanged, and `#/endpoints` now also opens the endpoints page.
- The audit record: `docs/audit` (security audit, usability audit, gap analysis, UI direction, PM decision,
  QA report, release gate).

### Security

- The SQLite database (and its `-wal`/`-shm` files) is created owner-only (`0600`) and an existing one is
  tightened on start; the collector's CBOM file is written `0600` (POSIX).
- Access tokens shorter than 16 characters are refused at start; failed authentication is logged (method, path,
  remote address, never the value) and delayed 250 ms.
- The SSRF guard also refuses `0.0.0.0/8` and NAT64 (`64:ff9b::/96`) spellings of blocked IPv4 addresses.
- Host names on upload must be printable UTF-8 without control or bidirectional-override characters.
- `Permissions-Policy` is sent on every response; workflow checkouts no longer persist the job token.

### Changed

- Project renamed from the working name `cbom-scan` to **CipherHorizon**, to avoid any confusion with a
  specific document type ("a CBOM") and to give the whole platform (inventory, TLS scanning, readiness,
  posture) one name.
- The TLS rating was redesigned from an SSL-Labs-style A-F letter grade to **TLS hygiene**, a 0-100 score
  derived only from a result's own cited findings, with its own bands (Strong/Sound/Fair/Weak/Broken) and no
  shared terminology or scoring tables with any other scanner's rating.

### Known limitations

- **Not yet validated:** the host collector has run on one Windows machine as a standard user only; it has not run
  on a live Linux host or with Administrator/root rights (fixture and shim tests only). macOS is not supported.
  The release workflows, container image and signing have never executed (nothing is pushed); the first tag is a
  pre-release for that reason. The module owner and the security contact are placeholders until a repository exists.
- Worst-case disk use per host is 50 snapshots of up to 32 MiB; there is no per-instance storage budget yet.

See [docs/product/RELEASE-REPORT-001.md](docs/product/RELEASE-REPORT-001.md) for the full list, including
deviations from the original plan and what has and hasn't been tested. In short: single shared bearer token
(no multi-user auth), SQLite only, no OpenAPI spec yet, `tls scan`'s text/JSON output doesn't yet carry the
evaluation (only `--cbom` and the web UI/API do), and testing so far has used hermetic test servers rather than
real-world TLS implementations.

[Unreleased]: https://github.com/OWNER-PLACEHOLDER/cipherhorizon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER-PLACEHOLDER/cipherhorizon/releases/tag/v0.1.0
