# RELEASE-REPORT-001: Posture Workbench (R1), `cipherhorizon 0.1.0`

Prepared by the product/engineering roles for the project owner. Read this first; the detail is in
[PRD-001](PRD-001-posture-workbench.md), [ENG-HANDOFF-001](ENG-HANDOFF-001.md), [QA-PLAN-001](QA-PLAN-001.md) and
[QA-REPORT-001](QA-REPORT-001.md).

## 1. What you asked for, and what exists now

> "There should be a UI and proper workflow like a product, where they can add assets, scan, then see progress,
> see historical data. PQC readiness is an important part."

| You asked for | Where it is in the product |
|---|---|
| Add assets | **Endpoints**: add one, or paste a list (one bad line never blocks the rest); edit, tag, delete with confirmation; CSV export |
| Scan | Scan one, scan selected, scan all; optional automatic rescans (hourly to weekly); a queue with limited concurrency |
| See progress | Live panel: stage (1 of 5), percentage, connection count, event log, **Cancel** |
| Historical data | Every scan kept (200 per endpoint); trend chart of readiness; **compare any two scans** ("3 better, 0 worse"); open any past scan read-only; fleet trend on the dashboard |
| PQC readiness | L0 to L4 per endpoint with the harvest-now-decrypt-later flag, three cited dimensions, next steps; distribution across the fleet |
| TLS/SSL evaluation | Protocols, every cipher suite per version, key-exchange groups incl. `X25519MLKEM768`, certificates, features, findings with citations, a **TLS hygiene** score (0 to 100, bands Strong to Broken) in which every point taken off is listed with its finding, and what was *not* measured |
| CBOM / inventory | Upload a CBOM from `cipherhorizon run`; per-algorithm quantum verdicts with sources and the packages that can provide them |
| "Collect all of it" | `artifacts/` (section 6) |

Run it: `cipherhorizon serve`, open `http://127.0.0.1:8080`. One static binary, one SQLite file, works offline.

## 2. Verdict

**Ready for a pre-alpha release to early users.** All P0 and P1 acceptance criteria pass except one that is partly
verified (the "incomplete scan" banner). No critical or high defect is open. Evidence: 222 Go test results (0
failing), lint and vet clean, three fuzz targets, 44/44 browser checks in real Edge with 32 screenshots, 25/25 live
security checks. See QA-REPORT-001 sections 1 and 4 for exactly what that does and does not cover.

**Not ready** for: exposure beyond a trusted network without a reverse proxy (single shared token, no roles, no
audit log), scanning at fleet scale on real networks (untested), or any claim that its scores match another scanner's ratings (they are this project's own).

## 3. Deviations from the approved plan and the PRD

These are decisions made while building, listed so none is a surprise.

| # | Planned | Delivered | Why, and the cost |
|---|---|---|---|
| 1 | UI in Svelte + Vite + ECharts (plan D8, the default) | Plain ES modules, hand-written SVG charts, **no build step or npm dependency**, embedded with `go:embed` | Keeps "one binary, no toolchain, auditable" and an air-gapped build. Cost: we wrote a small router, DOM helper and charts ourselves. Revisit if the UI grows much beyond ten views. |
| 2 | SQLite or Postgres (plan D5) | **SQLite only** (pure Go, WAL) | One process and one file is the R1 promise. Multiple replicas need Postgres; not started. |
| 3 | OpenAPI as the API contract (plan D4) | JSON API documented by tests and code only; **no OpenAPI file** | Deferred. Do it before anyone builds against the API. |
| 4 | Live progress (implicitly push) | **Polling** every 0.7 to 1.2 s | Simple and adequate for a single-user tool; SSE is a small later change. |
| 5 | Hashed tokens with roles, OIDC, audit log (plan section 6) | **One shared bearer token**, or none on loopback | Enough for a single-team tool behind a proxy; not multi-user. |
| 6 | Trust store: OS store plus an optional CA bundle (plan decision 4) | **OS store only** | Endpoints using a private CA carry the untrusted-certificate finding, and so a Fair band, until this is added. This is the most likely thing users hit first. |
| 7a | `tls scan` producing an evaluated report (plan M2) | **Not built.** The CLI's text/JSON output is still the raw probe report; TLS hygiene, readiness and findings are visible in the UI/API only, not via the CLI. | Deferred; `tls scan --evaluate` remains a reasonable next step. |
| 7b | CBOM `protocol`/`certificate` assets for TLS endpoints | **Built, after this report's first version.** `tls scan --cbom HOST:PORT` (one target) exports a CycloneDX 1.6 CBOM: one `protocol` component per supported version with its cipher suites, one `algorithm` component per cipher/group/hybrid they reference (including the three RFC 10024 hybrids, `combiner`-primitive, cited), one `certificate` component per certificate in every chain. PQC-annotated by the same `internal/pqc` pass a host inventory's CBOM gets, so it can also be uploaded through the UI's Hosts page. Covered by unit tests (`internal/cbom/tlsbuild_test.go`) and a CLI integration test against a real hermetic server (`internal/app/tls_test.go`). Not built: `CryptoProtocolType` values beyond `tls` (ssh/ipsec/... probing does not exist yet to need them); classical named curves beyond x25519 (no catalogue entry for secp256r1/384r1/521r1 yet, so they are named but not referenced); multi-target CBOM in one document (the command takes one target, matching one document per subject). |
| 8 | Agent daemon, `/metrics`, webhooks, listener discovery, further collectors (plan M3, M4, M6) | Not started | Outside the PRD's R1 scope. |
| 9 | Notice "before the first scan" (PRD AC-11.7) | Shown when adding endpoints, on About, and in the CLI/server banners, not on the Scan button | Judged sufficient; recorded as O5. |
| 10 | Hermetic Docker matrix against nginx/Apache/OpenSSL (plan section 8) | Hermetic in-process servers and a scripted SSLv3 server only | Real server software has **not** been scanned. |
| 11 | Letter grade A-F modelled on a third-party rating guide (PRD AC-05.3 as first written) | **Replaced by the product's own TLS hygiene score** (0 to 100, five named bands, derived from cited findings) | Owner request after first QA: avoid another scanner's terminology and tables. Databases from the earlier build upgrade automatically but show no rating on old scans until they are scanned again. |

## 4. Known limits (read before trusting a result)

- **The TLS hygiene score is the project's own**, worked out only from the cited findings, with weights chosen for
  this project. It uses its own bands (Strong, Sound, Fair, Weak, Broken) and shares no terminology or tables with
  any other scanner. It is a summary; the findings are the primary output.
- **Readiness levels are the project's own scale**; each underlying fact is cited.
- **Findings are inferred from what a server offers**, not from exploit attempts. A missing finding for
  Heartbleed-class bugs means "not tested", and the UI says so.
- **Only direct TLS** (no STARTTLS). One address per name is probed (the others are listed).
- **The demo endpoints score Fair** (56 to 60) because they use self-signed, short-lived certificates. That is correct behaviour.
- **Dashboard days are UTC.**
- **Scanning is active traffic.** A scan makes tens to hundreds of handshakes per endpoint. The UI, CLI and server
  all say to scan only what you are authorised to test, and the server refuses loopback, link-local, cloud-metadata
  and unspecified addresses (loopback only with `--allow-loopback`).

## 5. Recommended next steps (ordered)

1. **`tls scan --evaluate`**: print the TLS hygiene score, readiness level and findings from the CLI, not only
   the UI/API (CBOM export for TLS endpoints, the other half of this item, is now built — see deviation 7b).
2. **Private-CA support**: a `--ca-bundle` option so internal endpoints can be rated on their merits.
3. **Prove it on real servers**: a Docker matrix (nginx, Apache, HAProxy, OpenSSL 3.5 with hybrid groups, a
   legacy OpenSSL) cross-checked against another scanner. Everything so far used our own hermetic servers.
4. **OpenAPI spec** and a documented stability promise for the JSON report and API.
5. **STARTTLS** (SMTP/IMAP first) and **HTTP-layer checks (HSTS)**.
6. **Alerts**: notify when readiness regresses or a certificate is close to expiry.
7. **Agent + listener discovery** so hosts scan their own listeners and push results (restores "push, not pull").
8. Multi-user auth (roles, hashed tokens, audit log) and Postgres for shared deployments.
9. Cut a real release: name, module path and licence holder are still placeholders (below).

## 6. Decisions still open for you

- **Project name and module path** (`cipherhorizon`, `github.com/example/cipherhorizon` are placeholders).
- **Licence holder/notice** (Apache-2.0 is in place).
- **Git history**: the repository has no commits yet; nothing has been committed for you.
- **Push the CI changes**: the new `e2e` job and the extra build targets have not run anywhere.

## 7. Artifacts

Everything is in `artifacts/` (index and checksums in `artifacts/MANIFEST.md`):

| Folder | Contents |
|---|---|
| `docs/` | PRD, engineering handoff, QA plan, **QA report**, this report, methodology |
| `screenshots/` | 32 screenshots of the shipped UI from the automated journey, plus `results.json` (every check with its result) |
| `logs/` | full `go test -v`, summary, 8x repeat, vet, lint, fuzz, e2e journey, live security run, manual and performance checks, demo-target output, toolchain versions |
| `samples/` | real output: reports and evaluations for the four demo postures, history and diff for the PQ toggle, fleet summary, CSV export, host list, a sample host CBOM |
| `binaries/` | `cipherhorizon 0.1.0` for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64, windows/amd64; `demo-targets` for linux/amd64 and windows/amd64 |

Reproduce the browser evidence: [testing/README.md](../../testing/README.md).

## 8. Code delivered in this release

| Area | Where |
|---|---|
| Server, API, runner, SSRF guard, ingest | `internal/server` |
| Storage (SQLite, migrations, history, fleet) | `internal/store` |
| Evaluation: rules, readiness, TLS hygiene, diff | `internal/eval` |
| TLS probe engine (own wire stack), registries, test servers | `internal/tlsprobe` |
| Web UI (embedded) | `web/static`, `web/embed.go` |
| `serve` command | `internal/app/serve.go` |
| Demo targets (development only) | `cmd/demo-targets` |
| Browser journey and security script | `testing/e2e` |
