# ENG-HANDOFF-001: Posture Workbench (R1)

Implements `PRD-001`. Read that first; acceptance criteria are referenced as AC-xx.y.

## Design decisions (and why)

| # | Decision | Reason |
|---|---|---|
| D1 | `cbom-scan serve`: one process = HTTP API + embedded UI + job runner + scheduler | Single static binary, air-gapped (PRD §9) |
| D2 | SQLite via pure-Go `modernc.org/sqlite` | `CGO_ENABLED=0` must keep working (`mattn/go-sqlite3` needs cgo) |
| D3 | UI: vanilla ES modules, hand-written SVG charts, **no build step**, `go:embed` | `go build` stays self-sufficient; no Node in CI; nothing to supply-chain. **Deviation** from the earlier Svelte plan; revisit if UI complexity outgrows it |
| D4 | UI builds DOM with `createElement`/`textContent` only, never `innerHTML` with data | AC-11.6: a hostile cert subject cannot execute |
| D5 | Evaluation is a pure function `eval.Evaluate(report, now)`; results are **stored** with the scan | History must show what we concluded *then*, even if rules later change |
| D6 | Rules live in Go with citations attached to the rule, and a test fails any rule without a citation | O2 |
| D7 | Job queue = `scans` table + in-process worker pool | No queue infrastructure (principle 5); replicas/Postgres are a later step |
| D8 | Progress = `stage`, `progress_pct`, `connections` on the scan row + an event log, polled by the UI | Robust, testable, no websockets |
| D9 | SSRF guard enforced in `net.Dialer.Control` on the actual remote address | Defeats DNS rebinding between check and connect |

## Components and interfaces

```
internal/eval      Evaluate(*tlsprobe.Report, time.Time) Evaluation ; Compare(a, b Evaluation+Report) Diff
internal/store     SQLite: assets, scans, events; migrations; retention; fleet aggregates
internal/server    HTTP handlers, middleware (host/origin/token/CSP), Runner (queue, workers, scheduler), Guard (SSRF)
web/               embedded static UI: index.html, app.js, api.js, charts.js, style.css
internal/app       `serve` subcommand
cmd/demo-targets   dev-only: local TLS servers of different postures (never shipped) for QA and demos
tlsprobe           + Options.Tick(connections) for live progress
```

### eval (types are the API contract; see `internal/eval`)
`Evaluation{Version, Findings[], Readiness, Hygiene, Counts}`. `Finding{ID, Title, Severity, Category, Detail,
Evidence(observed|inferred|registry|not-measured), Citations[], Remediation}`. `Readiness{Level 0-4, Label,
HNDLExposed, KeyEstablishment, Authentication, Symmetric (each Dimension{Status, Detail, Evidence}), NextSteps[],
Citations[]}`. `Hygiene{Score, Band, Deductions[], Ceiling, NotMeasured[], Methodology}` (derived from the findings; see `docs/methodology.md`).

### REST API (JSON, `/api/v1`)
```
GET  /about                      version, registry date, limits, policy flags
GET  /summary                    fleet KPIs, distributions, needs-attention, recent scans, trend
GET  /assets            POST /assets            POST /assets/bulk {text}
GET|PATCH|DELETE /assets/{id}   POST /assets/{id}/scan          GET /assets/{id}/history
GET  /assets/{id}/diff?from=&to=
POST /scans {assetIds|all}      GET /scans?assetId=&status=      GET /scans/{id}   POST /scans/{id}/cancel
GET  /scans/{id}/report | /evaluation   (?download=1)
GET  /export/assets.csv
POST /hosts/ingest              (P1)
```
Errors: `{ "error": "<plain message>" }` with 4xx/5xx. All mutations require `Content-Type: application/json`.

### Data model
`assets(id, kind, name, host, port, tags, notes, interval_seconds, next_scan_at, created_at, updated_at,
UNIQUE(kind,host,port))`; `scans(id, asset_id→assets ON DELETE CASCADE, status, trigger, stage, progress_pct,
connections, queued_at, started_at, finished_at, error, report_json, eval_json, band, score, readiness_level,
hndl_exposed, crit, high, cert_not_after, incomplete)`; `scan_events(scan_id, at, message)`;
`schema_migrations(version)`. WAL mode, foreign keys on.

### Security controls (AC-11.x)
Loopback default bind; token required for non-loopback (`--token` / `CBOM_SCAN_TOKEN`, constant-time compare);
Host allowlist (`127.0.0.1`, `localhost`, `[::1]`, plus `--allowed-host`); Origin must equal Host on mutations;
CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, `nosniff`, `no-referrer`; SSRF guard blocks
link-local (incl. 169.254.169.254), multicast, unspecified, and loopback unless `--allow-loopback`.

## Build order (each step ends green: `go vet`, tests, lint)

1. `tlsprobe`: `Options.Tick`. 2. `eval` (rules, readiness, hygiene, diff) + tests incl. "every finding cited".
3. `store` + tests. 4. `server`: guard, middleware, API, runner/scheduler + httptest integration tests
against hermetic TLS servers. 5. `web/` UI. 6. `serve` subcommand. 7. `cmd/demo-targets`.
8. P1: scheduling, CSV/JSON export, host ingest. 9. Hand back to QA.

## Out of scope for dev in R1
See PRD §4 P2. If a requirement conflicts with a PRD acceptance criterion, the PRD wins; record any deviation
in the release report.

## Delivery status (added at release)

Built as specified, with the deviations listed in [RELEASE-REPORT-001](RELEASE-REPORT-001.md) section 3 (notably:
no-build vanilla UI instead of Svelte, SQLite only, no OpenAPI file, polling rather than SSE, OS trust store only).
Two additions beyond the handoff: `cmd/demo-targets` (known-posture servers for QA and demos) and
`testing/e2e` (browser journey and live security script, also run in CI). Verification is in
[QA-REPORT-001](QA-REPORT-001.md); how to read the results is in [../methodology.md](../methodology.md).
