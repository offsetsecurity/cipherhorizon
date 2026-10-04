# ENG-HANDOFF-004: Focused flows — build plan

Implements [PRD-005](PRD-005-product-focus-and-flows.md) per [UX-DESIGN-003](UX-DESIGN-003-focused-flows.md). Tests:
[QA-PLAN-005](QA-PLAN-005-focused-flows.md). Status in the [RTM](../program/RTM.md).

## 1. Design decisions

| # | Decision | Why |
|---|---|---|
| E-1 | **Restructure the UI, not the model.** Existing view modules are reused inside new pages (Reports, Inventory, Systems) through an `embedded` flag that drops their own page header. | Least risk; every existing capability stays reachable and tested. |
| E-2 | **Routes**: `#/` Scan, `#/reports`, `#/reports/N`, `#/inventory`, `#/systems`, `#/systems/N`; detail pages `#/hosts/N`, `#/certificates/FP` remain. Old routes **redirect** with `location.replace` (no history entry). | REQ-NAV-2; old links and bookmarks keep working. |
| E-3 | **Quick scan is client-side composition**: create the endpoint (`POST /api/v1/assets`); on 409 find it in `GET /api/v1/assets` by address; then `POST /api/v1/assets/{id}/scan`; then go to `#/reports/{id}`. | No new route for something the API already does. |
| E-4 | **New read API for the inventory**: `GET /api/v1/inventory?kind=algorithm|protocol|suite|group|software` (rows with quantum status and places) and `GET /api/v1/inventory/summary`. Built on the estate graph (current sources only). | REQ-INV-1..4; the graph already holds entities, observations and sources. |
| E-5 | **Whole-inventory CBOM**: `GET /api/v1/inventory/cbom?spec=1.7|1.6&imported=0|1`. The latest completed scan of every endpoint (built as today's per-scan CBOM) and the latest snapshot of every machine (stored CBOM) are merged: components by `bom-ref` (first wins), dependencies unioned, each component gains `cipherhorizon:seen-in` (source names, at most 20 then "and N more"). Imported CBOMs are added only with `imported=1`, their refs prefixed `import-<id>/`. PQC annotation runs on the merged document. Capped at 20,000 components (413 above). | REQ-INV-5/7; one CycloneDX document anyone can load. |
| E-6 | **Quantum status** for inventory rows: algorithms via `pqc.ClassOf(name, oid)`; groups: `pq` attribute → quantum-safe (hybrid), else `pqc.ClassOf`; protocols, suites, software: *not applicable*; no rule: *unknown*. | Same cited classification the CBOM uses (REQ-INV-3). |
| E-7 | **Report sections become `<details>`** with the one-line verdict in the `<summary>`; open when the status is problem/attention. Findings use a nested `<details>` "Why and sources". *How we tested*, reference data and the hygiene breakdown move to one "About this report" `<details>`. | Native disclosure: keyboard and screen-reader friendly, no CSP change, closed content is not rendered (measurable). |
| E-8 | **Vocabulary guard**: a Go test in `web/` reads the primary-surface files (`index.html`, `views/scan.js`, `views/reports.js`, `views/inventory.js`, `views/systems.js`) and fails on the forbidden words of REQ-LANG-1 inside string literals. | REQ-LANG-2. |

## 2. API additions

| Route | Returns |
|---|---|
| `GET /api/v1/inventory?kind=K&vulnerable=1&source=scanner|collector|imported&q=TEXT` | `{rows:[{key, kind, name, attrs, quantum:{status, basis}, places:[{systemId, systemName, assetId, assetKind, assetName, sourceClass}], systems, placesCount, sources:[...], lastSeen}]}` (≤ 5,000 rows) |
| `GET /api/v1/inventory/summary` | `{algorithms, quantumVulnerable, quantumSafe, certificates, certificatesExpiring30, protocols, suites, groups, software, sources}` |
| `GET /api/v1/inventory/cbom?spec=1.7&imported=0` | CycloneDX JSON, attachment when `download=1` |

All through the guarded mux; documented in `openapi.json`.

## 3. Work packages

| WP | Scope | Requirements |
|---|---|---|
| F1 | Shell: menu, routes, redirects, active state, Systems badge, product sentence | NAV-1..4, LANG-3 |
| F2 | Scan home: input, inline errors, quick scan, recent reports, inventory card, secondary links | HOME-1..5, UNF-1 |
| F3 | Reports: fleet summary + tabs (Endpoints, Findings, Activity) embedding existing views; report URL, Download, Copy link | RPT-1..3, RPT-9 |
| F4 | Report compaction: summary + Fix first on first screen, one-line sections, findings with "Why and sources", "About this report" | RPT-4..8 |
| F5 | Inventory API + page: summary, tabs, rows, filters, sources, Add data, whole-inventory CBOM | INV-1..7 |
| F6 | Systems: ranking + Decisions tab; badge relabel | FSYS-1..3 |
| F7 | Language pass + vocabulary guard; README/About | LANG-1..3 |
| F8 | QA-PLAN-005; QA-REPORT-004 | all |

## 4. Constraints carried over

`textContent` only; strict CSP (no inline styles: positions via SVG attributes); no new Go module; no API removed;
journey, security script and OpenAPI parity stay green; own terminology (TLS hygiene, readiness level).

## 5. Deviations found during the build (2026-10-03)

| # | Planned | Built | Why |
|---|---|---|---|
| D-1 | E-4: inventory rows read from the estate graph; kinds algorithm, protocol, suite, group, software | Rows are read from the **merged CBOM** of E-5 (the same document the download returns); kinds `algorithm`, `key`, `protocol`, `software`. Suites and groups are algorithm components, as in the CBOM. | The graph holds no algorithms from TLS scans, so a graph inventory missed most of what a scan finds. Reading the merged CBOM makes the table and the download agree by construction. |
| D-2 | E-6: per-kind status rules via `pqc.ClassOf` | Status comes from `pqc.Annotate` on the merged CBOM (the cited classification already in the CBOM); a key takes the status of its algorithm; protocols and software are *not applicable*. | One classification path for the page and the download. |
| D-3 | §2: `source=scanner|collector|imported`; places carry system names; `systems`, `placesCount`, `sources` fields | `source=endpoint|machine|import`; a row is `{name, kind, detail, quantum, places:[{label, kind, assetId|importId, when}], refs, lastSeen}`; summary `{algorithm, key, protocol, software, quantumVulnerable, quantumSafe, endpoints, machines, certificates, certificatesExpiring30, imports}` | The CBOM records where a component was seen, not which system it belongs to; systems stay on the Systems page. OpenAPI describes what is built. |
| D-4 | Tabs Algorithms, Certificates, TLS, Software, Sources | Algorithms, **Keys**, Certificates, **Protocols**, Software, Sources | Keys are a CBOM asset type; "Protocols" is the word the CBOM and people use. |
| D-5 | Machine upload under Inventory | Sources embeds the existing Machines and Imported CBOMs views (upload, how-to, history) under plain headings. | Reuses tested views (E-1). |
| D-6 | Not planned | `dashboard.js` (TLS overview) and `cbom.js` (old CBOM page) removed; their routes redirect (REQ-NAV-2). The fleet Findings tab groups findings into one line per problem. | Dead code after the restructure; the Findings tab was still 3,340 words. |
| D-7 | REQ-FSYS (was REQ-SYS in drafts) | Renamed to REQ-FSYS-1..3. | PRD-003 already declares REQ-SYS-1/2; the traceability test refuses duplicate ids. |
| D-8 | (follow-up, 2026-10-03) PDF meant "print the page" | Server-made PDFs: `internal/pdf` (a minimal PDF 1.7 writer: standard fonts in WinAnsi, flate-compressed pages, link annotations, outline) and `internal/reportpdf` (the endpoint report in three kinds and the inventory report). Routes `GET /api/v1/scans/{id}/report.pdf?kind=` and `GET /api/v1/inventory/report.pdf`. | The owner found that the "PDF" opened the print dialog and printed the screen. No new module: the standard library plus x/text, already required. Text outside WinAnsi (e.g. CJK in a certificate subject) prints as "?"; noted in QA-REPORT-004 §9. |
| D-9 | (follow-up) Inventory opened on a tab bar of tables | Inventory opens on a dashboard computed by `GET /api/v1/inventory/dashboard` (also the source of the inventory PDF); the lists moved to `#/inventory/<list>` pages; `?tab=` addresses redirect. Lists and dashboard include imported CBOMs; only the CBOM download keeps the opt-in. | The owner found the tabbed tables did not read as data; the page and the PDF share one computation. |
| D-10 | (follow-up, 2026-10-03) The collector was offered as a downloadable binary | `internal/machinefacts`: two embedded scripts (PowerShell, POSIX sh) write a tab-separated facts file; `POST /api/v1/hosts/ingest` detects it, parses it with bounds (keys refused), and runs the collector's sensors on an in-memory filesystem (`apt`, `cert-files`, a fact-backed `windows-certs`) plus a new `packages` sensor for rpm/apk (methods `rpm.query@1`, `alpine.apk.installed@1`); only fact-backed sensors are registered, and the host OS/arch come from the facts, never the server. Binary routes stay in the API; the UI no longer offers them. | The owner: people will not run an unsigned open-source executable; signing can come if the product is ever paid. Scripts can be read before they run. Not collected by the scripts: Windows CNG and crypto DLLs (noted as not-seen in every script inventory). |
| D-11 | Section status from finding severity only | A vulnerabilities section with any exposed attack is at least "attention"; attack lines state results; rules `eval/4`; `Runner.ReevaluateOutdated` on start re-evaluates the latest result per endpoint made by older rules. | The morafinance report showed LUCKY13 exposed under a green "Good", and "BEAST — TLS 1.0 with CBC suites" under "not exposed" read like a finding. |
| D-12 | — | Failed scans render one explanatory card (`failedCard` in `asset.js`); suite lists in finding details are de-duplicated with their versions. | Owner feedback on reading results. |

