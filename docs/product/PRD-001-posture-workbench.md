# PRD-001: TLS & PQC Posture Workbench (Release R1)

| | |
|---|---|
| **Status** | Approved for build |
| **Owner** | Product (PM role) |
| **Builds on** | M0 foundation, M1 TLS probe engine (see `docs/architecture.md`, `docs/tls-scanning.md`) |
| **Follow-ups** | `ENG-HANDOFF-001.md` (how), `QA-PLAN-001.md` (proof) |

## 1. Problem

Security and platform teams must answer, for every TLS endpoint they run: *what does it actually support, how
bad is it, and are we exposed to "harvest now, decrypt later" before post-quantum key exchange is in place?*
Today that means running CLI scanners by hand, pasting output into spreadsheets, and having no history. The
engine exists (M1); there is no product around it: no place to keep assets, no workflow, no progress, no
history, no readiness view.

## 2. Objective

> **A user installs one binary, opens a web page, adds their endpoints, scans them, watches progress, and gets a
> cited PQC-readiness and TLS-posture picture for each endpoint and for the whole fleet, with history.**

### Outcomes and how we will measure them (release gates)

| # | Outcome | Measure | Target |
|---|---|---|---|
| O1 | Fast first value | Fresh start to first result on a local target, no configuration | ≤ 5 min, ≤ 30 s scan |
| O2 | Trustworthy | Findings and readiness claims that carry ≥ 1 citation | 100 % (automated check) |
| O3 | Live workflow | Scan visible in the UI after clicking Scan; progress refresh | ≤ 1 s; ≤ 2 s cadence |
| O4 | Memory | Every scan kept and comparable to the previous one | 100 % of scans; diff on demand |
| O5 | Safe by default | Non-loopback bind without token; SSRF to metadata/link-local; foreign Host/Origin | all refused (automated) |
| O6 | Self-contained | External network requests made by the UI | 0 (automated) |

## 3. Users

- **Priya, PQC migration lead.** Needs to know which endpoints are exposed and what to change first.
- **Marcus, platform/SRE.** Owns hundreds of endpoints; wants a list, a schedule, and alerts on regression.
- **Dana, auditor.** Wants evidence: what was observed, when, and the standard behind each statement.

## 4. Scope

**P0 (must ship):** US-01 assets, US-02 scan + progress, US-03 bulk scan, US-04 PQC readiness, US-05 TLS
detail + TLS hygiene, US-06 dashboard, US-07 history + diff, US-11 safe by default, US-12 data ownership.
**P1 (should ship):** US-08 scheduled rescans, US-09 export (CSV/JSON), US-10 host CBOM ingest.
**P2 (later, explicitly not in R1):** CBOM export for TLS endpoints, alerts/webhooks, HTTP checks (HSTS), STARTTLS,
multi-user auth/RBAC, agent daemon, PDF reports, SSH probing.

## 5. Workflow

```
Add asset(s) ─► Scan (now / all / scheduled) ─► Live progress ─► Result: readiness + posture + findings
      ▲                                                                   │
      └──────── Fix on the server ◄── Next steps (cited) ◄────────────────┤
                                     Re-scan ─► History: trend + "what changed since last time"
```

## 6. User stories and acceptance criteria

**US-01 Add assets (P0).** *As a user I add the endpoints I own so I can scan them.*
- AC-01.1 A form adds one endpoint (`host[:port]`, default 443) with optional name and tags; it appears in the list at once.
- AC-01.2 Bulk paste of many lines reports per-line results (added / duplicate / invalid + reason); one bad line never blocks the rest.
- AC-01.3 A duplicate host:port is refused with a clear message.
- AC-01.4 Input is normalised and validated: `https://host:8443/path` is accepted as `host:8443`; empty, bad port, spaces are rejected with a reason.
- AC-01.5 Name, tags and notes are editable; deleting an asset (after confirmation) deletes its history.

**US-02 Scan one asset and watch it (P0).**
- AC-02.1 "Scan now" queues a scan; its status is visible within 1 s.
- AC-02.2 The scan shows current stage (of 5), a percentage, a live connection counter and an event log, refreshing at least every 2 s.
- AC-02.3 On completion the result appears without a page reload.
- AC-02.4 An unreachable or non-TLS endpoint ends as *failed* with a plain reason; it does not block other scans and remains in history.
- AC-02.5 A queued or running scan can be cancelled.
- AC-02.6 At most one active scan per asset: a second request returns the existing one.

**US-03 Bulk scan (P0).**
- AC-03.1 "Scan all" and "scan selected" queue every asset; at most N scans run at once (default 2); the queue is visible.

**US-04 PQC readiness (P0, the headline).**
- AC-04.1 Each scanned asset shows a readiness **level L0–L4**, its plain-language meaning, a harvest-now-decrypt-later (HNDL) exposure flag, three dimensions (key establishment, authentication, symmetric strength) each with an evidence tier, at least one citation per claim, and ordered next steps.
- AC-04.2 The fleet view shows the distribution over levels and the number of HNDL-exposed assets.
- AC-04.3 The level legend is visible in the UI and states that the scale is this product's own, with the standards cited for the underlying facts.
- AC-04.4 Verified with real targets: a server offering `X25519MLKEM768` that negotiates it → L3; a TLS 1.3 server with classical groups only → L1; a TLS 1.2-only server → L0.

**US-05 TLS posture detail (P0).**
- AC-05.1 Shows protocols (with evidence), cipher suites per version with flags (export, anonymous, NULL, 64-bit block, no forward secrecy), IANA recommendation, server-order rank, key-exchange groups with PQ badges, certificate chain with trust/name/expiry-in-days, and server features.
- AC-05.2 Findings list sorted by severity; each has detail, evidence tier, citation(s) and remediation.
- AC-05.3 A **TLS hygiene** score (0 to 100, bands Strong / Sound / Fair / Weak / Broken) worked out only from the result's own cited findings: every point taken off is listed with its finding, any ceiling is stated, and what was **not** measured is listed. Labelled as this product's own scale, not a standard. *(Revised at the owner's request after first build: the original AC used a letter grade modelled on a third-party rating guide; it was replaced so the product shares neither that scanner's terminology nor its tables.)*
- AC-05.4 An *incomplete* scan is flagged; absence of a finding is not presented as absence of a problem.

**US-06 Fleet dashboard (P0).**
- AC-06.1 KPIs: assets, scanned, HNDL-exposed, critical/high findings, certificates expiring ≤ 30 days.
- AC-06.2 Readiness distribution, TLS hygiene band distribution, a "needs attention" list (worst first), recent scans, and a fleet readiness trend over time.

**US-07 History (P0).**
- AC-07.1 Every scan is kept with time, status, TLS hygiene, readiness.
- AC-07.2 A per-asset trend chart of readiness level and TLS hygiene over time.
- AC-07.3 Compare any two scans: changes grouped and marked better / worse / neutral; the default is latest vs previous.
- AC-07.4 Any past scan can be opened read-only in full.
- AC-07.5 Retention keeps the most recent 200 scans per asset (configurable).

**US-08 Scheduled rescans (P1).**
- AC-08.1 Per-asset interval (off, 1 h, 6 h, 24 h, 7 d); next scan time shown; runs automatically; survives restart.

**US-09 Export (P1).**
- AC-09.1 Asset list as CSV; any scan's report and evaluation as JSON.

**US-10 Host CBOM ingest (P1).**
- AC-10.1 A CBOM produced by `cipherhorizon run` can be uploaded (API and UI); it creates/updates a *host* asset showing algorithm verdicts (quantum-vulnerable / safe / unclassified) and the packages that provide them.

**US-11 Safe by default (P0).**
- AC-11.1 Binds to `127.0.0.1` by default; a non-loopback bind is refused unless a token is set.
- AC-11.2 With a token configured every API call without it gets 401.
- AC-11.3 Requests with a foreign `Host` header (DNS rebinding) and mutating requests with a foreign `Origin` are refused.
- AC-11.4 Scan targets in link-local/cloud-metadata, multicast or unspecified ranges are refused at dial time (and loopback unless allowed).
- AC-11.5 The UI makes no external requests; strict CSP.
- AC-11.6 All target- and user-supplied text is rendered as text (a malicious certificate subject or asset name cannot execute).
- AC-11.7 The authorised-use notice is shown in the UI before the first scan.
- AC-11.8 Scan concurrency and per-scan connection budget are enforced.

**US-12 Data ownership (P0).**
- AC-12.1 All state lives in one SQLite file (`--db`); no other service is needed.
- AC-12.2 A scan interrupted by a restart is marked failed, never left "running".

## 7. PQC readiness definition (product specification)

The scale is **this product's own**. Each fact it rests on is cited; the scale itself is not a standard.

| Level | Name | Meaning |
|---|---|---|
| L0 | Not ready | No TLS 1.3: post-quantum key exchange in TLS exists only in TLS 1.3 (RFC 10024). |
| L1 | Exposed | TLS 1.3, but no standardised post-quantum group: recorded traffic is exposed to harvest-now-decrypt-later. |
| L2 | Hybrid available | A standardised hybrid group is supported but a current client does not negotiate it. |
| L3 | Hybrid negotiated | A current client negotiates a standardised hybrid group (e.g. `X25519MLKEM768`). |
| L4 | PQ-authenticated | L3 plus a post-quantum certificate (ML-DSA / SLH-DSA). |

Dimensions: **key establishment** (drives level and HNDL), **authentication** (certificate key algorithms; all
classical today: relevant to future forgery, not to recorded traffic), **symmetric strength** (AES-128+ is at
least NIST category 1). "Standardised" means an IANA group that is neither marked OBSOLETE nor an unpublished
draft; the obsolete Kyber drafts do not count. Sources: NIST FIPS 203/204/205, NIST IR 8547 (draft),
RFC 10024, CISA/NSA/NIST *Quantum-Readiness* factsheet (HNDL), IANA TLS registries.

## 8. UX principles

One-screen answers first, evidence one click deeper. Never colour alone (icon + text). Progress is always
visible and cancellable. Language for a busy engineer, not a cryptographer. Light/dark by system setting;
keyboard operable; respects reduced motion. Works at laptop and narrow widths.

## 9. Non-functional requirements

Single static binary, `CGO_ENABLED=0`; offline; list of 500 assets renders in < 1 s; API p95 < 100 ms excluding
scans; graceful shutdown; scans never run unbounded (timeouts, connection budget); no telemetry.

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Scanner used against systems the user does not own | Notice in UI and CLI; SSRF guard; concurrency/budget caps; no exploit payloads |
| Localhost API abused by a web page the user visits | Host-header allowlist, Origin check, JSON-only mutations, strict CSP |
| Rating mistaken for another scanner's, or borrowing its vocabulary | Own name, own bands (no letters), derived only from cited findings; unmeasured items listed; a test forbids the old vocabulary in the rating text |
| Readiness scale mistaken for a standard | Legend states it is product-defined; facts cited |
| Malicious server output in the UI | Text-only rendering; XSS test with hostile certificate/asset strings |

## 11. Definition of done

All P0 acceptance criteria pass in `QA-REPORT-001`; every finding/readiness claim cited (automated); lint,
unit, integration and fuzz green; UI exercised end-to-end in a real browser with screenshots; artifacts
collected with a manifest; deviations from this PRD listed in the release report.
