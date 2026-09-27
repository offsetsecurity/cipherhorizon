# SECARCH-001: Security architecture, threat model and security requirements for the estate model

| | |
|---|---|
| **Status** | Baselined with PRD-003 (joint requirements review, [REQ-REVIEW-001](REQ-REVIEW-001-joint-review-and-signoff.md)) |
| **Author role** | Security Architect, working with the Product Manager |
| **Scope** | Everything PRD-003 adds: unified entity model, certificate sensors, correlation, third-party CBOM ingest, system metadata, exports, an optional CBOM-Repository-compatible endpoint |
| **Inherits** | ADR-0004 (no subprocess/PowerShell), ADR-0005 (secret safety by construction), ADR-0006 (host/network separation), ADR-0009 (privilege disclosure and redaction), ADR-0013 (native Windows cryptography), the audit record in `docs/audit/`. Those rules are unchanged; this document only adds. |
| **Method** | STRIDE over the trust boundaries below, checked against the real code paths; each threat has a mitigation that is a *testable* security requirement (SR-n), each SR is traced to a requirement and a test in the [RTM](../program/RTM.md). |

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| **Integrity of the inventory** | A posture tool that can be made to say "safe" or "unsafe" by an unauthenticated party is worse than none. |
| **Confidentiality of the estate map** | Hostnames, certificates, which systems are quantum-vulnerable, FISMA identifiers, criticality: an attacker's target list. Treat the database and every export as sensitive. |
| **Private key material** | Must never enter the product. Not "protected": *absent by construction* (ADR-0005). |
| **Availability of the server and the UI** | Not a life-safety system, but ingest and correlation must not be a cheap DoS. |
| **Host being inspected** | The collector runs on other people's machines. It must stay read-only, bounded, and free of subprocesses and network. |

## 2. Trust boundaries and data classes

```
                   [1] operator browser ── token ──►┐
 [2] collector on host ── token (push) ────────────►│  cipherhorizon serve
 [3] third-party CBOM (file upload / CLI) ─────────►│   ├─ ingest + validation  ◄── boundary B: untrusted document
 [4] optional compat endpoint (opt-in listener) ───►│   ├─ store: raw documents (immutable) + graph projection
 [5] TLS targets (outbound scan, SSRF guard) ◄──────┘   └─ export
 [6] host filesystem / OS APIs  ◄── collector (read-only)                ◄── boundary A: hostile files, hostile certificates
```

**Source classes** (a first-class attribute of every observation, see PRD-003 REQ-MOD-6):

| Class | Produced by | Trust |
|---|---|---|
| `scanner` | our TLS prober (outbound, this server) | first-party |
| `collector` | our collector, authenticated push or operator upload of its own output | first-party *if authenticated*; **an uploaded file is not authenticated as ours** — see T-03 |
| `imported` | any other CycloneDX document | **untrusted**, provenance recorded |
| `operator` | a person, in the UI/API | trusted but audited |

## 3. Threats and mitigations (STRIDE)

Likelihood/impact are judged for a self-hosted tool with a single trust domain per deployment. "Residual" states what is left after mitigation.

| ID | STRIDE | Threat | Mitigation → security requirement | Residual |
|---|---|---|---|---|
| **T-01** | D | Hostile CBOM: huge, deeply nested, million-component, or pathological strings exhausting CPU/memory | **SR-01** Hard limits before parsing (existing 32 MiB body cap kept), then depth limit, component/dependency count limit, string length cap, wall-clock budget; reject with a clear 4xx, never partially store. Native fuzz target on the ingest path. | A well-formed 32 MiB CBOM still costs work; bounded by the budget |
| **T-02** | T/I | Stored XSS: cert subjects, component names, properties and file paths are attacker-chosen strings rendered in the UI | **SR-02** All new views use `createElement`/`textContent` only (existing D4 rule); strict CSP unchanged; the E2E journey gains hostile-string fixtures for every new view; an automated check fails the build on any `innerHTML` with data. | None expected |
| **T-03** | S/T | A CBOM claiming to be collector output (or a compromised collector) to gain first-party trust | **SR-03** First-party trust attaches to the **channel**, not to what a document says about itself. Scanner records are first-party by construction. Today the collector has no push channel of its own: its output arrives through the token-protected host upload route, so **a document is attributed to the collector only when that route receives it *and* it names this product as its producer; anything else is `imported`** (recorded per source, decided in `internal/server/ingest.go`, pinned by `TestHostUploadSourceClassFollowsTheProducer`). This is weaker than the ideal (the producer name is a claim); it is accepted because posting to the route already requires the token, and it is closed properly when an authenticated collector push exists (future work). Third-party documents go through the import flow (WP-4), which never assigns `collector`. Documents' own `tools`/`metadata` are recorded and shown, never used to place data. | A token holder can mislabel a document; the class is recorded per source and shown |
| **T-04** | S | Subject spoofing: a CBOM's `metadata.component` names an existing system so its data lands there | **SR-04** The subject of an ingested document is assigned by the operator at ingest; the document's own subject is stored as a claim and never used for placement. (Real CBOMs omit or misstate the subject: RESEARCH-003 §2.2.) | None |
| **T-05** | T | Correlation poisoning: a crafted certificate fingerprint or hostname attaches an endpoint to the wrong system, or hides a real one | **SR-05** Auto-confirm only when every joined datum is first-party; any link touching `imported` data is at most `proposed`. A fingerprint present on several systems yields *no* automatic join. A `rejected` link is never re-proposed. Every link stores the rules and fields that produced it. | A compromised authenticated collector can still assert false hostnames; mitigated by review queue, not eliminated |
| **T-06** | I | Private key exposure: certificate sensor reads key files/blobs | **SR-06** Certificate sensors read public parts only. Linux: file-name and PEM-label allow-list; any `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `*.key`, `*.p12/.pfx`, `private/` path is **skipped without decoding**; a decoy-key test fixture asserts none is parsed and none appears in output. Windows: enumerate certificate contexts read-only; private-key *presence* comes from a certificate context **property**, never from opening a key handle. A mutation check removes the guard and the test must fail. | None |
| **T-07** | E | New syscall surface (crypt32 store enumeration) abused or crashing | **SR-07** All calls in `internal/winapi` only (architecture test unchanged); open stores with read-only and open-existing flags; per-call timeout; caps on stores, certificates and string sizes; error paths close every handle; written security review (as `stage-2-security-review.md`) is a gate before merge. | Windows bugs outside our control |
| **T-08** | I | Exports and the DB leak the estate map | **SR-08** Every export route requires the token; exports carry the same redaction options as ADR-0009 (hostnames/paths); the DB file keeps restrictive permissions (existing `perm.go` check extended to any new file); documentation states the estate map is sensitive. | Operator handling of exported files |
| **T-09** | S/T/D | The CBOM-Repository contract has **no authentication**; a compatible endpoint exposes an unauthenticated write path | **SR-09** Default **off**; when enabled: separate listener (not the main mux), write-only (`POST /v1/bom` and health only — no search/get), bearer token *or* explicit source-IP allowlist required to start (refuses to start with neither), body/rate limits, documents land as `imported` in an "unassigned" inbox that an operator must assign a subject to. Feature is P2 and blocked on OQ-2. | Unauthenticated Lens clients cannot be supported without allowlist |
| **T-10** | T/D | Migration corrupts or loses data | **SR-10** Raw documents (`scans.report_json`, `host_snapshots.cbom_json`) are the source of truth and are **never rewritten**; the graph is a projection that can be dropped and rebuilt; migration runs in a transaction after an automatic timestamped DB backup; a test migrates a fixture of the v0.1.0 schema and asserts row counts and a rebuilt-graph golden. | Disk full during backup: migration aborts before changing anything |
| **T-11** | R | No record of who changed criticality, environment, link decisions or trust marks | **SR-11** Append-only `audit_log` for every operator mutation (actor = token label, time, before/after, reason). Visible in the UI for a system. | Single shared token means actor = "token"; per-user identity is out of scope (stated limit) |
| **T-12** | S/T | New mutating routes miss the token/Origin/Host checks (CSRF, DNS rebinding) | **SR-12** New routes are registered only through the existing guarded mux; `testing/e2e/security.sh` is extended to enumerate **every mutating route** from the route table and assert: 401 without token, 403 on foreign Origin, 421/403 on foreign Host. A route added without the guard fails the check. | None |
| **T-13** | T | SQL injection via new filter/sort parameters | **SR-13** Parameterised queries only; sort/filter keys come from allow-lists; a test asserts hostile values are inert. | None |
| **T-14** | T | Supply chain: new fixtures, vendored schemas, any new dependency | **SR-14** No new Go dependency without an ADR (target: none). Vendored schemas/fixtures record source URL, version, licence, SHA-256 in a manifest; `govulncheck` and licence check stay in CI. | Upstream schema errors |
| **T-15** | D | Correlation explosion (N×M candidates), pathological many-to-many fingerprints | **SR-15** Index by fingerprint; cap candidates per entity; a fingerprint shared by more than a stated number of systems (default 25) is marked "widely shared" and never auto-joins; runtime budget on the correlation pass. | Very large estates need a tuned cap |
| **T-16** | T/I | Linux certificate sensor follows symlinks or reads devices/FIFOs outside intended dirs | **SR-16** Walk with `fs.WalkDir`; regular files only (skip symlinks, devices, sockets, FIFOs); per-file size cap; per-directory and total counts capped; no path escapes the sensor's `fs.FS` root. | Legitimate symlinked trust stores (e.g. Debian's `/etc/ssl/certs` symlinks into `/usr/share/ca-certificates`) require an explicit, tested resolution rule — see design note DN-4 |
| **T-17** | I | Error messages, logs and CBOM output leak file contents or secrets | **SR-17** The existing "no secret in output" invariant test is extended with the estate fixtures; certificate and ingest error messages contain only names and codes, never document fragments beyond a length-capped, escaped excerpt. | None |
| **T-18** | R/T | An imported document could *lower* a finding (mask a weakness) or remove first-party evidence | **SR-18** Precedence rule: imported evidence can add observations and open questions, never delete or downgrade first-party observations; conflicts are shown side by side with their sources. | None |

## 4. Security requirements by work package (gates)

Each work package in [ENG-HANDOFF-002](ENG-HANDOFF-002-estate-model.md) names the SRs it must satisfy. A package is **not done** until (a) the SR tests exist and pass, (b) the mutation check named in the RTM makes the test fail when the guard is removed, and (c) for WP-CERT-WIN the written syscall review is complete.

## 5. What we explicitly do not defend against (stated limits)

- A malicious **operator with the token**: they can mislabel trust and edit metadata; all of it is audited, none of it prevented.
- A **compromised collector host**: the collector's assertions are only as good as the host it runs on; the graph records that they are collector claims.
- **Multi-tenant isolation**: one deployment = one trust domain (unchanged from 0.1.0).
- **Per-user identity/RBAC**: one shared token; a real identity layer is future work, listed in PRD-003 non-goals.

## 6. Review checkpoints

| When | Reviewer | Checks |
|---|---|---|
| Requirements baseline | Security Architect + PM | This document ↔ PRD-003 traceable (RTM) |
| Design | Security Architect | ENG-HANDOFF-002 data model and trust rules match §3 |
| Each work package | Security Architect | SR tests present; mutation check performed |
| WP-CERT-WIN | Security Architect | Written syscall review |
| Pre-release | Security Architect + QA | `security.sh` extended results; hostile-fixture journey; fuzz run; privacy/secret invariant |
