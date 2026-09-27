# PRD-003: Cryptographic estate model — one graph, certificates, correlation, third-party CBOM ingest

| | |
|---|---|
| **Status** | **Baselined** by the joint requirements review ([REQ-REVIEW-001](REQ-REVIEW-001-joint-review-and-signoff.md)); changes go through the change log in §12 |
| **Authors** | Product Manager and Security Architect, jointly |
| **Builds on** | PRD-001 (workbench), PRD-002 (evidence and coverage), the host-discovery program (ADR-0001…0013) |
| **Inputs** | [STRATEGY-001](../strategy/STRATEGY-001-product-review.md) (verdict: *reposition and narrow*), [RESEARCH-003](RESEARCH-003-ecosystem-standards-and-design-inputs.md), [SECARCH-001](SECARCH-001-threat-model-and-security-requirements.md) |
| **Target release** | 0.2.0 (after the still-untagged 0.1.0) |
| **Traceability** | Every requirement below has an ID; [RTM](../program/RTM.md) links it to its research source, design, code, test and QA evidence. Progress is in [TRACKER](../program/TRACKER.md). |

## 1. Problem

CipherHorizon today has two good but unconnected halves: an active TLS scanner (endpoints, rated and evidence-graded) and a host cryptographic inventory (evidence-graded CBOM per machine). They are stored in different shapes, related only by a manually created link, and neither knows **who owns a system, how exposed it is, or how long its data must stay confidential**. Certificates — where CISA says the inventory data "explicitly" exists — are not entities at all, and host inventory cannot state a key length.

The product review's finding: the market gap is not "another scanner" (CBOMkit, cdxgen, CBOM-Lens and commercial suites already scan, and give away CBOMs) but **turning many partial, differently-trustworthy observations into one honest picture of which systems are exposed and what to fix first**.

## 2. Vision and positioning

> **CipherHorizon is a cryptographic inventory and PQC-readiness workbench. It joins what its own sensors observe with what other tools report into one evidence-graded picture of your estate, tells you what it did *not* see, and ranks what to fix first with the reasons shown.**

- **Category:** cryptographic inventory and PQC readiness (direction: cryptographic posture management). CBOM is an **interchange format we read and write**, not the product.
- **We do not compete on** source-code, container or repository scanning. We ingest that output.
- **We do compete on** honesty (evidence rungs, blind spots, `unknown(reason)`), the deepest active PQC-TLS enumeration, native Windows cryptography inventory, small air-gapped static binaries, and — new in this PRD — **correlation and prioritisation across sources**.

## 3. Personas and jobs

| Persona | Job to be done | What they need from this release |
|---|---|---|
| **Priya — PQC migration lead** | "Which systems do I migrate first, and can I defend the order?" | Estate view ranked with reasons; certificates and key lengths; data-lifetime-aware exposure |
| **Dana — auditor / compliance** | "Produce the inventory the memo asks for, and show how each fact is known." | M-23-02-shaped export, provenance per fact, blind spots stated, audit trail |
| **Marcus — system owner / platform engineer** | "What is wrong with *my* system and what do I change?" | System detail joining its endpoints, host and certificates; clear next steps; no false joins |
| **Alex — security engineer running other tools** | "I already run CBOMkit/CBOM-Lens; give me one place." | Upload/push third-party CBOMs, assign them to systems, see them next to first-party data without being misled |

## 4. Goals, non-goals, success measures

**Goals (0.2.0).** G1 one data model; G2 certificates and key length; G3 automatic, reviewable correlation; G4 third-party CBOM ingest with provenance; G5 system metadata and explainable prioritisation; G6 standards-current export (CycloneDX 1.7, M-23-02 structure, OpenAPI); G7 UI and wording that state the new positioning.

**Non-goals.** Source/container/repo scanning; SaaS or multi-tenant operation; per-user accounts/RBAC; Postgres; agent auto-update; vulnerability database; remediation automation; a CyberScope submission client; macOS certificate sensor (OQ-3); compliance *certification* claims (we "support the structure", we do not certify).

**Success measures** (verified in QA, [QA-PLAN-002](QA-PLAN-002-estate-model.md)):

| # | Measure | Target |
|---|---|---|
| M1 | Two real third-party CBOMs (CBOMkit, CBOM-Lens) ingest and display without loss of asset counts | 100% of asset counts preserved; unsupported content counted, not dropped |
| M2 | On the synthetic estate fixture, automatic correlation | 0 false auto-confirmed joins; every ambiguous or third-party-derived join is `proposed` |
| M3 | Certificate sensor on the development Windows machine | Store contents equal an independent oracle (`certutil`-based) set for the same store: 0 missing, 0 extra |
| M4 | Private key material anywhere in DB, CBOM, logs, UI | 0 occurrences over the decoy-key fixtures |
| M5 | Existing 0.1.0 database migrates | 0 rows lost; every finding visible before is visible after |
| M6 | New CBOM output validates | 100% against the 1.7 schema (and 1.6 in compatibility mode) |
| M7 | A new user, with the guided first run, reaches "systems ranked with reasons" | ≤ 5 clicks / ≤ 10 minutes measured on the journey script |

## 5. Requirements

Priority: **P0** must ship for 0.2.0; **P1** should ship, may slip with PM sign-off; **P2** may follow. *Source* cites RESEARCH-003 finding IDs; *SR* cites SECARCH-001 requirements that the requirement must also satisfy.

### Epic A — Unified estate model (REQ-MOD)

| ID | Requirement | Pri | Source | SR |
|---|---|---|---|---|
| **REQ-MOD-1** | Raw documents (scan report JSON, host/imported CBOM) are stored unchanged and are the source of truth. The estate graph is a **projection** that can be dropped and rebuilt from them. | P0 | STRATEGY §data model | SR-10 |
| **REQ-MOD-2** | The graph has entities: **system**, **service** (a `host:port` endpoint), **certificate**, **algorithm use**, **protocol configuration**, **software/provider**. Each has a stable natural key (e.g. certificate = SHA-256 fingerprint). | P0 | STRATEGY | |
| **REQ-MOD-3** | Every TLS scan projects into the graph: its service, certificate chain, and every observed protocol/suite/group with its evidence class. **No finding, rating or readiness result shown in 0.1.0 disappears or changes.** | P0 | STRATEGY | SR-10 |
| **REQ-MOD-4** | Every host snapshot projects into the graph: system, software/providers, algorithm uses, files, with evidence rung and method quality preserved. | P0 | STRATEGY | SR-10 |
| **REQ-MOD-5** | An existing 0.1.0 database migrates forward automatically, after a timestamped backup, in one transaction; the graph is then rebuilt from stored documents. A database newer than the binary is refused (existing behaviour). | P0 | — | SR-10 |
| **REQ-MOD-6** | Every observation records **source class** (`scanner`, `collector`, `imported`, `operator`), method, evidence class/rung, observation time, and the document it came from. The **host and network streams stay separate** (ADR-0006): unification is one store and one entity space, not one merged claim; a host observation is never rewritten as network evidence or the reverse, and a joined result is a labelled *link* (assessment) whose class is capped by the weakest of its inputs and its link. | P0 | E-1, E-2 | SR-03 |
| **REQ-MOD-7** | The graph tracks first-seen / last-seen per entity and reports entities **no longer observed** (stale), without deleting them. | P1 | — | |

*Acceptance.* AC-MOD-1: dropping and rebuilding the graph from raw documents yields an identical graph (golden). AC-MOD-2: a 0.1.0 fixture DB with S scans and H snapshots migrates with S and H raw rows unchanged and the UI shows the same findings (compared by the journey script against a pre-migration capture). AC-MOD-3: `Observation` rows cannot be inserted without source class, method and time (schema `NOT NULL` + test). AC-MOD-4: killing the process during migration leaves the pre-migration DB intact (test with injected failure).

### Epic B — Certificates and key length (REQ-CERT)

| ID | Requirement | Pri | Source | SR |
|---|---|---|---|---|
| **REQ-CERT-1** | A **Windows certificate sensor** enumerates the machine and current-user certificate stores (MY, Root, CA, TrustedPeople, TrustedPublisher, AuthRoot, Disallowed) via native APIs in `internal/winapi`. | P0 | K-1 | SR-06, SR-07 |
| **REQ-CERT-2** | A **Linux certificate sensor** reads certificates from a fixed allow-list of trust-store and service directories via `fs.FS`. | P0 | K-1 | SR-06, SR-16 |
| **REQ-CERT-3** | Per certificate: subject, issuer, serial, SHA-256 fingerprint, validity, key algorithm and **size/curve**, signature algorithm, SANs, key usage/EKU, CA and self-signed flags, origin (store/path), **private key present: yes / no / unknown**. | P0 | K-2, S-5 | SR-06 |
| **REQ-CERT-4** | **No private key material is ever read, stored, logged, exported or displayed.** Files that could hold private keys are skipped undecoded. | P0 | K-4 | SR-06, SR-17 |
| **REQ-CERT-5** | Root and intermediate CA certificates are **summarised** (count; expiring; weak key; SHA-1-signed; changed since last snapshot) and not listed as individual findings; end-entity certificates are itemised. | P0 | K-3 | |
| **REQ-CERT-6** | Certificates observed by the TLS scanner and by sensors/imports are the **same entity** when the fingerprint is equal; the entity shows every place it was seen. | P0 | S-5, C-1 | |
| **REQ-CERT-7** | Cited findings for certificates: expired / expiring (configurable window), RSA < 2048, SHA-1 or MD5 signature, validity beyond a stated PQC deprecation date (a quantum-vulnerable key in a certificate that outlives 2030/2035). Each finding has a citation; a test fails any rule without one (existing rule D6). | P0 | S-6 | |
| **REQ-CERT-8** | Key length and curve appear in the host CBOM (`certificate` components with public-key size/curve) and in the UI system detail. Where no source states a key length the UI says `unknown` with the reason. | P0 | S-5, K-2 | |

*Acceptance.* AC-CERT-1: on the development Windows machine, the sensor's set of certificates per store equals an independent `certutil -store` oracle set (0 missing, 0 extra) — new oracle script `compare-certs.ps1`. AC-CERT-2: Linux fixture with decoy private keys (`.key`, PKCS#8 block, `.p12`, encrypted key, key inside a `certs/` directory): none parsed, none in output, mutation check (guard removed → test fails). AC-CERT-3: the same certificate scanned over TLS and found in a store yields one entity with two observations. AC-CERT-4: every certificate finding has a citation (invariant test).

### Epic C — Automatic correlation (REQ-COR)

| ID | Requirement | Pri | Source | SR |
|---|---|---|---|---|
| **REQ-COR-1** | The product proposes links between systems and services using exactly the rules in RESEARCH-003 §4.2: **J1** certificate fingerprint, **J2** endpoint address ↔ host name/address, **J3** SAN ↔ host name (corroboration only). No fuzzy or similarity matching. | P0 | C-1 | SR-05 |
| **REQ-COR-2** | A link is a stored object: the two entities, the rules that fired with the matching values, a strength label (`strong` / `medium` / `weak`, from a fixed documented table — not a computed score), a **state** (`proposed` / `confirmed` / `rejected`), and who/when decided. | P0 | C-2, §4.3 | SR-11 |
| **REQ-COR-3** | **Ambiguity is shown, not resolved.** A fingerprint present on several systems yields proposals to each and joins none; a fingerprint on more than the "widely shared" cap (default 25) never auto-joins. | P0 | C-3 | SR-05, SR-15 |
| **REQ-COR-4** | A link **auto-confirms** only if it is `strong`, unique, and every datum comes from `scanner`/`collector` sources. Any link involving `imported` data stays `proposed` until a person confirms it. | P0 | C-4 | SR-03, SR-05 |
| **REQ-COR-5** | A `rejected` link is not re-proposed by later scans; a confirmed link that is no longer supported is flagged for review, not silently removed. | P0 | C-5 | |
| **REQ-COR-6** | Each link explains itself: which values matched, on which observations, from which sources. | P0 | C-6 | |
| **REQ-COR-7** | API and UI: a **review queue** of proposed links (confirm / reject / note), and confirm/reject actions on a system's detail. Existing manual links keep working and appear as `confirmed`, source `operator`. | P0 | — | SR-11, SR-12 |
| **REQ-COR-8** | Correlation runs after each ingest/scan within a time budget and is deterministic (same inputs → same links). | P1 | — | SR-15 |

*Acceptance.* AC-COR-1: on the synthetic **estate fixture** (unique certs, a certificate shared by 3 hosts, a wildcard on 40 hosts, a host with two IPs, hostile decoys — name-collision host, forged imported CBOM carrying a real fingerprint) the golden expected link set is produced exactly. AC-COR-2 (M2): zero auto-confirmed links that the golden marks as wrong or ambiguous. AC-COR-3: reject → rescan → link stays rejected. AC-COR-4: determinism (run twice, identical output incl. ordering).

### Epic D — Third-party CBOM ingest (REQ-ING)

| ID | Requirement | Pri | Source | SR |
|---|---|---|---|---|
| **REQ-ING-1** | Accept CycloneDX **1.6 and 1.7** CBOMs via UI upload, API and CLI (`cipherhorizon import`). | P0 | E-3 | |
| **REQ-ING-2** | Validate against the vendored schema for the declared version; enforce size, depth, count and time limits; reject invalid or over-limit documents with a specific message; store nothing on rejection. | P0 | | SR-01 |
| **REQ-ING-3** | The **operator assigns the subject system** at ingest (an existing system or a new one). The document's own `metadata.component` is stored as a claim and shown, never used for placement. | P0 | E-2 | SR-04 |
| **REQ-ING-4** | Every import stores **provenance**: source class `imported`, declared tool/version if any, file SHA-256, size, receive time, submitting token label, and the assigned subject. Re-importing identical content is idempotent (no duplicate). | P0 | | SR-03, SR-11 |
| **REQ-ING-5** | Evidence mapping by source class: static-source CBOMs (CBOMkit, cdxgen) map to **capable from source**; host/network CBOMs (CBOM-Lens) map to **present** or **observed** as the document supports; nothing is ever mapped to *exercised* or *bound* on an import's say-so. | P0 | E-1 | SR-18 |
| **REQ-ING-6** | Recognised **profiles**, each tested against a real sample: CBOMkit, CBOM-Lens (1.6 and 1.7), Theia/hyperion, cdxgen (sample to be generated if not obtainable), CipherHorizon's own output. An unrecognised producer still ingests generically. | P0 | E-3, E-4 | |
| **REQ-ING-7** | Content the product cannot interpret (unknown asset types, non-crypto components, unsupported fields) is **preserved raw and counted** in a visible "not interpreted" summary — never silently dropped, and included in coverage/blind spots. | P0 | | |
| **REQ-ING-8** | Imported evidence can add observations but never delete or downgrade first-party ones; conflicts are shown side by side with sources. | P0 | | SR-18 |
| **REQ-ING-9** | An import can be **withdrawn** (removes its observations from the graph; the raw document is retained for audit unless purged). | P1 | | SR-11 |
| **REQ-ING-10** | Optional **CBOM-Repository-compatible endpoint** (`POST /v1/bom`, `/v1/health*`) so CBOM-Lens can push: default off, separate listener, write-only, token or IP allowlist mandatory, lands in an *unassigned inbox*. **Blocked on OQ-2**; not started until resolved. | P2 | E-6 | SR-09 |

*Acceptance.* AC-ING-1 (M1): the CBOMkit Keycloak/Kafka, Theia and CBOM-Lens 1.6/1.7 samples ingest; asset counts by type equal those measured independently by a script on the raw JSON. AC-ING-2: a CBOM with no subject and one whose subject names an existing system both land only where the operator assigns. AC-ING-3: hostile documents (depth bomb, 1M components, oversize, wrong schema, XSS strings in every string field) rejected or rendered inert; fuzz target runs clean for a fixed budget. AC-ING-4: a forged "collector" CBOM uploaded via the UI is `imported`, cannot auto-confirm a link.

### Epic E — System metadata and prioritisation (REQ-SYS, REQ-PRI)

| ID | Requirement | Pri | Source | SR |
|---|---|---|---|---|
| **REQ-SYS-1** | A system carries **optional** operator fields: owner (person/team), environment (production / staging / development / other), criticality (low / moderate / high — matching FIPS 199 vocabulary), exposure (internet / internal / restricted), **data lifetime** (how long the data must stay confidential, in years), FISMA system id, FIPS 199 category, HVA id, hosting (on-premises / commercial cloud + name / government cloud + name / hybrid + names), notes. | P0 | S-4 | |
| **REQ-SYS-2** | Fields are editable per system and by **CSV import/export**; every change is audited (who/when/before/after). Missing fields display as *not provided*, and the product states when a ranking rests on missing inputs. | P0 | | SR-11, SR-13 |
| **REQ-PRI-1** | The estate view ranks systems by an **explainable rule ordering**, not an opaque score: (1) confidentiality exposure to harvest-now-decrypt-later = quantum-vulnerable key establishment observed *and* data lifetime extends beyond the relevant NIST IR 8547 date; (2) exposure and criticality; (3) certificate/hygiene defects; (4) evidence strength. Each rank row lists the facts and citations that put it there. | P0 | S-6 | |
| **REQ-PRI-2** | The TLS hygiene rating stays, but is presented as **one input** on a service, not the headline of the product. | P0 | STRATEGY | |
| **REQ-PRI-3** | Every rule that orders systems has a citation and a test; changing the ordering rules requires a changelog entry. | P0 | | |

*Acceptance.* AC-SYS-1: CSV round-trip preserves all fields; malformed rows reported with line numbers, none applied partially. AC-PRI-1: on a fixture with known systems the ranking equals the golden and every row's explanation cites its facts; two systems differing only in data lifetime rank in the expected order. AC-PRI-2: a system with no metadata is ranked and labelled "based on evidence only — no owner/exposure/lifetime provided".

### Epic F — Export and standards (REQ-EXP)

| ID | Requirement | Pri | Source | SR |
|---|---|---|---|---|
| **REQ-EXP-1** | CBOM output is **CycloneDX 1.7** by default, validated against the vendored 1.7 schema; a `--spec 1.6` option remains for consumers that have not moved. 1.7 replacements for deprecated 1.6 constructs are used, not both. | P0 | S-1 | SR-14 |
| **REQ-EXP-2** | A tested table maps our algorithm catalogue IDs to the 1.7 cryptography-registry family and curve names; any catalogue entry without a registry equivalent is listed, and emitted without an invented name. | P0 | S-1 | |
| **REQ-EXP-3** | **M-23-02 structured export** (JSON and CSV) per system for the nine items: items 4–6 from evidence (algorithm, service provided, key length; software/vendor where known; OS); items 1–3, 7–9 from system metadata, each marked *provided* or *not provided*. Worded as "supports the structure", never "compliant". | P0 | S-4 | SR-08 |
| **REQ-EXP-4** | An **estate CBOM** export (whole graph or one system) that expresses correlation using BOM-Link references where the standard allows. | P2 | S-2 | |
| **REQ-EXP-5** | A hand-maintained **OpenAPI 3.1** document for every API route, with a test that fails if a registered route is undocumented or a documented route does not exist. | P1 | R6 | |
| **REQ-EXP-6** | All export routes require the token; ADR-0009 redaction options apply. | P0 | | SR-08 |

*Acceptance.* AC-EXP-1 (M6): generated CBOMs validate against 1.7 (1.6 in compat) and a negative control is rejected. AC-EXP-2: mapping table test lists unmapped catalogue entries explicitly. AC-EXP-3: the export for a fixture system has all nine items with correct provided/not-provided marks; item 4 rows carry algorithm, service and key length or an explicit `unknown(reason)`. AC-EXP-5: route/OpenAPI parity test.

### Epic G — UI and positioning (REQ-UI)

Design is a separate deliverable (UX-DESIGN-002, produced after the model is built) but requirements are fixed here.

| ID | Requirement | Pri |
|---|---|---|
| **REQ-UI-1** | Wording and navigation state the new positioning: the primary object is a **system**; "Hosts" and "Endpoints" become views of a system; CBOM becomes an export/interchange action, not a top-level destination; the README states the category. Product terminology rule stands (no SSL-Labs-style grades). | P0 |
| **REQ-UI-2** | **Estate** view: systems ranked per REQ-PRI-1 with owner, environment, exposure, reasons, and a "based on evidence only" marker where metadata is missing. | P0 |
| **REQ-UI-3** | **System detail**: services, host evidence, certificates (with key size), links (with explanations and confirm/reject), imported sources with provenance, metadata editor, audit trail, coverage/blind spots. | P0 |
| **REQ-UI-4** | **Certificates** view: all certificates, filter by expiry window, key size/curve, signature algorithm, origin; roots summarised. | P0 |
| **REQ-UI-5** | **Correlation review queue** (REQ-COR-7). | P0 |
| **REQ-UI-6** | **Import flow**: choose file, see detected producer and what was/wasn't interpreted, assign subject, confirm. | P0 |
| **REQ-UI-7** | Guided first run updated for the new model. | P1 |
| **REQ-UI-8** | Unchanged: strict CSP, no external requests, no `innerHTML` with data, keyboard navigation, dark mode, AA contrast; the hostile-string fixtures cover all new views. | P0 |

### Epic H — Quality, release, non-functional (REQ-REL, REQ-NFR)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-REL-1** | CHANGELOG, version and README updated; upgrade notes for the migration. | P0 |
| **REQ-REL-2** | Documentation: user guide for import, correlation review and system metadata; sensor doc for certificates; methodology doc for prioritisation with citations. | P0 |
| **REQ-REL-3** | A documented **rename procedure** (module path, binaries, `cipherhorizon:` namespace, env vars) exists and is mechanically checkable (ADR-0014). | P1 |
| **REQ-REL-4** | A CI job runs the collector and certificate sensor on a Linux runner against a known image with an oracle script (closes the Linux live-validation gap). *Owner action: needs the GitHub repository.* | P1 |
| **REQ-NFR-1** | Performance *design targets, to be measured and reported, not promised*: list views over 5,000 systems / 50,000 certificates respond in under 1 s at p95 on a developer laptop; a 32 MiB import completes within its budget (default 10 s) or fails cleanly. | P1 |
| **REQ-NFR-2** | `CGO_ENABLED=0`; both binaries still cross-compile for every release platform; no new Go dependency without an ADR (target: none). | P0 |
| **REQ-NFR-3** | The collector remains read-only, with no subprocess and no network beyond its own authenticated push (ADR-0004, ADR-0006). | P0 |
| **REQ-NFR-4** | Zero new external requests; CSP unchanged. | P0 |
| **REQ-NFR-5** | Every P0/P1 requirement has ≥ 1 automated test named in the RTM; lint, vet, `govulncheck`, licence check green; existing 430-test suite still passes. | P0 |
| **REQ-NFR-6** | Accessibility: keyboard reachability and contrast checks on the new views are part of the journey script. | P1 |

## 6. Scope by release increment

Work is delivered in increments, each ending in something runnable and a gate (see [PROGRAM](../program/PROGRAM.md)).

| Increment | Contains | Why this order |
|---|---|---|
| **I1 — Model** | REQ-MOD-1…7, REQ-SYS-1/2 storage, audit log, OpenAPI skeleton | Everything depends on it; safest to migrate first |
| **I2 — Certificates** | REQ-CERT-1…8 | Fills the M-23-02 item 4 gap; needs the model; Windows part needs a syscall review |
| **I3 — Ingest** | REQ-ING-1…9, fixtures, fuzzing | Independent of certificates; feeds correlation |
| **I4 — Correlation and prioritisation** | REQ-COR-1…8, REQ-PRI-1…3 | Needs certificates and ingest to have something to join |
| **I5 — Export and standards** | REQ-EXP-1…6 | 1.7 output touches the CBOM builder which I1–I4 extend; do it once |
| **I6 — UI** | REQ-UI-1…8 (after a design document) | Built on stable APIs |
| **I7 — QA and release** | REQ-REL-*, REQ-NFR-* verification, QA report | Independent verification pass |
| Later | REQ-ING-10 (blocked on OQ-2), REQ-EXP-4 | |

## 7. Assumptions and constraints

- Single-node, single trust domain, one shared token (unchanged).
- SQLite (pure Go) remains the store; the graph is tables plus indexes, not a graph database.
- Windows development machine only; Linux validated by CI once the repository exists.
- Sample CBOM licences are unverified (OQ-5); fixtures are vendored only where the licence permits, otherwise regenerated.

## 8. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| RK-1 | Migration bug loses or distorts existing data | Low | High | Raw docs immutable; backup; rebuildable projection; migration fixture (SR-10) |
| RK-2 | Correlation produces plausible false joins that users trust | Medium | High | Only deterministic keys; proposals by default; explanations; golden estate fixture with hostile decoys |
| RK-3 | 1.7 output breaks consumers still on 1.6 | Medium | Medium | `--spec 1.6` compatibility path; both validated |
| RK-4 | Windows certificate enumeration hits an API edge case | Medium | Medium | Written syscall review; oracle comparison; fail-soft per store |
| RK-5 | Scope too large for one release | High | Medium | Increments with gates; P1/P2 slip explicitly; PM sign-off on any P0 change |
| RK-6 | Ingest profile drift as upstream tools change formats | Medium | Low | Generic ingest always works; profiles are additive and versioned |
| RK-7 | Positioning change confuses existing users | Low | Low | Changelog, redirects from old routes, guided first run |

## 9. Open decisions (owner)

OQ-1 trademark/domain clearance; OQ-3 macOS certificate sensor in scope?; OQ-4 spreadsheet-shaped export wanted?; OQ-2 and OQ-5 are PM research tasks (tracked). None blocks I1–I3.

## 10. Definition of done (per requirement)

A requirement is **done** when: design recorded (ADR/handoff), code merged with tests that trace to its ID, security requirements verified (mutation check where the RTM says so), QA evidence recorded in the RTM (test name or report section), documentation updated. The RTM is the only place "done" is asserted.

## 11. Approval

Joint review and sign-off: [REQ-REVIEW-001](REQ-REVIEW-001-joint-review-and-signoff.md).

## 12. Change log

| Date | Change | Approved by |
|---|---|---|
| 2026-09-26 | Baseline | PM, Security Architect |
| 2026-09-26 | REQ-CERT-7: removed "CA-flag or key-usage anomalies". No such rule could be written with a citation (the requirement was not specific enough to test, which the review checklist forbids); the five shared rules and the PQC-outlives rule remain. A specific anomaly rule can be added later as its own requirement. | PM, Security Architect |
