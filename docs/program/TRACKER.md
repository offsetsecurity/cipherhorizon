# Tracker

Live status of the program in [PROGRAM](PROGRAM.md). Requirement status lives **only** in the [RTM](RTM.md); this file tracks phases, work packages, tasks, decisions, risks and open questions. Update it in the same change as the work.

Legend: ✅ done · ⏳ in progress · ⬜ not started · ⛔ blocked · ➖ deferred

## Phases

| Phase | Status | Date | Notes |
|---|---|---|---|
| 0 Research | ✅ | 2026-09-26 | RESEARCH-003, ADR-0014 |
| 1 Requirements | ✅ (owner approval pending) | 2026-09-26 | PRD-003, SECARCH-001, REQ-REVIEW-001, RTM |
| 2 Design and handoff | ✅ | 2026-09-26 | ENG-HANDOFF-002, QA-PLAN-002 |
| 3 Build | ✅ | 2026-09-26 | WP-1 to WP-8 built |
| 4 UX and UI | ✅ | 2026-09-26 | UX-DESIGN-002; six new views; journey 104/104 |
| 5 QA and release | ✅ (owner review pending) | 2026-09-26 | QA-REPORT-002; nothing committed or tagged |

## Work packages

| WP | Title | Status | Requirements | Security review | Commit | Notes |
|---|---|---|---|---|---|---|
| WP-1 | Model, migration, systems metadata, audit | ✅ (built, uncommitted) | MOD-1…7, SYS-1, SYS-2 (ranking statement moves to WP-6) | mutation checks done: backup, audit, host-exercised, import-bound, forgery guard | — | COR-2 storage moves to WP-5 (links); OpenAPI parity moves to WP-7 |
| WP-2 | Certificate entities + Linux certificate sensor | ✅ (built, uncommitted) | CERT-2…7, CERT-8 (UI part in WP-8) | done: docs/program/reviews/WP-2-security-review.md | — | live Linux host not validated; overridden-root symlink test skips on this machine |
| WP-3 | Windows certificate sensor | ✅ (built, uncommitted) | CERT-1 | done: docs/host-discovery/wp3-security-review.md | — | oracle AGREE on this machine; Server/ARM64/elevated not validated |
| WP-4 | Third-party CBOM ingest | ✅ (built, uncommitted) | ING-1 (UI part WP-8), 2…9 | done: docs/program/reviews/WP-4-security-review.md | — | cdxgen: no real sample; ING-10 deferred |
| WP-5 | Correlation | ✅ (built, uncommitted) | COR-1…6, 8; COR-7 (UI part WP-8) | done: docs/program/reviews/WP-5-security-review.md | — | UI must announce automatic joins (W5-3) |
| WP-6 | Prioritisation | ✅ (built, uncommitted) | PRI-1, 3; PRI-2 (score presentation is WP-8) | notes in WP-1/WP-4 reviews | — | four ordered cited rules, no composite score |
| WP-7 | Export and standards | ✅ (built, uncommitted) | EXP-1,2,3,5,6 | SR-08 (table-walk token test), SR-14 (no new module) | — | see docs/exporting.md; gaps: OS item, supplier, response schemas |
| WP-8 | UX design and UI | ✅ (built, uncommitted) | UI-1…8, COR-7, ING-1, CERT-8, PRI-2 UI parts | hostile-string and CSRF checks in journey and security.sh | — | see UX-DESIGN-002; fixed a real race: a finished scan was visible before its certificates and proposals were derived |
| WP-9 | QA and release | ✅ (built, uncommitted) | REL-1 (cut pending), REL-2, REL-3, NFR-1…6 | QA-REPORT-002 | — | govulncheck, licence check, Linux live validation not done; see the report |

## Task log

| ID | Task | Requirement | Status |
|---|---|---|---|
| T-101 | Read migrations/store to fix schema version and backfill rule | MOD-5 | ✅ |
| T-102 | 0.1.0 database fixture (built from the frozen migrations by `store.BuildLegacyDB`, pinned by hash) | MOD-5 | ✅ |
| T-103 | Migration 4 with backfill and pre-migration backup | MOD-1, 5; SYS-1 | ✅ |
| T-104 | `internal/estate`: entities, observations, validation, keys | MOD-2, 6 | ✅ |
| T-105 | Projection of TLS scan reports | MOD-3 | ✅ |
| T-106 | Projection of host CBOMs | MOD-4 | ✅ |
| T-107 | Rebuild, startup rebuild on version change, `db` command | MOD-1, 5 | ✅ |
| T-108 | Stale detection | MOD-7 | ✅ |
| T-109 | Systems API, CSV, audit | SYS-1, 2 | ✅ |
| T-110 | Tests and mutation checks | AC-MOD-1…4 | ✅ |
| T-111 | RTM rows, CHANGELOG | — | ✅ |
| T-201 | Certificate evidence attributes, Linux certificate sensor, decoy-key fixtures | CERT-2…4 | ✅ |
| T-202 | certinfo, shared CBOM certificate builder, estate certificate projection, certificate rules and API | CERT-3, 5…7 | ✅ |
| T-203 | Windows layer, sensor, syscall review, oracle with negative controls | CERT-1 | ✅ |
| T-301 | Third-party CBOM ingest: limits layer, schema validation, profiles, subject assignment, provenance, fuzz, CLI | ING-1…9 | ✅ |
| T-401 | Correlation: rules J1–J3, links table and state machine, estate fixture with hostile decoys, review API | COR-1…8 | ✅ |
| T-501 | Prioritisation: ordered cited rules, per-row explanation, methodology doc | PRI-1…3, SYS-2 | ✅ |
| T-601 | CycloneDX 1.7 conversion, registry mapping, dual-schema validation, importer reads relatedCryptographicAssets | EXP-1, 2 | ✅ |
| T-602 | M-23-02 export (JSON, CSV), OpenAPI 3.1 with route parity tests, docs/exporting.md | EXP-3, 5, 6 | ✅ |
| T-701 | UX-DESIGN-002, then the UI for REQ-UI-1…8 | UI-1…8 | ✅ |
| T-801 | QA report against QA-PLAN-002 (M1-M7), REQ-REL/NFR verification, rename rehearsal, scale measurement | REL, NFR | ✅ |
| T-901 | Owner review, commit, cut 0.2.0 (scripts/prepare-release.sh), publish | REL-1 | ⬜ owner |

## Decisions log

| Date | Decision | Record |
|---|---|---|
| 2026-09-26 | Reposition and narrow (inventory + PQC readiness; CBOM is an interchange format) | STRATEGY-001 |
| 2026-09-26 | Keep name CipherHorizon (alternatives collide/crowded) — owner may override | ADR-0014 |
| 2026-09-26 | Order: model → certificates → ingest → correlation/prioritisation → export → UI → QA | PRD-003 §6 |
| 2026-09-26 | No per-user identity/RBAC in 0.2.0 | REQ-REVIEW-001 #10 |
| 2026-09-26 | CBOM-Repository-compatible endpoint P2, default off, blocked on OQ-2 | REQ-REVIEW-001 #3 |
| 2026-09-26 | Trust follows the channel, not what a document claims (host upload = collector only if it names this product as producer; documented weaker guarantee until an authenticated push exists) | SECARCH-001 T-03 |
| 2026-09-26 | Systems are a layer above assets (asset = observation anchor; system = owned unit); links merge systems | ENG-HANDOFF-002 D3, DN-1 |

## Open questions and owner actions

| ID | Item | Owner | Blocks |
|---|---|---|---|
| OQ-1 | Trademark/domain clearance for CipherHorizon | Product owner | Launch, namespace registration |
| OQ-2 | Can CBOM-Lens send an `Authorization` header to a repository? | PM (research) | REQ-ING-10 |
| OQ-3 | macOS certificate sensor in scope? | Product owner | Scope only |
| OQ-4 | Spreadsheet-shaped (CyberScope) export wanted? | Product owner | REQ-EXP-3 format |
| OQ-5 | Licences of third-party sample CBOMs | PM (research) | Fixture vendoring (WP-4) |
| OA-1 | GitHub owner (`scripts/set-owner.sh`), SECURITY.md contact, tracked `artifacts/` decision, tag and push after CI | Product owner | Release, REQ-REL-4 |
| OA-2 | Approve PRD-003 (REQ-REVIEW-001 §4) | Product owner | Formal baseline |
| OA-3 | A Linux environment for live validation (WSL hangs on the dev machine) | Product owner | Linux "validated" claim |

## Risks (live)

See PRD-003 §8. Newly raised risks are added here with date and owner.

## Not validated (carried forward)

Linux live host; Windows admin tier; Windows Server; ARM64; Windows builds before 24H2; third-party key storage providers; disconnected-network Authenticode. Each remains listed in every release report until validated.
