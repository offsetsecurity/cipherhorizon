# Program: cryptographic estate model (PRD-003 → 0.2.0)

How the work is run. Short on purpose: the substance lives in the documents it links.

## Phases and gates

Each phase produces named documents or code, and ends in a **gate**. Work does not start on the next phase until the gate passes; a failed gate is recorded in the [TRACKER](TRACKER.md) with the reason.

| # | Phase | Roles | Output | Gate (all must hold) | Status |
|---|---|---|---|---|---|
| 0 | **Research** | PM (research), Security Architect (review) | [RESEARCH-003](../product/RESEARCH-003-ecosystem-standards-and-design-inputs.md), [ADR-0014](../decisions/ADR-0014-product-name.md), [STRATEGY-001](../strategy/STRATEGY-001-product-review.md) | Every claim sourced; open questions named with owners; findings carry IDs the PRD cites | ✅ done 2026-09-26 |
| 1 | **Requirements** | PM + Security Architect, jointly | [PRD-003](../product/PRD-003-cryptographic-estate-model.md), [SECARCH-001](../product/SECARCH-001-threat-model-and-security-requirements.md), [REQ-REVIEW-001](../product/REQ-REVIEW-001-joint-review-and-signoff.md) | Every requirement testable; every threat mapped; joint review recorded; RTM has a row per requirement (checked by test) | ✅ baselined 2026-09-26; product-owner approval pending |
| 2 | **Design and handoff** | Engineering lead, Security Architect | [ENG-HANDOFF-002](../product/ENG-HANDOFF-002-estate-model.md), [QA-PLAN-002](../product/QA-PLAN-002-estate-model.md), this program folder | Design decisions recorded with reasons; work packages mapped to requirements and threats; test strategy written before code | ✅ 2026-09-26 |
| 3 | **Build, WP-1 … WP-7** | Engineering; Security Architect reviews per package | Code + tests + ADRs, one commit per package | Per-package gate below | ⏳ |
| 4 | **UX and UI, WP-8** | UX (design doc first), Engineering | `UX-DESIGN-002`, UI, extended journey | UI gate below | ⏳ |
| 5 | **QA and release, WP-9** | QA (independent of the package authors' tests), PM | QA report, release report, changelog | Release gate below | ⏳ |

## Per-package gate (WP-1 … WP-7)

1. Requirements in scope have RTM rows moved to `in-progress`, then `done` **only** with named tests.
2. `go build`, `go vet`, `golangci-lint`, `go test ./...` green (Windows and cross-compile for every release platform); no new dependency without an ADR.
3. Every SR assigned to the package has its test **and** its mutation check performed and recorded (guard removed → test fails → guard restored).
4. Security Architect review recorded in the TRACKER (for WP-3 the written syscall review).
5. Docs touched in the same commit; CHANGELOG `[Unreleased]` entry.
6. Ready to commit as one commit per package with the requirement IDs in the message. Commits are made **when the product owner asks** (the gate is the recommended commit point); **no push, no tag** — those are owner actions.

## UI gate (WP-8)

Design document reviewed against REQ-UI-1…8; hostile-string fixtures render inert in every new view; journey script passes with new checks; `security.sh` passes; screenshots refreshed; keyboard and contrast checks.

## Release gate (WP-9)

RTM: every P0 `done`, every P1 `done` or `deferred` with PM sign-off; QA report has no open Sev-1/Sev-2; success measures M1–M7 measured and reported (pass or an honest fail); the product owner approves; docs and changelog complete. Tagging and publishing remain owner actions.

## Severity definitions (QA)

| Sev | Meaning | Example |
|---|---|---|
| 1 | Data loss, secret exposure, false auto-confirmed link, security control bypass | private key parsed; migration drops a scan |
| 2 | Wrong result presented as fact; crash on valid input | key length shown for a certificate that has none |
| 3 | Degraded but correct; unclear wording; performance below target | explanation missing a matched value |
| 4 | Cosmetic | alignment |

## Roles

| Role | Responsibility |
|---|---|
| Product owner (the user) | Approves scope and decisions; owns naming/trademark, GitHub owner, SECURITY contact, tagging and publishing |
| Product Manager | Requirements, priorities, acceptance criteria, PM sign-off on any change to a P0 |
| Security Architect | Threat model, security requirements, design and package reviews, syscall review |
| Engineering | Design, implementation, tests, tracker upkeep |
| UX | Design document and UI |
| QA | Test plan, independent verification, QA report |

All roles are currently performed by one assistant under the product owner's direction, which is why gates are mechanical (tests, scripts, invariants) wherever possible rather than dependent on a reviewer's attention. Each recorded review says so.

## Change control

A change to a requirement is a change to the PRD §12 change log, an RTM update and, if it touches a threat, a SECARCH-001 update — in the same commit. `TestRequirementsTraceability` and `TestSecurityRequirementsAreCovered` fail if the documents drift apart.
