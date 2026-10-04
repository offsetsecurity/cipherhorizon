# QA-PLAN-005: Focused flows

Verifies [PRD-005](PRD-005-product-focus-and-flows.md) as built per [ENG-HANDOFF-004](ENG-HANDOFF-004-focused-flows.md).
Results go to QA-REPORT-004 and the RTM.

## 1. Levels

| Level | Tooling | Scope |
|---|---|---|
| Unit / API | `go test` | Inventory rows (quantum status per kind, places, filters), summary counts, whole-inventory CBOM (merge, seen-in, imported opt-in, size cap, schema-valid 1.6 and 1.7), OpenAPI parity |
| Vocabulary | `go test ./web` | Forbidden words absent from primary-surface files (REQ-LANG-2), with a negative control |
| Browser journey | `testing/e2e/journey.mjs` (+ phases) | First run → one action to a report (F-M1); menu has four entries (F-M2); every old route lands on the right page (F-M6); report first screen shows summary and Fix first; sections closed unless problem; "Why and sources" opens; report visible words vs the T1 baseline (F-M3); Inventory summary, tabs, filter, Download CBOM in ≤ 2 clicks (F-M4); Systems with Decisions; 390 px and dark; hostile text in the new pages |
| Measurement | `scratchpad/audit.mjs` re-run | Words, first-screen words, controls, page height per page vs RESEARCH-005 §2.3 |
| Security | `testing/e2e/security.sh` | New inventory routes behind token/Origin/Host checks |

## 2. Exit

- every P0 requirement `done` in the RTM;
- F-M1…M6 measured and recorded;
- `go test ./...`, lint, journey and `security.sh` green;
- QA-REPORT-004 written, including what was not validated.
