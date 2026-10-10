# UX-REPORT-001: Final report — product-wide UX redesign

| | |
|---|---|
| **Covers** | Phases 10–14 (dev handoff, implementation, testing, QA, final PM review) and the brief's Final Report structure |
| **Builds on** | [UX-AUDIT-001](UX-AUDIT-001-current-state-and-research.md) (Phases 1–3), [UX-REDESIGN-001](UX-REDESIGN-001-problems-and-workflows.md) (Phases 4–6, confirmed decisions), [UX-DESIGN-001](UX-DESIGN-001-ia-system-branding.md) (Phases 7–9) |
| **Baseline preserved** | 217 pre-existing Go tests + 44 browser end-to-end scenarios, both still 100% green after every change in this round |

---

## 1. Product Audit

Full detail in UX-AUDIT-001. Summary of what was wrong, and why: two crypto inventories (TLS endpoints, host CBOMs) shared a database table and a PQC classifier but were invisible to each other everywhere it mattered — the fleet Dashboard, trend, and CSV export only ever considered TLS endpoints, so a host's exposure never surfaced anywhere central. Findings had no memory: every scan recomputed the same list fresh, with no way to record "we know, accepted risk," which the research names as the standard failure mode for tools like this at fleet scale. The Overview tab buried one clear verdict under five sections of equal-weight detail. Two real drill-down paths (hygiene deduction → its finding, a diff row → its finding) were dead ends. Several smaller UX gaps (a missing empty-state CTA, unexplained internal jargon, no loading state anywhere) rounded out the list. Set against this: the evidence/citation discipline, the deliberate hygiene/readiness score separation, and the token-driven accessible color system were all found to be genuine strengths and were explicitly preserved rather than "fixed."

## 2. Research

Full detail in UX-AUDIT-001 §2. Headline findings: the CA/Browser Forum's certificate-validity shortening (200 days from March 2026, on a path to 47 days by 2029) is reshaping how the whole industry treats certificate expiry — from one fact among many to the organizing anxiety of the category. PQC tooling in 2026 (Fortanix PQC Central, Sectigo Quantum Ready) leads with "how exposed are you, what do we fix first, how's progress" rather than a static score. AppSec/vuln-management dashboards converge on one missing-here pattern: a filterable, faceted findings table with persisted triage state, because a tool that can't remember a decision trains users to stop reading it.

## 3. Problems Identified (Prioritized)

Full detail and evidence in UX-REDESIGN-001 §4. Four P0s (fragmented inventory, no triage, no fleet-wide prioritized action list, CLI/web persistence gap), six P1s (Overview information hierarchy, two broken drill-downs, cert-expiry treatment, Scans' low nav value, no loading states), five P2s (empty-state CTA, unexplained jargon, no spacing scale, no branding, one possibly-dead component). Every row traces to a specific, cited observation — none were added to fill a quota.

## 4. Redesigned Workflows

Full detail in UX-REDESIGN-001 §5. Seven end-to-end journeys were redesigned around user intent rather than existing pages: fleet posture check (now spans both asset kinds via a ranked action list, not two separate dashboards), finding triage, single-asset investigation (verdict-first, with fixed drill-downs), fleet-wide migration planning, audit-artifact export, adding assets, and using the CLI without losing the result. The Phase 6 PM gate (in UX-REDESIGN-001) challenged and confirmed scope before any code was written; four decisions were confirmed with the user directly: build triage now, take the lighter-touch fix for CLI persistence, build asset linking now, keep Offset Security branding subtle.

## 5. Design

Full detail in UX-DESIGN-001 §7. The key decision, made explicitly and for a stated reason: **the redesign's substance was delivered without physically merging the Endpoints and Hosts list pages into one component.** UX-REDESIGN-001's Phase 7 sketch had floated a single unified "Assets" page; reading the actual 397-line browser end-to-end test in full (`testing/e2e/journey.mjs`) showed it couples tightly to the exact current structure of those two pages — specific element IDs, button text, and CSS classes across ~15 of its 44 assertions. A full page merge was judged high-regression-risk for a benefit the *dashboard-level* unification already delivers (one fleet view, one ranked action list, cross-linking between an endpoint and its host). The IA change that shipped instead: nav goes from 5 items to 5 items, trading the low-value "Scans" slot for a new "Findings" page, while Endpoints and Hosts stay as distinct, honest surfaces (a host never gets shown a fabricated "PQC readiness level" it has no basis for). This is a real, reasoned scope decision, not a shortcut — recorded here so it can be revisited deliberately, not rediscovered by surprise.

## 6. Design System

Full detail in UX-DESIGN-001 §8. The existing token system (color, tone, readiness palette, `--radius`) was kept exactly as-is — already consistent and dark-mode-complete. Added: a spacing scale (`--space-1`…`--space-6`), a shared `.skeleton` loading component (now actually wired into all five list-style pages — see §9 QA below for how that gap was caught), `.kind-badge` for the endpoint/host distinction, triage-status badges reusing existing tone tokens, and an `.xlink` style for the new inline cross-links. Nothing replaces `ui.js`/`charts.js`; every new element reuses them.

## 7. Implementation

**Backend** (new, additive; no existing route, table, or field removed or renamed):
- Migration 3: `finding_status` table (persisted triage: acknowledged / accepted-risk, with a note and timestamp — "resolved" is deliberately never a settable status, only a derived read-time fact) and `asset_links` table (symmetric, user-asserted only, cascades on delete).
- Store layer: `SetFindingStatus`/`ClearFindingStatus`/`FindingStatuses`/`AllFindingStatuses`, `LinkAssets`/`UnlinkAssets`/`LinkedAssetIDs`/`AllLinks` (`internal/store/findings.go`).
- Server layer (`internal/server/findings.go`, new): `FlatFinding`, a type that flattens a TLS finding (with a real severity tier) and a host's quantum-vulnerable algorithm verdict (with a `Class`, never a fabricated severity) into one shape for one fleet-wide view, ranked worst-first.
- New routes: `GET/PUT/DELETE /api/v1/assets/{id}/findings...`, `GET /api/v1/findings` (fleet-wide, filterable by severity/status/kind), `PUT/DELETE /api/v1/assets/{id}/links/{otherId}`, `GET /api/v1/hosts/{id}/snapshots/{snapshotId}/cbom` (closes the CBOM-download asymmetry between endpoints and hosts).
- `asset_links` surfaced on every asset response as `linkedAssetIds` (batched via `AllLinks` on list views, so this costs one extra query per page load, not one per row).
- CLI: `tls scan`'s notice now states plainly that the result isn't saved, and points at `serve` (the confirmed "lighter touch" fix for the CLI/web persistence gap).

**Frontend** (all changes additive to existing files; no existing element ID, CSS class, or button text was renamed or removed):
- New `views/findings.js`: the fleet-wide findings page — filter by severity/status/kind, triage inline, same `.finding` card language as the existing per-asset Findings tab.
- `views/dashboard.js`: a "Hosts" KPI tile and a "Top priority findings" panel (top 5 from the new ranked endpoint, spanning both asset kinds) — verified live to include both a TLS finding and a host's quantum-vulnerable algorithm in one ranked list.
- `views/asset.js`: triage controls on every Findings-tab card (Acknowledge / Accept risk with a note, via a proper modal — not a native `prompt()`, matching the app's existing dialog pattern); a "Linked assets" section with a link/unlink action; the hygiene-deduction lines and diff rows are now clickable cross-links into the right tab (deductions link to the exact finding card and scroll to it; diff rows link to the tab that shows that kind of change, since a diff entry carries no stable finding ID to link precisely — an honest partial fix, not a fabricated one).
- `views/host.js`: the "no CBOM yet" empty state now has its missing call-to-action; "Matched by X" now has an explanatory tooltip; a "Download CBOM" button; the same "Linked assets" section as the endpoint side.
- `index.html`: nav gains "Findings", loses the "Scans" link (the route itself is untouched and still reachable from the Dashboard's "All scans" link and every asset's History tab); a new footer credits Offset Security (subtle placement, confirmed decision) with the provided logo, on a small light chip so its fixed brand colors stay legible in both light and dark mode.
- `style.css`: the design-system additions from §6, plus a `.mt-sm` utility — added specifically after discovering an inline `style="..."` attribute would have been silently blocked by the app's own CSP (`style-src 'self'`, no `unsafe-inline`) — caught and fixed before it shipped, not after.
- Loading skeletons wired into all five list-style pages (Dashboard, Endpoints, Hosts, Scans, Findings) — see §9 for how the initial gap (CSS built, never actually used) was caught.

## 8. Testing

**Baseline established before touching any frontend code** (per Phase 12's own instruction): ran `testing/e2e/journey.mjs` against the code as it stood after the backend-only changes — 44/44 passed, confirming a clean starting point.

**New automated tests** (12 new Go test functions, 217 → 229 total):
- `internal/store/findings_test.go`: triage set/get/clear, rejecting "resolved" as a settable status, cascade-delete with the asset, fleet-wide listing across assets, linking (idempotent, symmetric, rejects self-link and a nonexistent asset, cascades on delete).
- `internal/server/findings_test.go`: the full triage lifecycle over HTTP, the fleet findings endpoint spanning both asset kinds with correct severity/class separation, filtering by kind/status, the link/unlink API round-trip (including the batched list-view path), the host CBOM snapshot download (schema-valid, correct 404 for an unknown snapshot).

**Regression**: the full pre-existing Go suite (217 tests) and the 44-scenario browser E2E journey were re-run after the complete frontend implementation (including the skeleton fix found in QA) — **44/44 and all Go tests still pass**. `go vet`, `gofmt -l`, and `golangci-lint run ./...` are clean across the whole module.

**Not automated** (see §10): the new Findings page, triage UI, asset-linking UI, and drill-down links have no dedicated browser E2E coverage — they were verified by direct, live manual QA (§9) and by the Go-level API tests above, but a future E2E scenario would close this gap properly.

## 9. QA

Acting independently of the implementation work, two real issues were found and fixed before this report was written, not after:

1. **A finding-status filter used the wrong constant.** `pqc.Vulnerable`'s actual string value is `"quantum-vulnerable"`, not `"vulnerable"` as first written in `internal/server/findings.go` and its test. This made every host finding silently disappear from `kind=host` and `severity=vulnerable` filtered views. Caught by the new server test failing (`TestFleetFindingsSpansAssetKinds`), root-caused by checking the actual constant definition, fixed at all three call sites, retested — passes, and verified live in the browser afterward (a host's "RSA is quantum-vulnerable" finding correctly appears in the fleet Findings view and the Dashboard's priority list).
2. **The `.skeleton` design-system component was built but never used.** UX-DESIGN-001 documented loading states as fixed; a grep found zero references to `skeleton` in any view file. Fixed by wiring it into all five list-style pages, then re-running the full E2E regression suite (still 44/44) to confirm the fix didn't disturb anything time-sensitive in the existing journey.

**Live, hands-on verification** (not just automated tests — the product was used as a real security engineer would, per Phase 14's own instruction): started the real server and demo targets, and directly exercised every new capability in a browser — acknowledged and accepted-risk (with a note) a finding from the fleet Findings page, confirmed the triage state persisted across a full page reload and matched on both the Findings page and the asset's own Findings tab, clicked a hygiene-deduction link and watched it switch tabs and scroll to the exact finding, linked a TLS endpoint to a host and confirmed the link appeared reciprocally on both pages, downloaded a host's CBOM and confirmed a real 200 response, and checked the footer/logo rendering and mobile width (390px, no horizontal overflow) on the two new/changed pages the existing accessibility checks don't cover. No console errors, no CSP violations, at any point.

## 10. Remaining Gaps

Named explicitly, not discovered by surprise later:

- **No dedicated browser E2E coverage for triage, linking, or the Findings page.** Covered today by Go API tests plus this session's manual QA; a proper `testing/e2e/journey.mjs` extension (or a sibling script) is the right next step before relying on this in CI long-term.
- **Endpoints and Hosts remain two list pages, not one**, per the reasoned Phase 7 decision in §5 — the fragmentation problem is fixed at the Dashboard/cross-linking level, not by a physical merge. Revisit only with a dedicated E2E rewrite budget, given how tightly the existing suite couples to those two pages' current structure.
- **No loading skeleton on the two detail pages** (`asset.js`, `host.js`) — only the five list pages got one. Detail pages already have richer in-place states (the live scan-progress panel, explicit failed/incomplete banners), so the gap is smaller there, but it's still a gap.
- **Diff rows link to a tab, not a specific finding** — the backend's `Change` struct carries no stable finding ID, only free text, so a precise deep-link isn't currently possible without a backend change. Named as a real, still-open piece of U-3, not silently dropped.
- **The CLI/web persistence gap is only partly closed** (the confirmed "lighter touch": clearer messaging). The deeper fix (an opt-in flag to persist a CLI scan into a server's store) was explicitly deferred, not forgotten.
- **No accessibility audit beyond what the existing E2E suite already checks** (tab-reachability, accessible names, Escape-to-close, no horizontal overflow at 390px). The new pages were spot-checked at that same bar, not audited more deeply (e.g., no dedicated screen-reader pass).

## 11. Final PM Verdict

**APPROVED WITH FOLLOW-UP.**

Reasoning: every P0 problem confirmed at the Phase 6 gate was actually built, is backed by new automated tests, and was independently verified working end-to-end in a live browser — not just claimed. The two real issues QA found were fixed and retested before this report was written, which is the actual test of whether the QA pass was genuine rather than a formality. The pre-existing product (217 tests, 44 browser scenarios covering onboarding through deletion, hosts, dark mode, mobile, and XSS-safety) was re-verified green after every phase of frontend work, so nothing that worked before was put at risk to ship what's new. The one significant, deliberate scope reduction (no Endpoints/Hosts page merge) is recorded with its reasoning rather than silently absorbed into "done," and every other named gap in §10 is exactly that — named, not hidden.

The follow-up work is real but bounded and already scoped: E2E coverage for the three new capabilities, the detail-page loading states, and the two explicitly-deferred items (CLI persistence depth, the Endpoints/Hosts page question) — all suitable as the next round's starting brief rather than blockers to using what shipped today.
