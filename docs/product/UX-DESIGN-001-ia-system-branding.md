# UX-DESIGN-001: Information architecture, design system, and branding

| | |
|---|---|
| **Builds on** | [UX-REDESIGN-001](UX-REDESIGN-001-problems-and-workflows.md) (approved workflows, confirmed decisions) |
| **Covers** | Phase 7 (UX/UI design), Phase 8 (design system), Phase 9 (Offset Security branding) |
| **Backend already shipped for this round** (see git diff): `finding_status` and `asset_links` tables + store methods, `GET/PUT/DELETE /api/v1/assets/{id}/findings...`, `GET /api/v1/findings` (fleet-wide, ranked, filterable), `PUT/DELETE /api/v1/assets/{id}/links/{otherId}`, `GET /api/v1/hosts/{id}/snapshots/{snapshotId}/cbom`, CLI notice update. All covered by new tests (store + server layers). |

## Phase 7 — Information architecture and navigation

**Top-level navigation becomes 4 items** (was 5): **Dashboard | Assets | Findings | About**.

- **Assets** replaces **Endpoints** and absorbs **Hosts** as a type filter, not a separate section — this is the direct fix for P0-1 (fragmented inventory). One list, one add flow (with a choice of "TLS endpoint" or "upload a host CBOM"), one set of filters, type shown per row via a badge. Existing `/assets` and `/hosts` routes and their detail pages keep working (non-negotiable principle 11); the nav and the unified list are what change, not the underlying data model or APIs (host-specific actions like "Upload CBOM" still exist, scoped to host-type rows).
- **Findings** is new: the fleet-wide, filterable (severity/status/asset-kind), triaged findings table the research names as the standard, missing pattern for this class of tool (P0-2, P0-3). Backed entirely by the already-shipped `GET /api/v1/findings`.
- **Scans** is demoted from top-level nav to a contextual link (from the Dashboard's recent-activity area, and from each asset's History tab) — the route and its functionality are unchanged, it simply no longer occupies primary nav real estate for what is fundamentally an audit log (P1, U-4).
- **About** unchanged in position; content gains the branding line (Phase 9) and stays otherwise as-is (it is a genuine strength: honest, cited, plain-language).

**Dashboard** becomes the fleet-wide view across both asset kinds: KPI tiles cover both (with kind-appropriate ones — HNDL exposure and cert-expiry stay TLS-only, since a host asset genuinely has neither), the PQC-readiness donut and hygiene bands stay TLS-scoped (a host doesn't have either scale — showing them for hosts would be exactly the fabricated-single-score mistake Phase 6 ruled out), and a new **"Top priority findings"** panel replaces/absorbs "Needs attention" — the top N rows from `GET /api/v1/findings`, ranked, linking straight to triage.

**Asset detail (unified)**: the same page now renders for either kind, switching its content (TLS tabs vs. host algorithm table) by `asset.kind`, plus:
- A **Linked assets** section (present for either kind): shows any manually-linked asset(s) with a link/unlink action, and — when a link exists — presents both assets' evidence in one place without merging their data (Phase 5.1a).
- The Overview tab is restructured around one verdict + top action, with dimension detail, PQ-group list, and sources moved behind a "Details" disclosure (U-1).
- Every hygiene deduction line becomes a link to its Findings-tab card (U-2). Every diff row links back to its finding (U-3).
- Findings tab gains per-finding triage controls (Acknowledge / Accept risk, with a note) and shows current status as a badge (P0-2, Phase 5.2).
- Host detail's "no CBOM yet" empty state gets its missing CTA (U-5); "Matched by X" gets a one-line gloss (U-6); a "Download CBOM" action is added (closing the host/endpoint export asymmetry) alongside the existing "Download CBOM" the TLS side already has.

**Loading states**: a shared skeleton primitive (Phase 8) replaces "blank until first paint" on every list/detail page (I-3).

## Phase 8 — Design system

The existing token system (color, semantic tone, readiness-level palette, `--radius`) is **kept as-is** — it's already consistent, accessible, and dark-mode-complete (UX-AUDIT-001 §1.5). What's added:

- **A spacing scale**: `--space-1` through `--space-6` (4/8/12/16/24/32px), replacing ad hoc per-rule `rem` values going forward (existing rules are not mass-rewritten — non-negotiable principle 10 — new/touched CSS uses the scale).
- **A shared `.skeleton` component**: a subtle pulsing placeholder block, used for list/detail loading states.
- **A shared `.linkbtn`-style inline link treatment** for the new deduction→finding and diff→finding cross-links, visually distinct from a button but clearly actionable.
- **A `.kind-badge` component**: the small type badge ("Endpoint" / "Host") used throughout the unified Assets list and asset detail.
- **A triage-status badge** (new semantic states: "new" [neutral/default, effectively unbadged], "acknowledged" [info tone], "accepted risk" [warn tone]) — reuses the existing tone tokens, no new colors introduced.

Nothing here replaces the existing badge/table/modal/toast components (`ui.js`, `charts.js`) — they are reused throughout the redesigned pages, per the brief's instruction to build reusable components rather than independent per-screen styling.

## Phase 9 — Offset Security branding (subtle, per the confirmed decision)

- **Footer** (new — none existed before): added to the app shell, present on every page. Content: `CipherHorizon is an open-source project from Offset Security.` linking to `https://offsetsecurity.net/`, plus the existing version string.
- **About page**: a new short line near the top ("This installation") section crediting Offset Security with the same link — no invented company history, team, or claims beyond "developed by," matching brief rule 6 (do not invent company information) and the confirmed "subtle" scope.
- **Favicon/tab icon**: the provided Offset Security logo is used for the browser tab icon; the product's own header mark (the ◈ glyph + "CipherHorizon" wordmark) stays the primary, most prominent identity in the header, unchanged — this is what "subtle" (vs. "prominent," the rejected option) means concretely: Offset Security is credited, not co-branded into the primary nav.
