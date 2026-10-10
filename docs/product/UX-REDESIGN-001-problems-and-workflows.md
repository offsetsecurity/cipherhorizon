# UX-REDESIGN-001: Prioritized problems, redesigned workflows, and the PM gate

| | |
|---|---|
| **Builds on** | [UX-AUDIT-001](UX-AUDIT-001-current-state-and-research.md) (Phases 1–3: inventory, research, audit) |
| **Covers** | Phase 4 (prioritized problems), Phase 5 (redesigned workflows), Phase 6 (Product Manager gate) |
| **Status** | **Gate — not yet approved for visual design or implementation.** This document stops at the gate the brief itself specifies; Phases 7–14 (visual design, design system, branding, build, test, QA, final review) do not start until the open questions at the end are resolved. |
| **Personas** | Carried forward unchanged from PRD-001/PRD-002, not reinvented: **Priya** (PQC migration lead — fleet-wide planning), **Marcus** (SRE — operates and monitors specific systems), **Dana** (auditor — needs evidence and export, not day-to-day operation) |

---

## Phase 4 — Prioritized problems

Severity guide: **P0** = fundamental product/UX problems that limit what the product can be used for, not just how it looks. **P1** = major usability/capability gaps that make the product harder to use than it should be. **P2** = real but lower-stakes improvements and polish. Nothing is listed to create work — every row traces to a specific observation in UX-AUDIT-001.

### P0 — fundamental product/UX problems

| Problem | User affected | User goal | Current experience | Why it's a problem | Impact | Opportunity |
|---|---|---|---|---|---|---|
| **Two disconnected crypto inventories** (Endpoints vs. Hosts) | Priya, Dana | "What is our organization's crypto posture, everywhere?" | Two separate top-level sections, two separate dashboards-worth of KPIs, zero cross-links; the fleet Dashboard, trend, "needs attention," and CSV export only ever see TLS endpoints | A user assessing org-wide posture must know both pages exist and mentally combine two numbers themselves; a host's PQC exposure is invisible to the one page (Dashboard) built to answer "what needs attention" | Undermines the product's core promise ("all your cryptographic needs in one place") for any org using both host inventory and TLS scanning | Unify into one fleet view without inventing a relationship the data doesn't support (§ Phase 5.1) |
| **No triage/status workflow on findings** | Marcus | "Stop showing me the same accepted-risk finding every single scan" | Every finding is recomputed fresh every scan; nothing distinguishes new / acknowledged / accepted-risk / resolved | At fleet scale, a tool that can't remember "we already decided about this" trains users to stop reading findings at all — the exact failure mode the research names as most consequential for findings-heavy tools | Directly threatens whether the product stays useful past initial setup | Add a lightweight, evidenced triage state (§ Phase 5.2; flagged as new backend capability, see open questions) |
| **No fleet-wide prioritized action list** | Priya | "Across everything we scan, what's the highest-value fix to make first?" | Per-endpoint "what to do next" exists; nothing ranks across endpoints. The Dashboard's "needs attention" list is worst-first by band/level, not by fix-value | Migration planning (Priya's actual job) has no home in the product today — she'd have to build this herself from the CSV export | This is the single most-requested shape of feature in the PQC-tooling research (Discovery → **Planning**) and the product has Discovery only | Rank using data the backend already computes (severity × evidence tier × HNDL exposure) — no new scan capability needed |
| **CLI and web are not one product** | Marcus (ad-hoc CLI use), Priya (expects continuity) | Scan something once, keep the result, regardless of which entry point was used | `tls scan` (CLI) never persists; `run` (host inventory) has no server-triggered path — both dead-end outside the persistent product | A security engineer's natural first move (CLI scan against a box they're worried about) produces a result that vanishes, breaking the "one place to see everything" value proposition from the very first interaction | Erodes trust in the tool as the source of truth | Bridge with an explicit, opt-in persistence path (§ Phase 5.7; flagged as new capability, see open questions) |

### P1 — major usability/capability problems

| Problem | User affected | User goal | Current experience | Why it's a problem | Opportunity |
|---|---|---|---|---|---|
| Overview tab has no single "the one thing to act on" framing | Marcus, Priya | Understand this endpoint's status in seconds, not by reading five sections | Three dimension rows, a 5-segment scale, a PQ-group list, remediation list, and sources are all shown at once with equal visual weight | Directly contradicts "optimize for understanding and action" (brief principle 8); a returning user re-derives the same conclusion every visit | Lead with one verdict + top action; push supporting detail behind progressive disclosure |
| Hygiene deduction doesn't link to its Findings-tab card | Marcus | See the evidence behind a specific point deduction | User must manually switch tabs and search by rule ID | A cheap, currently-broken drill-down (Phase 3, U-2) | One-line fix: make the deduction row a link |
| Diff ("what changed") shows raw technical strings with no links back | Priya (tracking migration progress over time) | Understand *why* a value changed, not just that it did | Before/after values shown as plain text | Breaks the otherwise-strong evidence-drilldown pattern at exactly the point Priya needs it most (tracking progress) | Route diff rows through the same badge/detail components used elsewhere |
| Certificate expiry is one fact among many | Marcus, Priya | See what's about to break, ranked by urgency | KPI tile + table column + chip; no dedicated expiry lens | The industry's compliance ground is shifting fast (47-day max validity by 2029) and this product doesn't yet treat expiry with matching urgency | Elevate to a first-class filtered view; needs no new data, only new emphasis |
| Scans page is a flat audit log promoted to a top-level nav item | Everyone | — | Every scan, filterable by status, little decision value | Occupies a full nav slot without helping anyone decide anything | Demote to secondary (an activity log reachable from context), freeing IA budget for higher-value surfaces |
| No loading/skeleton state on any page | Everyone | Know the product is working, not broken, while data loads | Blank `<main>` until first fetch resolves | On a slow network or large fleet, indistinguishable from a hang | Add a shared skeleton/loading primitive to the design system (Phase 8) |

### P2 — improvements and polish

| Problem | Opportunity |
|---|---|
| Host detail's "no CBOM yet" empty state has no action button, inconsistent with the rest of the app | Match the established empty-state-plus-CTA convention |
| "Matched by {rule}" shown as unexplained internal jargon | Add a one-line plain-language gloss or tooltip |
| No spacing/layout scale (ad hoc `rem` values, three fixed grid presets) | Formalize as part of the design system (Phase 8) — not urgent enough to block anything |
| No product logo image, no footer, no company identity | Addressed directly in Phase 9 (branding), not a UX defect on its own |
| `spark()` sparkline helper appears unused by any current view | Verify and remove if genuinely dead code (housekeeping, not a redesign driver) |

---

## Phase 5 — Redesigned workflows

Per the brief: workflows first, not screens. Each journey below spans the *whole* product as needed — it does not assume today's navigation or page boundaries. Screens are decided in Phase 7, only after these are confirmed.

### 5.1 "What is our crypto posture, right now?" (Priya, Dana — the core repeat journey)

- **Starting point**: any session start; today this is the Dashboard, and stays the Dashboard.
- **Intent**: one honest answer, not two hunts through separate sections.
- **Redesign**: the Dashboard becomes fleet-wide across *both* evidence types (network-observed TLS endpoints and package-derived host inventories), presented as one inventory with a visible type distinction per row — **not** a fabricated merge. If a host asset and a TLS endpoint happen to be the same physical machine, the product does not guess that; a user may optionally assert the link themselves (§5.1a), and only a user-asserted link is ever shown as one asset. Everything else stays two clearly-typed rows in one list, one dashboard, one CSV export, one trend — solving the *invisibility* problem (P0-1) without inventing evidence the scans don't support (non-negotiable principle 10).
- **Information needed**: total assets by type, how many scanned/never-scanned, count exposed to HNDL, count with critical/high findings, certs expiring soon, and — new — the fleet-wide prioritized action list (P0-3).
- **Decision**: where do I look first? The prioritized action list answers this directly instead of making the user infer it from four separate KPI tiles.
- **Next actions**: click into the ranked item → asset detail (5.3); or "Scan all" / "Add assets."
- **Exit points**: navigate to a specific asset, or to the migration-planning view (5.4) for the fuller ranked list.

**5.1a — Manually linking a host asset to a network endpoint.** A small, explicit, reversible action ("This is the same machine as…") on either asset's detail page, never inferred automatically. Once linked, both are shown together in that asset's detail page as two evidence sources, each still labeled by how it was obtained (observed via scan / reported via uploaded CBOM) — this preserves the evidence-tier discipline (non-negotiable principle 10) while solving the fragmentation problem (P0-1) honestly.

### 5.2 "Triage a finding so it stops nagging me" (Marcus)

- **Starting point**: a finding on an asset (from the asset detail page, or directly from the fleet action list).
- **Intent**: record a decision once, have the product remember it.
- **Actions**: on a finding, a lightweight status action — **Acknowledge** (seen, not yet decided), **Accept risk** (decided, won't fix, optionally with a note and an expiry so it re-surfaces later rather than being silently forgotten forever), **Resolved** (will be re-verified automatically on the next scan — if the finding still fires, it reopens; findings are never manually marked "fixed" while still detected, since that would contradict the product's own evidence discipline).
- **Information needed**: who/when a decision was made (for Dana's audit trail), and why (freeform note).
- **Decision**: acknowledge vs. accept-risk vs. do nothing yet.
- **Result**: the fleet action list and per-asset finding count reflect triage state (e.g., "3 new, 2 accepted risk" rather than a flat "5 findings"), so re-surfacing is meaningful, not noise.
- **Next actions**: filter the findings view by triage state; export triage history for an audit.
- **Exit points**: back to the asset, or to the fleet list, unchanged navigation otherwise.
- **Flagged for the gate**: this requires a new persisted field/table (finding status) — new backend capability, not just a UI change. Confirmed scope needed (see Open Questions).

### 5.3 "Investigate one asset, from summary to evidence" (Marcus, Dana)

- **Starting point**: any list or the fleet action list.
- **Intent**: understand this one asset's posture and, if needed, get to the exact evidence behind any specific claim.
- **Redesign of the existing Overview**: lead with one verdict card — PQC readiness *and* TLS hygiene shown together but never combined into a single misleading number (preserving the audit's identified strength) — plus the single highest-priority next action. Dimension detail, the PQ-group list, and sources move to a secondary, expandable position rather than sharing top billing with the headline.
- **Fixed drill-downs** (P1, cheap, no backend change): every hygiene deduction links directly to its Findings-tab card; every diff row links back to the finding or TLS-detail row it changed; "Matched by X" gets a one-line plain gloss.
- **Decisions**: is this asset acceptable as-is, does it need a fix, or does it need triage (hands off to 5.2)?
- **Next actions**: rescan, edit schedule, download CBOM, triage a finding, or (for a linked asset, §5.1a) switch between its TLS-scan evidence and its host-inventory evidence without leaving the page.
- **Exit points**: back to whichever list the user arrived from (preserve return context — a real, currently-missing nicety); "download CBOM" as a terminal export action.

### 5.4 "Plan a PQC migration across the fleet" (Priya)

- **Starting point**: Dashboard's prioritized action list, or a dedicated migration view reached from it.
- **Intent**: a ranked list of what to fix first, fleet-wide, with visible progress over time.
- **Information needed**: every open finding across every asset, ranked by severity × evidence tier × HNDL exposure (computable today with zero new scan capability — this is a view over existing data, not a new backend feature); trend of the ranking over time (the existing 14-day trend, generalized to any range and to the ranked list, not just counts).
- **Decisions**: what to fix next; whether current pace is on track.
- **Actions**: triage from this view directly (hands off to 5.2); export the plan (CSV, extending the existing export).
- **Exit points**: into a specific asset for detail; out to an exported plan for sharing outside the tool.

### 5.5 "Generate an audit artifact" (Dana)

- **Starting point**: an asset detail page, or a fleet-level export action.
- **Intent**: defensible evidence, not just a summary — a CBOM with provenance, and (new, from 5.2) a triage/decision trail.
- **Actions**: unchanged CBOM download (already just built for TLS endpoints this round; extended to Hosts, closing the asymmetry named in P1); CSV export (unchanged, extended with triage-state columns once 5.2 exists).
- **Exit points**: terminal — the artifact leaves the product.

### 5.6 "Add and configure ongoing monitoring" (Marcus, first-time and repeat)

- **Starting point**: empty state, or "Add" action from the unified list (5.1).
- **Intent**: get an endpoint or a host under continuous watch with minimal friction.
- **Actions**: unchanged for TLS endpoints (single/bulk add, already good); for hosts, the redesign should close the gap named in P0-4/P1 by offering an explicit "how do I get a host's inventory in here" path from the UI itself (documentation and copy, not necessarily a new scan capability — see 5.7 for the deeper option), rather than leaving it entirely to out-of-product CLI knowledge.
- **Decisions**: scan once, or schedule; which rescan interval.
- **Exit points**: into the new asset's detail page.

### 5.7 "Use the CLI and not lose the result" (Marcus, ad-hoc)

- **Starting point**: a terminal, `tls scan` against a target the user is worried about right now.
- **Intent**: get an answer now, without necessarily standing up the full server — but not have that answer vanish if it turns out to matter.
- **Two options, deliberately left open for the gate rather than decided here** (this is a scope/cost decision, not a UX one):
  - **(a) Lighter touch**: the CLI's one-shot output clearly tells the user this result is not persisted and how to get persistence (point at `serve`), removing the silent surprise without adding new capability.
  - **(b) Deeper fix**: give `tls scan` an opt-in flag to write its result into a running server's store (or a local store file), so the same scan a user ran ad hoc shows up in history/trend without rerunning it through `serve`.
- **Flagged for the gate**: (b) is new backend capability; (a) is copy-only. Confirmed choice needed (see Open Questions).

---

## Phase 6 — Product Manager gate

Acting as PM, challenging the above before anything is built.

**Are these the right problems?** Yes, with one caveat: P0-2 (triage) and P0-4/5.7b (CLI persistence) are the two items in this list that require *new backend capability*, not just UX/IA rework. Everything else in P0 and P1 is achievable by reorganizing and better presenting data the product already computes — which is the cheaper, lower-risk, higher-confidence majority of the redesign. Rearranging existing capability into one coherent product is the bulk of the value here; the two new-capability items are real but should be confirmed explicitly rather than assumed, per non-negotiable principle 11 (preserve existing functionality) and the general house rule against unjustified new work.

**Are we solving user problems or rearranging UI?** The P0 list is not screen-level — it's information-architecture and product-scope level (what data exists where, what's connected to what). That's the right altitude for a product-wide redesign per the brief's own instruction not to start with screens.

**Are we prioritizing the highest-value improvements?** The two structural P0s (fragmented inventory, no triage) are what the research independently flags as the biggest gaps in this class of tool, not items invented to fill a quota — both were found by two independent methods (direct hands-on use, and separate code-level inventory) before being cross-checked against industry research.

**Is the workflow simpler?** For the core repeat journey (5.1), yes — one inventory, one ranked list, instead of two dashboards a user has to remember to check separately. For the CLI question (5.7), simplicity is exactly what's contested — hence leaving it open rather than deciding unilaterally.

**Does it communicate risk clearly, and help users know what to do next?** The fleet-wide prioritized action list (5.1, 5.4) is the direct answer to "help users understand what to do next" at the scale (fleet, not one endpoint) where the product currently has no answer at all.

**Does it differentiate from generic TLS scanners?** Yes, more than today: no competitor found in research combines active TLS assessment, host-package CBOM, and PQC readiness into one fleet-wide, cited, evidence-tiered inventory with migration planning. Today's product has the pieces; this redesign is what turns them into that combination rather than three adjacent tools sharing a nav bar.

**Are we building unnecessary features?** Explicitly avoided: no auto-merging of host and endpoint identities (would fabricate evidence), no combined single score replacing hygiene/readiness (would hide the exact risk the split exists to show), no speculative features not traced to a named P0/P1 problem.

**Verdict**: the workflows are approved to proceed to visual design **once the two new-backend-capability items and the branding depth are confirmed** — see below. Everything else in this document can proceed as scoped.

---

## Decisions (confirmed at the gate)

1. **Findings triage/status (P0-2, §5.2)** — **build it now.** New backend capability: a persisted status per finding, with an audit trail.
2. **CLI/web persistence gap (P0-4, §5.7)** — **lighter touch.** CLI output clearly states the result isn't saved and points to `serve` for persistence; no new persistence capability this round.
3. **Host/endpoint linking (§5.1a)** — **build it now.** A small, explicit, reversible, user-asserted link action; never auto-inferred.
4. **Branding depth (Phase 9)** — **subtle.** Footer credit + About-page mention and link to offsetsecurity.net; the product keeps its own identity as primary.

Scope for Phase 7 onward: all of P0 and P1 in one pass (the two new-capability items are now confirmed in scope; nothing here was deferred to a checkpoint).
