# UX-AUDIT-001: Current-state inventory, industry research, and product audit

| | |
|---|---|
| **Covers** | Phase 1 (Understand), Phase 2 (Research), Phase 3 (Product Audit) of the product-wide UX redesign brief |
| **Method** | Full read of every frontend/backend file (two independent full-repo passes), the product run and used hands-on in a browser against live demo endpoints, and primary-source industry research (not vendor marketing alone) |
| **Followed by** | [UX-REDESIGN-001](UX-REDESIGN-001-problems-and-workflows.md) — prioritized problems (Phase 4), redesigned workflows (Phase 5), PM gate (Phase 6) |

---

## Phase 1 — Understand: what the product actually is today

### 1.1 Shape of the product

One Go binary (`cipherhorizon`), four capabilities, two of which persist state and two of which don't:

| Capability | Entry point | Persists to the store? |
|---|---|---|
| Host package/crypto inventory (CBOM) | CLI `cipherhorizon run` only | No — output is a file; only reaches the web product via manual upload |
| Active TLS/PQC scanning | CLI `tls scan`, or the web UI's Endpoints | CLI: no (stateless, one-shot). Web: yes |
| Web dashboard/fleet view | `cipherhorizon serve` | — |
| CBOM export (TLS-scan-derived) | CLI `tls scan --cbom`, or `GET /api/v1/scans/{id}/cbom` | Re-derives from a stored scan; the CBOM itself isn't stored |

This asymmetry matters for the redesign: **the CLI and the web product are not two views onto the same thing** — a security engineer running `tls scan` ad hoc against a box gets no history, no trend, no fleet context, even though it's the identical scan engine `serve` uses internally.

### 1.2 The web product's navigation and pages

Five top-level nav items (`Dashboard`, `Endpoints`, `Scans`, `Hosts`, `About`), plus two drill-down-only routes (`Endpoint detail`, `Host detail`) with no nav entry of their own.

| Page | What it is | Data model it draws from |
|---|---|---|
| **Dashboard** | Fleet KPIs (endpoint count, scanned count, HNDL-exposed count, critical/high findings, certs expiring), a PQC-readiness donut, a 14-day readiness trend, a TLS-hygiene band distribution, a "needs attention" worst-first list, recent scans | TLS endpoints only |
| **Endpoints** | The TLS-endpoint inventory: add (single/bulk), filter, sort, multi-select, bulk-scan, CSV export | TLS endpoints |
| **Endpoint detail** | Overview (readiness + hygiene + "what to do next"), TLS details (protocol/suite/group/cert tables), Findings, History+diff | One TLS endpoint |
| **Scans** | A flat, filterable log of every scan ever run, across every endpoint | TLS scans (audit trail, not a decision surface) |
| **Hosts** | A *separate* inventory: machines whose package-derived CBOM has been uploaded, with quantum-vulnerable/-safe counts | Host assets (CBOM ingest) |
| **Host detail** | Algorithm-by-algorithm capability breakdown of one machine, with PQC verdicts and citations | One host asset |
| **About** | The product's own glossary/methodology reference (readiness scale, hygiene formula, what's out of scope, live server config) | Static + `/api/v1/about` |

**The single most consequential structural fact found in Phase 1**: *Endpoints* and *Hosts* are two disjoint inventories that share a database table and a PQC-verdict engine but are invisible to each other everywhere it matters. The fleet Dashboard, the trend chart, the CSV export, and the "needs attention" list only ever consider TLS endpoints — a host's crypto posture (from `cipherhorizon run`) never appears on the Dashboard, never contributes to a fleet-wide number, and there is no link anywhere from a TLS endpoint to "the host this same machine also reported," or vice versa. A user cannot get one number for "our organization's crypto posture" — they get two unconnected ones, and have to know both pages exist.

### 1.3 What one full scan actually produces

A `tlsprobe.Report` (protocols, suites, preference order, key-exchange groups, DH parameters, server features, certificates, what a real current client negotiates, optional HSTS) is judged by `eval.Evaluate` into:
- **35 distinct, cited finding rules** across 7 categories (protocol, cipher, key-exchange, certificate, feature, vulnerability, pqc).
- **Two deliberately orthogonal scores**: TLS hygiene (0–100, classical configuration quality, PQC findings excluded on purpose) and PQC readiness (L0–L4, quantum-computer-era exposure). A server can be hygiene "Strong" and readiness "L0" at once — this separation is a real design strength, not a gap (a combined score would hide exactly the risk — HNDL exposure on an otherwise well-configured server — that PQC readiness exists to surface).
- Every finding is evidence-tiered (`observed`/`inferred`/`registry`/`not-measured`) and cited to a primary source. This discipline is consistently enforced (a test fails the build if any rule lacks a citation) and is a genuine differentiator worth preserving exactly as-is.

### 1.4 What exists but is not surfaced anywhere in the UI

Found by direct code inspection, not assumption:
- A host's raw uploaded CBOM has no download route at all (the storage function exists, `store.HostCBOM`, nothing calls it) — asymmetric with the Endpoint side, which now has CBOM download.
- `cipherhorizon run` (the host inventory collector) has no server-triggered/API equivalent — a host's crypto inventory can only enter the product via a human manually running a separate CLI command elsewhere and uploading the file.
- `tls scan` from the CLI never touches the store, so ad-hoc CLI scans get no history/trend/diff even though `serve`'s internal runner calls the exact same code.

### 1.5 Component and visual-design ground truth

- No frontend framework or build step: hand-rolled `h()` hyperscript helper, lazy-loaded per-route ES modules.
- Color is **already systematically token-driven** (CSS custom properties in `:root`, fully re-mapped for dark mode via `prefers-color-scheme`) and consistently reused for the same semantic meaning everywhere (a "bad" tone always means the same thing on a badge, a KPI tile, or a finding border). This is a real strength worth keeping, not replacing.
- Layout/spacing is **not** systematized: no spacing scale, ad hoc `rem` values chosen per rule, three fixed one-off grid presets rather than a general system.
- No shared loading/skeleton component anywhere — every page is a blank `<main>` between route-in and first paint. Only the live-scan progress panel has genuine designed-for loading UI.
- Empty states exist on 6 of 7 top-level pages, but are inconsistent: Host detail's "no CBOM yet" state has no action button even though the app's own convention elsewhere is empty-state-plus-CTA.
- Accessibility is already unusually good for this product's stage: `:focus-visible`, skip-link, `sr-only` utilities, `prefers-reduced-motion` handling, and badges that pair color with an icon/text label rather than color alone (a code comment explicitly names this as a deliberate colour-blind-safe choice).
- No product logo image anywhere today — a single Unicode glyph (◈) in the primary color stands in for a mark. No footer, no company identity of any kind currently in the product.

### 1.6 Baseline test coverage (for the QA phase)

217 top-level Go test functions across 15 packages, plus a browser-driven end-to-end script (`testing/e2e/journey.mjs`) covering ~25 named user scenarios (onboarding, scanning, hygiene/PQC findings, readiness change over time, scheduling, export, XSS-safety, host/CBOM ingest, About-page content) and a companion security-header smoke test. This is the regression baseline the redesign must not break (Phase 12 requirement).

---

## Phase 2 — Research: what the industry actually does

Grounded in primary/vendor documentation and dated industry sources (2026), read for UX patterns, not just feature lists.

### 2.1 Certificate/TLS management: the ground is shifting under everyone

The CA/Browser Forum's shortened maximum TLS certificate validity is now in force: **200 days from March 2026, 100 days from March 2027, 47 days from March 2029.** Every current certificate-management vendor UX research turned up (Sectigo, CyberArk, IBM Concert, AppViewX) is being rebuilt around this: automated renewal, "benchmark against critical trends like 47-day TLS," and expiry visibility as close to a first-class dashboard object as findings themselves. **This is directly relevant**: the current product already tracks cert expiry (a KPI tile, a table column, a per-cert chip) but treats it as one fact among many rather than as the organizing anxiety it's rapidly becoming industry-wide. [Dotcom-Monitor: SSL Certificate Management 2026](https://www.dotcom-monitor.com/blog/ssl-certificate-management/)

### 2.2 PQC readiness tools lead with "how exposed are you," not a static score

Fortanix's PQC Central and comparable 2026 platforms (Sectigo Quantum Ready, ISARA) frame the product around four capabilities in this order: **Discovery → Planning (with a migration wizard/prioritized task list) → Continuous Intelligence → Automation.** The recurring UX pattern is not "here is your score" but "here is what's exposed, here is what to do about it, in what order, and here's your progress over time." [AppViewX PQC Assessment](https://www.appviewx.com/blogs/appviewx-avx-one-pqc-assessment-tool-kickstart-your-pqc-readiness-journey-with-complete-cryptographic-visibility/), [Fortanix PQC](https://www.fortanix.com/solutions/use-case/post-quantum-cryptography)

**Comparison to this product**: the current Dashboard and Endpoint Overview show the *state* well (readiness level, cited evidence, "what to do next" as a list) but don't show *progress toward migration* as a fleet-level concept — there's a 14-day trend chart, but no prioritized cross-fleet "these N endpoints are the highest-value fix" ranking, and no way to track "we said we'd fix this" over time (no triage/status state at all on findings, fleet-wide or per-endpoint).

### 2.3 CBOM tooling is starting to connect inventory to consequence and compliance

2026 CBOM tool comparisons note that mature tools "tie the CBOM to break-year estimates and compliance evidence," not just list algorithms. [CBOM tooling landscape](https://postquantum.com/post-quantum/cryptographic-bill-of-materials-cbom/) This product's CBOM output already carries PQC verdicts with citations (arguably ahead of some named tools, which are static viewers) but doesn't connect a finding to "by when does this become a real risk" or to a named compliance framework a security team would report against.

### 2.4 Security-findings dashboards: triage state is the missing piece here

Well-established practice across AppSec/vuln-management dashboards (GitLab, Datadog, Orca, and general industry guidance): findings need a **filterable, faceted table by severity/triage-state/host**, and a first-class **triage workflow** (acknowledge, assign, snooze, mark accepted-risk) so the same finding isn't re-surfaced as new on every scan. [Secure.com: vulnerability remediation best practices](https://www.secure.com/blog/infrastructure-security/vulnerability-remediation-best-practices) The guiding principle repeatedly stated: **"prioritize actionable insights over generic data."** [Aufait UX: cybersecurity dashboard UI/UX](https://www.aufaitux.com/blog/cybersecurity-dashboard-ui-ux-design/)

**This product has zero triage state.** Every finding is recomputed fresh on every scan and shown flat; there is no way to say "we know about this, it's accepted" or "ticket filed," which is precisely the gap the research names as most consequential for a findings-heavy security tool at fleet scale.

### 2.5 Competitive landscape (carried forward from prior research, re-verified relevant to UX specifically)

testssl.sh/SSLyze/SSL Labs are single-endpoint report generators with no fleet concept at all; Keyfactor/Venafi/DigiCert-class enterprise PKI platforms have fleet dashboards but are commercial, closed, and (per public UX write-ups) are frequently criticized for exactly the information-overload problem this audit's Phase 3 independently finds here. CBOMkit is a viewer, not an assessment/scoring product. **This product's actual differentiation opportunity is real**: it is the only thing found in research that combines active TLS/PQC assessment, a cited evidence model, and CBOM generation in one open-source, single-binary tool — but that differentiation is currently expressed as three separate, disconnected surfaces (Endpoints, Hosts, CBOM export) rather than one coherent "your organization's crypto posture" product.

---

## Phase 3 — Product audit

Ground rule followed throughout: document problems before proposing solutions (this doc stops there; solutions are in UX-REDESIGN-001).

### 3.1 Product-level findings

| # | Observation | Evidence |
|---|---|---|
| P-1 | Two crypto inventories (Endpoints, Hosts) never combine into one fleet picture; a host's posture is invisible to the Dashboard, trend, CSV export, and "needs attention" list | §1.2, backend inventory: `FleetSummary` only iterates `KindTLS`; no join/FK between the two `kind`s of `assets` row |
| P-2 | No triage/status state on findings anywhere — nothing distinguishes "new," "acknowledged," "accepted risk," or "fixed" across scans | Full read of `eval.Finding`/`store` schema: findings are recomputed fresh every scan, no persisted status field exists |
| P-3 | The CLI and the web product are not the same product experienced two ways — `tls scan` (CLI) never persists, `run` (host inventory) has no server-triggered path at all | §1.1, §1.4 |
| P-4 | The product computes a ranked "what to do next" per endpoint (Overview tab) but nothing fleet-wide — no cross-endpoint prioritized action list exists, despite the backend having everything needed (severity + evidence tier + HNDL exposure per finding) | Confirmed absent from Dashboard, Endpoints list, and API (`FleetSummary` has counts, not a ranked task list) |
| P-5 | Certificate expiry is tracked as one fact among many rather than the organizing anxiety the industry is converging on (§2.1) | KPI tile + table column + chip, no dedicated expiry-focused view or count-down urgency treatment beyond a 30-day threshold |

### 3.2 UX-level findings

| # | Observation | Evidence |
|---|---|---|
| U-1 | The Overview tab front-loads a large amount of correctly-cited but undifferentiated information (three dimension rows, a 5-segment scale, a PQ-group list, a remediation list, a sources block) with no single "the one thing to act on" framing | Screenshot review of `terrible-legacy` endpoint's Overview tab |
| U-2 | A hygiene deduction line ("−20 CERT.EXPIRING") does not link to its matching Findings-tab card — the user must manually switch tabs and search by rule ID | Frontend inventory, Path B |
| U-3 | The diff/"what changed" view shows before/after values as raw technical strings with no link back to the finding or TLS-detail row they came from | Frontend inventory, Path C |
| U-4 | The Scans page is a flat, low-decision-value activity log — it doesn't help a user decide anything, it's an audit trail promoted to a top-level nav item | §1.2, hands-on tour screenshot |
| U-5 | Host detail's "no CBOM yet" empty state has no call-to-action button, inconsistent with the rest of the app's own empty-state convention | Frontend inventory §5 |
| U-6 | "Matched by {rule}" on the Host algorithm table is unexplained internal jargon shown directly to the end user | Frontend inventory, Path D |

### 3.3 UI-level findings

| # | Observation | Evidence |
|---|---|---|
| I-1 | Color/severity system is consistent and accessible; **keep as-is** | §1.5 |
| I-2 | No spacing/layout scale exists — three fixed grid presets and ad hoc `rem` values rather than a systematic scale | §1.5 |
| I-3 | No loading/skeleton state on any page's initial load — a blank page until the first fetch resolves | §1.5, confirmed across all 7 top-level views |
| I-4 | No product logo image, no footer, no company identity anywhere | §1.5 |

### 3.4 Technical-experience findings

| # | Observation | Evidence |
|---|---|---|
| T-1 | Evidence is genuinely accessible and drill-downable for the *primary* path (finding → citation) — this is a real strength | Path A, fully connected |
| T-2 | Several *secondary* paths dead-end in raw, unexplained server text (`trustError`, `nameError`, diff values, "Matched by") | U-3, U-6, frontend inventory "additional dead-end" note |
| T-3 | Observed/inferred/unknown is well-modeled and consistently labeled everywhere it's shown (`evidenceBadge`) — a genuine strength to preserve exactly as-is | §1.5, `ui.js` evidenceBadge tooltips |

### 3.5 What Phase 3 explicitly did *not* find

To be equally clear about what's already good, so the redesign doesn't discard it: the citation/evidence discipline, the deliberate hygiene/readiness score separation, the accessible and consistent color system, and the primary finding→citation drill-down path are all genuinely strong and are treated in UX-REDESIGN-001 as constraints to preserve, not problems to fix.

---

Continued in [UX-REDESIGN-001-problems-and-workflows.md](UX-REDESIGN-001-problems-and-workflows.md): prioritized problem list (Phase 4), redesigned end-to-end workflows (Phase 5), and the Product Manager gate (Phase 6).
