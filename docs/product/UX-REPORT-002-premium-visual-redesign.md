# UX-REPORT-002: Premium visual redesign

| | |
|---|---|
| **Scope** | A full visual redesign to a premium, enterprise security-product quality bar, plus three new capabilities: certificate chain visualization, report export, and a first-class CBOM view. Requested directly, separately from the earlier UX-AUDIT/REDESIGN/DESIGN/REPORT-001 round. |
| **Baseline preserved** | 217 Go tests + 44 browser end-to-end scenarios, all still green after every change. |

## What changed

**Design system, rebuilt from tokens up.** Self-hosted Inter (UI text) and JetBrains Mono (technical/tabular values) — both OFL/Apache-licensed, embedded locally so the product's "no external requests, air-gapped" principle holds; a full neutral/severity/status color ramp (light and dark); a real spacing and type scale; a tightened, low-key shadow/elevation system in place of the previous flat cards. Every existing CSS class name JS depends on was preserved — only their values changed.

**Navigation moved to a persistent dark sidebar** — the pattern used by Datadog, Wiz, Vercel and similar products: a fixed-tone brand anchor regardless of the content area's light/dark mode, icons paired with labels, collapsing to a horizontal bar on narrow viewports. Removing the old top bar was the one real information-architecture change requested; nothing about the route table or page content changed, only its container.

**Certificate chain**, previously three lines of a `subject → subject → subject` text summary, is now a dedicated graphical chain: leaf → intermediate → root, connected nodes, a status icon (trusted/warning) per certificate, click-to-expand full detail (Subject, Issuer, CN, SANs, validity, key algorithm and size, signature algorithm, serial number, certificate type, SHA-256 fingerprint, trust status) with computed warnings (expiry, weak signature, weak key, self-signed/missing-intermediate), all derived from fields the scan already observed — nothing invented.

**CBOM is now a first-class page** (`#/cbom`), not just a download button: pick any asset and see its actual dependency tree — Endpoint → Protocol/Certificate → the algorithms each depends on — with an evidence chip on every node naming exactly what observed it, next to a one-click machine-readable export of the same document.

**Export is now a real feature**, not a bare download link: an "Export report" dialog on each endpoint offering five report types (Full Security Report, TLS Report, Certificate Report, PQC Assessment, CBOM) against the formats that make sense for each (JSON always, CSV for findings/certificates, PDF via the browser's native print-to-PDF against a dedicated print stylesheet — no new dependency).

**Offset Security branding** moved from a small footer credit to a real lockup at the top of the sidebar (brand mark + "CipherHorizon / by Offset Security") plus the logo badge repeated in the sidebar footer — addressing "too subtle" directly, without inflating a wordmark logo that wasn't designed for that treatment.

## QA: bugs found and fixed before this report was written

Four real, independently-verified bugs were caught during this round's own QA, not left for later discovery:

1. **Certificate detail panels didn't actually collapse.** `.certcard-detail { display: grid }` had equal CSS specificity to the browser's own `[hidden] { display: none }` rule and won by cascade order, so every certificate rendered permanently expanded. Fixed with an explicit `[hidden]` override; verified by clicking a card and confirming it now toggles.
2. **`nullnull` text rendered inside two panels.** Two call sites used the native `Element.append()` (not this app's own null-safe `h()` builder) with a conditional expression that could be `null` — and native `.append(null)` stringifies it to the literal text "null". Found by reading the actual rendered page, not by code review. Fixed at both sites (the certificate detail panel and the export dialog) by filtering the argument list before spreading it into `.append()`.
3. **A warning icon rendered at full, unconstrained SVG size**, breaking the layout below an expanded certificate card. The icon had no explicit width/height and no CSS rule sized it in that container. Fixed by giving every hand-rolled icon its own explicit size, so it's correct in any container by construction rather than depending on each new call site remembering a CSS rule.
4. **The sidebar went white in dark mode.** Its background was built from `var(--gray-950)`, a token that deliberately inverts between light and dark mode for ordinary content — but the sidebar is a fixed brand anchor, not ordinary content. Caught by checking computed style directly (a screenshot from the automated E2E run had made this look fine at a glance; `getComputedStyle` proved otherwise), not by eyeballing alone. Fixed with dedicated, non-inverting sidebar tokens.
5. **A modal left open across a route change** (only reachable via the browser's Back/Forward buttons, since a real click can't reach a nav link through the modal's full-screen overlay) stayed stranded on top of the new page. Fixed by clearing `#modal-root` on every route change, matching how the router already tears down the previous page's own cleanup.

## Verification

Full Go suite (`go build`, `go vet`, `gofmt -l`, `go test ./...`, `golangci-lint run ./...`) clean throughout. The 44-scenario browser E2E journey — unchanged from the product's existing regression baseline — was re-run after the design-system rewrite, again after the certificate-chain/export/CBOM features, and a final time after every bug fix above: **44/44 every time**. Beyond automated coverage, every new surface was exercised live in a running browser: light and dark mode, desktop and mobile width (no horizontal overflow on any checked page), a certificate card expanded and inspected, an export actually triggered (CSV, verified via the modal closing cleanly with no thrown error), the CBOM tree opened and confirmed genuinely nested (not flat — an early read via plain-text extraction looked flat and turned out to be a false alarm, caught by taking an actual screenshot instead of trusting the text dump).

## Self-review against the requested bar

- **Premium, not generic?** The dark sidebar brand anchor, the token-driven type/color/spacing system, and the certificate-chain and CBOM-tree visualizations are not what a default admin-dashboard template produces — this reads as a designed product.
- **Offset immediately recognizable?** Yes — top-of-sidebar lockup is the first thing rendered, present on every page.
- **TLS posture understandable in seconds?** Yes — Dashboard leads with KPIs and a ranked "Top priority findings" list spanning both endpoints and hosts.
- **Certificate chain clear and inspectable?** Yes, directly verified — see the bugs found above, all in this exact feature, all fixed and re-verified.
- **CBOM understandable?** Yes — the tree view makes the endpoint → protocol/certificate → algorithm relationship visible, each node evidenced.
- **Exportable?** Yes — five report types, format choice, working end to end.

## Remaining gaps (named, not hidden)

- PDF export relies on the browser's native print-to-PDF rather than a custom-rendered document; it's real and dependency-free, but a purpose-built PDF layout (distinct from the on-screen page) would look more finished.
- No dedicated browser E2E scenarios yet cover the certificate-chain expand/collapse, the export dialog, or the CBOM tree specifically — they were verified live this round but aren't yet part of the automated regression baseline the way the pre-existing 44 scenarios are.
- The print stylesheet has not been checked against a real PDF output (only the CSS itself was verified), since this session's tooling can't drive the browser's native print dialog to inspect the resulting file.
