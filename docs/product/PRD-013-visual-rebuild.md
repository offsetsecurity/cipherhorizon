# PRD-013 · The visual rebuild: Summary, Configuration, certificates, Inventory

Status: baselined 2026-10-21, approved by the owner ("let's build it"). Design:
[UX-DESIGN-011](UX-DESIGN-011-instruments-not-paragraphs.md). It replaces the screens PRD-011 and PRD-012 first
shipped; their data and APIs stay. Sign-offs: the cryptographer's review (CRYPTO-REVIEW-001) and the PM's.
Results: QA-REPORT-012.

## Requirements

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-VIS-1** | **Shared instruments** (`viz.js`, UX-DESIGN-011 §2): bits bar and axis, strength chip, part cell, post-quantum glyph, status tile, lifetime bar, gauge, level stepper, stack bar, jump row. Each one has a text alternative. | One scale and one set of colours everywhere | `TestInstrumentsAreSharedAndLabelled`, `script:testing/e2e/visual-phase.mjs#E2E-VIS-1` | P0 |
| **REQ-VIS-2** | **Summary** (§3.1): instruments, Fix first, the checks bar, area tiles; no coverage sentence and no "why it matters" groups. | Each tile opens its section | `script:testing/e2e/visual-phase.mjs#E2E-VIS-2` | P0 |
| **REQ-VIS-3** | **Configuration, protocols and suites** (§3.2.1): the negotiated banner; each version on with its groups and its suites in server order, one row each with five part cells and the strength chip; versions off on one line. | The rows equal the report's suites in rank order, and the cells equal the evaluation's parts | `script:testing/e2e/visual-phase.mjs#E2E-VIS-3`, `script:testing/e2e/strength-phase.mjs#E2E-STR-1` | P0 |
| **REQ-VIS-4** | **Certificate chain card** (§3.2.2): every certificate served opens its page; a missing issuer or an untrusted root is a dashed card that says what to do; trust per store and the name match beside it. | | `script:testing/e2e/x509-phase.mjs#E2E-XV-1` | P0 |
| **REQ-VIS-5** | **Key exchange, revocation and features** (§3.2.3 to 5), as chip rows and status tiles, each saying what was found and whether that is right. | Every feature the scan records has a tile; one it did not probe says "not probed" | `script:testing/e2e/visual-phase.mjs#E2E-VIS-4` | P0 |
| **REQ-VIS-6** | **The class map** (§3.2.6): one lane per class, each named once; a bits bar per algorithm on one axis; the weakest ringed; it agrees with the API. A sticky jump row leads to every section. | | `script:testing/e2e/classes-phase.mjs#E2E-CLS-1` | P0 |
| **REQ-VIS-7** | **Certificate page** (§3.3), in that order, agreeing with the API; PEM collapsed. | | `script:testing/e2e/x509-phase.mjs#E2E-XV-2` | P0 |
| **REQ-VIS-8** | **Inventory** (§3.4): the class bars and the strength histogram open filtered lists; the list is weakest first with a bits bar. A `strength=` filter (broken, below-112, 112, 128, 192, 256, not-rated). | | `TestInventoryFiltersByStrength`, `script:testing/e2e/visual-phase.mjs#E2E-VIS-5` | P1 |
| **REQ-VIS-9** | **Heartbeat probe.** The scan records whether the server negotiates the heartbeat extension (RFC 6520) and its Features tile shows it. Early data (0-RTT) stays *not probed*, said so on the tile. | | `TestHeartbeatIsProbed` | P2 |
| **REQ-VIS-10** | **SSH report** algorithm tables use the bits bar and the post-quantum glyph. | | `script:testing/e2e/visual-phase.mjs#E2E-VIS-6` | P2 |
| **REQ-VIS-11** | **Fit and access** (§4): no sideways scroll at 1440, 1100, 860 and 375 px; every control reachable by Tab; dark mode; contrast AA. | | `script:testing/e2e/visual-phase.mjs#E2E-VIS-7` | P0 |
| **REQ-VIS-12** | **Sign-off.** A cryptographer checks every number and claim the new screens show, against its source (CRYPTO-REVIEW-001); the PM signs off the walk (QA-REPORT-012). | | `report:docs/product/CRYPTO-REVIEW-001-visual-rebuild.md` | P0 |
| **REQ-VIS-13** | **Versions fold** (owner request, 2026-10-21): each TLS version that is on is open only when it needs a look (an old version on, a suite below Strong, or the only version); folded, its head says how its suites rate; one button shows or hides every version and says which it will do. | A reviewer sees first what there is to do | `script:testing/e2e/visual-phase.mjs#E2E-VIS-FOLD` | P1 |
