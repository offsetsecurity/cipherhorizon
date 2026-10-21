# PRD-014 · The SSH report, as instruments

Status: draft 2026-10-21, from the owner's PRD-013 verdict ("instruments, not paragraphs"), applied to the SSH
server report. Design: [UX-DESIGN-012](UX-DESIGN-012-ssh-instruments.md), an addendum to UX-DESIGN-011. The data,
the API and the evaluation stay as they are; this is a front-end change. Sign-offs: the cryptographer
(CRYPTO-REVIEW-002) and the PM's walk (QA-REPORT-013).

## Why

PRD-013 rebuilt the TLS report on shared instruments. The SSH report kept its PRD-008 layout: a baseline card of
prose, fact cards that say each thing as a sentence and again as a bullet, and bullet lists of citations. Only its
algorithm tables used `bitsBar` and `pqGlyph` (REQ-VIS-10). The owner rejected that kind of screen for TLS; an SSH
reviewer should get the same one-stop page.

## Requirements

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-SSV-1** | **One Configuration page in a reviewer's order** (UX-DESIGN-012 §3): version and software, key exchange, host keys, ciphers, MACs and compression, baseline changes; a sticky jump row with each part's state; About this report last. | The parts are in that order and the jump row leads to each | `script:testing/e2e/visual-phase.mjs#E2E-VIS-8` | P0 |
| **REQ-SSV-2** | **The algorithm rows** (§3.1): every algorithm the evaluation lists, in the server's order, with the bits bar, the post-quantum glyph for key exchange and host keys, and the baseline mark; the row a current client uses is marked. | The rows equal `sshAlgorithms` kind by kind, and each bar, glyph and mark agrees with it | `script:testing/e2e/visual-phase.mjs#E2E-VIS-6` | P0 |
| **REQ-SSV-3** | **Version, key exchange and host keys as instruments**: the negotiated banner, status tiles (protocol, software, strict key exchange, compression), the readiness row with the stepper, a card per host key with its verification, and a dashed card for a key not fetched. | The banner equals the report's negotiated algorithms; the tiles agree with the report | `script:testing/e2e/visual-phase.mjs#E2E-VIS-9` | P0 |
| **REQ-SSV-4** | **Baseline as tiles and chips**: verdict tile, a tile per requirement (met or not), the changes as chips, the `sshd_config` lines with Copy. A server that meets it shows no lines. | Tiles equal the evaluation's requirements; chips equal its changes | `script:testing/e2e/ssh-phase.mjs#E2E-H.2`, `script:testing/e2e/ssh-phase.mjs#E2E-H.2c` | P0 |
| **REQ-SSV-5** | **Each part ends with its issues**: the findings of that part, each linking to its evidence, and the baseline changes that fall in it. | Every finding of the evaluation (bar the published attacks) is named under exactly one part | `script:testing/e2e/visual-phase.mjs#E2E-VIS-8` | P0 |
| **REQ-SSV-6** | **Citations in tooltips**: no bullet list of sources on the SSH Configuration; each source is a tooltip (and a link where it is a requirement). | No `ul.cites` on the page; every requirement tile names its source | `script:testing/e2e/visual-phase.mjs#E2E-VIS-8` | P1 |
| **REQ-SSV-7** | **The SSH Summary** (§2): readiness with the stepper, the baseline, the weakest classical strength with a bits bar, the host key; the baseline as the first Fix first line in the shared row shape, no "Why it matters" block. | Four tiles; the weakest strength equals the evaluation's weakest rated algorithm | `script:testing/e2e/visual-phase.mjs#E2E-VIS-10` | P1 |
| **REQ-SSV-8** | **Fit and access**: the SSH Summary and Configuration fit 1440, 1100, 860 and 375 px with no sideways scroll, every control reachable by Tab, instrument text at 4.5:1 in light and dark; an SSH-1-only server's report still renders every part. | | `script:testing/e2e/visual-phase.mjs#E2E-VIS-7`, `script:testing/e2e/ssh-phase.mjs#E2E-H.2b` | P0 |
| **REQ-SSV-9** | **Sign-off**: a cryptographer checks every number and claim the SSH screens show (CRYPTO-REVIEW-002); the PM walks every SSH screen (QA-REPORT-013). | | `report:docs/product/CRYPTO-REVIEW-002-ssh-instruments.md` | P0 |

## Out of scope

- No change to the SSH evaluation, the baseline, the API or the PDF.
- The SSH servers list, Overview, Findings and Help keep their PRD-008 layout.
