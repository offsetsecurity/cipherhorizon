# QA-REPORT-012 · Instruments, not paragraphs (PRD-013)

Date: 2026-10-21. Build: branch `feat/classes-and-x509` (PRD-011, PRD-012 and PRD-013 together) on top of `ee275af`.
Requirements: [PRD-013](../product/PRD-013-visual-rebuild.md), [RTM](RTM.md) §PRD-013. Design:
[UX-DESIGN-011](../product/UX-DESIGN-011-instruments-not-paragraphs.md). Cryptography:
[CRYPTO-REVIEW-001](../product/CRYPTO-REVIEW-001-visual-rebuild.md). The data layer is in
[QA-REPORT-011](QA-REPORT-011.md).

## Result

| Gate | Command | Result |
|---|---|---|
| Unit and integration | `go test ./...` | pass |
| Traceability | `TestRequirementsTraceability` | 13 new rows (REQ-VIS-1 to 13), all done, each with evidence |
| Instruments | `TestInstrumentsAreSharedAndLabelled` | every instrument exported from `viz.js` with a text alternative; the five rebuilt views draw with it and keep no screen-local drawing |
| Copy rules | `TestUICopyRules` | pass (three en-dash glyphs in `viz.js` replaced by `·`) |
| Lint | `golangci-lint run ./...`, and with `GOOS=linux` | 0 issues, 0 issues |
| UI scripts parse | `node --check` on every module | all parse |
| Browser journey | `testing/e2e/journey.mjs`, the CI setup (fresh database, fresh demo targets) | **235 passed, 0 failed** (with E2E-VIS-FOLD) |
| Screen walk | below | done, 14 defects found and fixed |
| Cryptography | CRYPTO-REVIEW-001 | signed off, 6 defects fixed, 3 notes kept |

## The new checks (visual-phase.mjs)

- **E2E-VIS-1** On Summary, Configuration, the Inventory, an SSH report and a certificate page, every bits bar,
  post-quantum glyph, status tile, validity bar, stepper, stack bar and gauge says in words what it shows.
- **E2E-VIS-2** The Summary has its four figures, Fix first, a checks bar whose segments add up to the checks run,
  eight area tiles and no prose blocks; an area tile opens its part of Configuration, in view.
- **E2E-VIS-3** On the report with the most suites, each version that is on lists exactly the report's suites in the
  server's order, five part cells each and the evaluation's word, under the negotiated banner.
- **E2E-VIS-4** Every feature tile is there and in the scan's state; 0-RTT says not probed; the revocation tiles; the
  readiness level and its stepper agree with the evaluation.
- **E2E-VIS-5** The Inventory's strength histogram adds up to the list, the class bars and three columns open lists
  of exactly their count, and the list is weakest first.
- **E2E-VIS-6** Every rated SSH algorithm's bar says the evaluation's strength; key exchange and host keys carry the
  post-quantum glyph.
- **E2E-VIS-7** Summary, Configuration, the Inventory and the certificate page at 1440, 1100, 860 and 375 px: no
  sideways scroll, every control reachable by Tab; instrument text at 4.5:1 or better in light and dark. (Checked by
  hand that the contrast check measures: 166 text elements on one Configuration, lowest 4.71:1.)

- **E2E-VIS-FOLD** (REQ-VIS-13, the owner's request after the PR opened) On the hybrid target, a TLS version is open
  only when it needs a look (an old version on, a suite below Strong, or the only version); a folded one says
  *Strong · all N*; the button shows or hides every version and its label follows the versions as they are
  opened by hand (the first build kept a stale label: fixed).

## Checks rewritten for the new structure, and why each is not a weakening

| Check | Was | Now |
|---|---|---|
| E2E-05.2 | grouped action items with "What to do" and "Why it matters" | each Fix first line numbered, with what to do, why in its tooltip and an Evidence link; titles unique |
| E2E-R.1, R.3 | a version matrix with Enabled/Disabled words | protocols first; every version shown (on as a block with its suites, off on one line); an old version on says *should be off*, and at least one such version is checked |
| E2E-F.8 | purpose lines ≤ 15 words | six sections, asides ≤ 25 words (an aside now carries a link), How we tested last |
| T1-E2E.4 | three summary tiles | four (the weakest classical strength added) |
| T1-E2E.7 | purpose line per card | the six parts in the reviewer's order, each headed, and the jump row leading to each with its state dot |
| T1-E2E.8, .12 | trust table rows | trust chips, *your CA bundle ✓* in the good tone; the missing issuer card |
| T1-E2E.13 | HSTS header in `#sec-http` | in the Features part, still rendered as text |
| T1-E2E.14 | check rows fold to two columns | area tiles fold to at most two |
| T1-E2E.15 | "OCSP response was stapled", "not looked up" | the OCSP stapling tile, the OCSP URL, "not contacted" |
| T1-E2E.17 | five detail cards, no finding card | no finding card in Configuration (stricter selector), the certificate part names its issue |
| E2E-PQS.1 | "post-quantum (ML-DSA-65)" in text | an accepted post-quantum scheme chip that names mldsa65 and ML-DSA-65 |
| E2E-STR-1 | groups have any bits | **stronger:** every group chip's bits equal the evaluation's for that group |
| E2E-CLS-1 | the class card first, rows matched by `includes` | lanes matched by class name exactly (the old check let *asymmetric* match *symmetric*); the bar's label equals the API's strength and weakest mark |
| E2E-CLS-2 | a suite's part list | **stronger:** every suite on the report, each part the API gives present with its bits, the ringed cell is the API's weakest |
| E2E-CLS-3 | a Class `<select>` | the segmented control's pressed button |
| E2E-XV-1 | "certificate 1 of N in the chain" | the ribbon marks *Leaf · this certificate* and the hint names the endpoint and links back |
| E2E-XV-2 | section names of the table layout | **stronger:** the new order, the meters' labels equal the API's strengths, identifiers equal (SHA-256, SHA-1, SPKI, serial), extensions counted, PEM collapsed and last |
| E2E-24.3 | "where it was seen" | *Seen on* |

## Defects found by QA and the screen walk, fixed

1. **Jump row and area tiles had `#/` hrefs.** `safeHref` turned every in-page anchor into `#/`; clicks worked only
   through their handlers. In-page anchors to an element id are now allowed (no scheme can pass).
2. **Configuration scrolled sideways on a phone** (7 to 36 px): the class lanes' bits bars with their *weakest* label
   were wider than the column. On phones a bar now stacks its value under the track.
3. **At 1100 px the class lanes collapsed** (a sliver of bar, the axis labels on top of each other) and **the suite
   tables pushed Strength out of view.** Below 1280 px a lane's name sits above its rows, the axis shows 0, 128 and
   256, and the suite table narrows its cells and wraps long names.
4. **On a phone the suite's strength was off-screen**: the strength chip now also sits under the suite name below
   520 px, and the name column stays in place while the parts scroll (only one of the two chips shows at any width).
5. **The Summary strip wrapped a fifth tile** (Not checked) onto a row of its own: it now joins the row.
6. **Fix first titles did not line up**: the urgency badge column has one width.
7. **Area tiles inherited the old check-row grid** (centred text, lost padding, lost tone borders): restored.
8. **SSH tables broke "Allowed" and "Should be off" mid-word** once the post-quantum column was added: the state
   word no longer wraps.
9. Six defects from CRYPTO-REVIEW-001: DH "not offered" beside a DH suite, TLS 1.2 off without "should be on", an
   invalid HSTS header read as max-age 0, "today" in the wrong place on the validity bar, an EC key with key
   encipherment, and *not a quantum question* on unclassified algorithms.
10. A stale `demo-targets.exe` from an earlier session held the demo ports and failed E2E-07: an environment fault,
    not the product's. The local runner now stops it first; CI starts its own.

## Screen walk (PM and design)

Walked on the journey's data, full page: the Summary of the legacy and the hybrid target, Configuration of the
legacy (SSL 3 only, no certificate), the hybrid (TLS 1.3 and 1.2, a self-signed certificate) and an ML-DSA target,
a certificate page, the Inventory, and an SSH report: by eye at 1440, 1100 (light and dark) and 375 px; at 860 px by the journey's fit check (E2E-VIS-7).

- **Story.** The Summary answers "how bad, what first" in its first screen: four figures, then a numbered list.
  Configuration answers "is it set up right" top to bottom, and its first thing is what the owner asked for: each
  TLS version with its suites in order and every part's bits.
- **One look per idea.** A strength is always the same bar or the same cell, coloured by the same bands; no number
  is written twice in the same place (the bits are in the bar's words, not also in a column).
- **Self-explaining.** Every figure has its source on hover; Help's new *Reading the figures* says what each mark
  means; each part of Configuration ends with its issues, which open their evidence.
- **Left as it is, and why.** The SSH report's body keeps its PRD-008 layout: PRD-013 rebuilt only its algorithm
  tables (REQ-VIS-10, P2). Bringing the rest of it to the instruments is a separate piece of work.

## Sign-off

- **QA:** all gates above pass on this build. Signed off.
- **Design:** the walk's defects 1 to 8 are fixed and re-shot at every width. Signed off.
- **Cryptography:** CRYPTO-REVIEW-001. Signed off.
- **PM:** PRD-013 REQ-VIS-1 to 13 are met (13: versions fold, so a reviewer sees first what needs a look), the owner's three comments on the concept are answered (versions and
  suites first, in suite order with each suite's information; certificates present; one place to check the
  configuration). Signed off for merge. **Not released:** a release needs the owner's go-ahead.
