# QA-REPORT-014 · Accuracy on real scans (PRD-015)

Date: 2026-10-22. Build: branch `fix/real-scan-review` on top of `5109981` (main, PR #24). Requirements:
[PRD-015](../product/PRD-015-accuracy-on-real-scans.md), [RTM](RTM.md) §PRD-015. Cryptography:
[CRYPTO-REVIEW-003](../product/CRYPTO-REVIEW-003-real-scans.md).

Data: a copy of the owner's database (`dist/cipherhorizon.db`: 55 TLS endpoints, 54 with a completed scan, one SSH
server), served by this build so every stored scan was re-evaluated with eval/12, and eight hosts scanned again.
The owner's own database was not written to.

## Result

| Gate | Command | Result |
|---|---|---|
| Unit and integration | `go test ./...` | pass |
| New tests | `TestCertificateIsReadFromARawFlight`, `TestDHPrimality`, `TestRevocationIsUnknownWithoutAStaple`, `TestCompromisedRootIsItsOwnFinding`, `TestCertExpiryIgnoresTheNoSNIChain` | pass |
| Traceability | `TestRequirementsTraceability` | 10 new rows (REQ-ACC-1 to 10), all done, each with evidence |
| Lint | `golangci-lint run ./...`, and with `GOOS=linux` | 0 issues, 0 issues |
| UI scripts parse | `node --check` on every module | all parse |
| Browser journey | `testing/e2e/journey.mjs`, the CI setup | **240 passed, 0 failed** |
| Screen walk | below, on the owner's data | done |
| Cryptography | CRYPTO-REVIEW-003 | signed off |

## What the owner saw, and what was wrong

| The owner's complaint | Cause | Fix |
|---|---|---|
| "A lot of things don't make sense" | Six evaluation and scanner errors (CRYPTO-REVIEW-003): the no-SNI fallback certificate reported as the server's on legacy-only servers; Google's RSA certificate never read; rogue roots called missing intermediates; compromised roots not named; revocation "good" unchecked; DH moduli judged by size only | REQ-ACC-1 to 6, eval/12 |
| The same, on the endpoints list | "Certificate expiry: expired 2996 days ago" on nearly every badssl.com host: the list took the earliest expiry of *every* chain, the no-SNI placeholder (expired 2018) included | The served leaf only; re-evaluation now refreshes the stored date (31 of the 54 now read valid, 13 expired, 12 have no served chain on record until scanned again) |
| "Things to fix looks broken" | Every finding was a "fix first" row, each with a severity badge *and* an urgency word, on a grid several old rules fought over | Three rows, one "when" chip each (coloured by severity), the rest folded with a count by severity; one clean grid (REQ-ACC-7) |
| "The alignment is so bad" | The strength chip sat 9 px above its row (an old `display: inline-flex` on the table cell); version heads wrapped differently per version; an empty rank column; area tiles centred | Measured, then fixed: 0 px; version heads on one grid; the rank column hidden when the client picks the order (REQ-ACC-9) |
| "TLS should be collapsed" | Versions opened when they needed a look | Every version starts folded, its head saying whether it should be on and how its suites rate (REQ-ACC-8) |

## The new checks

- **E2E-FIX-1** Fix first: the first three rows, one chip each, the rest folded under "N more things to fix" with a
  count by severity, numbering running on, and no old severity badge or urgency word left.
- **E2E-VIS-ALIGN** In the browser: each Fix first chip's centre within 4 px of its title's first line, every title
  at one x; every strength chip centred on its suite row within 2 px; every version head's name, facts and
  verdict at one x down the section.
- **E2E-VIS-FOLD** (rewritten) Every version starts folded unless it is the only one; each folded head's tally
  equals the evaluation's words per version; the show/hide button opens and closes them all and says which.
- **E2E-VIS-2** (changed) The Summary has four figures; a fifth, *Not checked*, only when a part of the scan did not
  run. Revocation's *unknown* is the same on every endpoint and is said in its area, not counted here.
- **T1-E2E.6** (widened) A section's status word may also be *Status unknown*.

## Screen walk (QA and PM), on the owner's data

At 1440, 1100 (dark) and 375 px, by eye; 860 px by the journey's fit check.

- **Summary** (superfish, ecc384, google): the headline and *First:* name the right thing (superfish: the
  compromised root, not "expired"); Fix first shows three rows and folds the rest; the weakest strength names 3DES
  where 3DES and RSA-2048 tie at 112; Revocation reads *Status unknown* with the reason.
- **Configuration** (google, ecc384): every version folded with its verdict; opened, the strength chips sit on the
  row; the class lanes' values never collide with *weakest*; on a phone a long value ("112 bits, disallowed")
  wraps instead of pushing the page 3 px wide (found by the walk, fixed).
- **Endpoints list**: expiry dates are the served certificates'.

## PM: is the story met?

The product says it is *a scanner that shows its work*. Before this, on the most standard test site there is, it
showed the wrong certificate for six hosts, the wrong diagnosis for five, and called unchecked revocation "good".
After it, every badssl.com host reports the defect it was built to show, under its right name, and what the scan
cannot know is said as *unknown*, never as *good*. Fix first is again a list of priorities. The story is met, with
two limits stated in PRD-015 (no CA contact; published leaf keys not recognised).

## Sign-off

- **QA:** all gates above pass on this build. Signed off.
- **Cryptography:** CRYPTO-REVIEW-003. Signed off.
- **PM:** PRD-015 REQ-ACC-1 to 10 met. Signed off for merge. **Not released.**
