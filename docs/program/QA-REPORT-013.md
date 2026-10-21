# QA-REPORT-013 · The SSH report, as instruments (PRD-014)

Date: 2026-10-21. Build: branch `feat/ssh-instruments`, stacked on `feat/classes-and-x509` (PRD-011 to 013, PR #23).
Requirements: [PRD-014](../product/PRD-014-ssh-instruments.md), [RTM](RTM.md) §PRD-014. Design:
[UX-DESIGN-012](../product/UX-DESIGN-012-ssh-instruments.md). Cryptography:
[CRYPTO-REVIEW-002](../product/CRYPTO-REVIEW-002-ssh-instruments.md).

## Result

| Gate | Command | Result |
|---|---|---|
| Unit and integration | `go test ./...` | pass |
| Traceability | `TestRequirementsTraceability` | 9 new rows (REQ-SSV-1 to 9), all done, each with evidence; PRD-014 added to the traced PRDs |
| Instruments | `TestInstrumentsAreSharedAndLabelled` | `report-ssh.js` draws only with `viz.js`; its local `strengthWords` and the algorithm tables are gone |
| Copy rules | `TestUICopyRules`, `TestSSHReportCopyHasNoTLSWords`, `TestSSHServersAreNamedAndNotScored` | pass |
| Lint | `golangci-lint run ./...`, and with `GOOS=linux` | 0 issues, 0 issues |
| UI scripts parse | `node --check` on the changed modules | all parse |
| Browser journey | `testing/e2e/journey.mjs`, the CI setup (fresh database, fresh demo targets, sign-in on with a token) | **237 passed, 0 failed** |
| Screen walk | below | done, 3 defects found and fixed |
| Cryptography | CRYPTO-REVIEW-002 | signed off, 2 defects fixed, 3 notes kept |

## The new and rewritten checks

- **E2E-VIS-6** (rewritten): every SSH algorithm row, kind by kind in the server's order, equals the evaluation's
  `sshAlgorithms`: its name, its bits bar's words, its post-quantum glyph, its baseline mark and its in-use mark.
  Stricter than before, which only looked for each bar's label somewhere on the page.
- **E2E-VIS-8** (new): six parts in a reviewer's order; a sticky jump row whose chips lead to them (a click puts the
  part in view); every finding outside the published attacks named exactly once, under its own part; a tile per
  baseline requirement that links to its source in a new tab with the source's name as its tooltip; a chip per
  baseline change; no bullet list of sources; About this report last.
- **E2E-VIS-9** (new): the banner equals the scan's negotiated key exchange, host key, cipher and MAC ("no MAC" with
  an AEAD); the protocol tile shows the identification string; strict key exchange as the report says; the
  readiness level and stepper; a card per host key with its fingerprint and verification, and a dashed card per key
  not fetched; the SSH-1-only server still draws all six parts, says *Does not apply* and has no rows.
- **E2E-VIS-10** (new): the SSH Summary's four tiles; the weakest strength is the evaluation's weakest rated
  algorithm; the baseline is Fix first line 1 and the findings are numbered on from it in one list; no "Why it
  matters"; the hardened server shows ✓ Meets and no baseline line.
- **E2E-VIS-1, VIS-7**: the SSH Summary joins the labelled-instrument check; the SSH Summary and Configuration join
  the fit (1440, 1100, 860, 375 px), keyboard and contrast checks, light and dark. The contrast selector now
  covers the SSH rows, marks, chips, banner chips and fingerprints.

| Check | Was | Now, and why it is not a weakening |
|---|---|---|
| E2E-H.2 | the words *Should be off*, *Allowed · post-quantum* and *used by OpenSSH 10.6* on the page | the marks and glyphs that replaced those words: a row should be off; the hybrid key exchange is allowed, has the quantum-safe glyph and is in use; and each kind's in-use row is exactly what the scan negotiated (the old check did not compare with the scan at all) |

E2E-H.2b, H.2c and every other SSH check pass unchanged.

## Screen walk (PM and design)

Every SSH screen, at 1440 px, 375 px and in dark mode, on the six demo servers.

1. **The Host key tile was green for a 1024-bit RSA key** (also CRYPTO-REVIEW-002 fix 1). It now follows the key's
   strength.
2. **The baseline's Fix first line listed every name it removes** (three lines of algorithm names on the legacy
   server). It now counts them ("Remove 8 algorithms; add mlkem768x25519-sha256; replace a host key."); each
   change's reason is in the tooltip and its chip sits in its part.
3. **The Baseline part's verdict tile sat in one narrow column** beside empty space. It spans two columns above
   phone width.

Seen and kept: the single *Strict key exchange* and *Compression* tiles (one fact each, in the part they belong to);
the *Software* tile in no tone (the scanner does not judge versions); the dot in the post-quantum column for ciphers
and MACs (CRYPTO-REVIEW-002 note 3).

## Not covered

- The PDF and the SSH servers list are unchanged by PRD-014 and were not re-walked.
- An OpenSSH host certificate and a host key that could not be fetched are drawn by code the demo servers do not
  exercise (no demo server serves either); E2E-VIS-9 counts dashed cards against the report, which has none.
