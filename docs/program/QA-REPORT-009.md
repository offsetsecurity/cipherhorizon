# QA-REPORT-009 · Charts, motion, port, CBOM (PRD-009)

Date: 2026-10-18. Build: branch `feat/interactive-charts` on top of `f0b62c1` (0.1.1). Plan:
[QA-PLAN-007](../product/QA-PLAN-007-charts-motion-port-cbom.md). Requirements: [RTM](RTM.md) §PRD-009.

## Result

| Gate | Command | Result |
|---|---|---|
| Unit and integration | `go test ./...` | 44 of 44 packages pass |
| Traceability | `TestRequirementsTraceability` (in the above) | 23 PRD-009 rows, all done, each with evidence |
| Lint | `golangci-lint run ./...`, and with `GOOS=linux` | 0 issues, 0 issues |
| Vulnerabilities | `govulncheck ./...` | no vulnerability reachable from our code |
| UI scripts parse | `node --check` on every module, as CI does | all parse |
| Browser journey | `testing/e2e/journey.mjs` (CI setup: `--sign-in on`, token, server log) | **214 passed, 0 failed** (204 at 0.1.0; 9 new chart and motion checks) |
| Live security checks | `testing/e2e/security.sh` | 127 passed, 0 failed |
| Container smoke (Podman, WSL) | `testing/deploy/smoke.sh` with `CERT=`/`KEY=` | 18 passed, 0 failed, including the new PORT case |
| Screen walk | [UX-REVIEW-009](../product/UX-REVIEW-009-charts-and-motion.md) | 6 findings fixed, 2 kept with reasons |

## What the new checks cover

- **Charts (E2E-CHT-1 to 6).**
  - Every linked readiness level, status-band link and Inventory mark opens a list whose length is the figure
    clicked. The ring counts algorithms and keys together, and the two lists add up to it.
  - A named row opens exactly one item.
  - Back returns to the chart.
  - No link is nested in another.
  - Every mark is a named link in the Tab order. Focus shows its tooltip and dims its siblings, and Enter opens it.
- **Motion (E2E-MOT-1, MOT-2, MOT-R).**
  - The ring sweeps on arrival only.
  - Figures end on their value.
  - Under reduced motion nothing animates.
  - `TestMotionRulesAreRespected` checks every keyframe and transition in style.css.
- **Port.**
  - `TestServePortFlag`, `TestServeAddrAndPortConflict` and `TestServePortFromEnvironment` are table tests of the
    flag, the variables and their precedence.
  - `TestServeListensOnTheGivenPort` and `TestServeAndHealthcheckFollowThePortEnvironment` start real servers.
  - `TestServeBusyPortSaysWhatToDo` holds a real port and checks the message.
  - The smoke test serves the image on 19000 from `CIPHERHORIZON_PORT`, and its health check follows.
- **CBOM.** Six tests, one per CBOM-REVIEW-002 finding, each validated against the vendored 1.6 and 1.7 schemas.

## Defects found by QA and fixed before release

| # | Found by | Defect | Fix |
|---|---|---|---|
| Q1 | Journey CHT-3, three runs | **Pre-existing.** Two certificates with one subject (an ECDSA and an ML-DSA one for `localhost`) were one inventory key row, whose status depended on the order the merge read its sources. The Inventory's counts changed between two loads of the same data. | A key's algorithm is part of its identity; conflicting statuses resolve to the worse; dependencies are sorted. `TestInventoryKeysWithOneSubjectAreTwoRowsWhateverTheOrder` checks three orders. |
| Q2 | Journey E2E-04.3 and three more Help checks | An edit put a raw line break inside a string in help.js. The Help page failed to load. | Fixed. Every module is syntax-checked before a build. |
| Q3 | Journey E2E-24.3 | A list's cross-fade could finish after the reader left the page, and then write its filters into the next page's address. | The redraw is skipped when the list is no longer on the page. The test now waits for the 80 ms fade before clicking a row. |
| Q4 | Screen walk | The L0 row lost its layout when it became a link. | Classes are added, not replaced. |
| Q5 | Screen walk | The ring and the list disagreed (algorithms and keys vs algorithms). | The list says how many keys share the status, with a link. |
| Q6 | Screen walk | A *Replace first* row opened a text search (three rows for X25519). | Exact `name=` filter, plus `quantum=vulnerable`, since that list holds only quantum-vulnerable items. |
| Q7 | Screen walk | Keyboard focus scrolled a point into view, and that scroll hid its tooltip. | The tooltip hides on scroll only when no mark has focus. |

## Test changes, and why each is not a weakening

- **E2E-CHT-2:** no longer compares `history.length`. Chrome caps it at 50, so it cannot show that an entry was
  replaced. Back returning to the chart shows it.
- **charts-phase:** enables focus emulation. A headless page has no window focus, so `.focus()` fires no focus events.
- **E2E-MOT-1:** samples the page from the first frame the ring exists. A navigation from outside arrived after the
  draw-in had finished.
- **E2E-24.3:** waits for the redraw after clearing a filter, as it already did after setting one.
- **`TestSystemdUnitIsSandboxed`:** accepts `--addr 127.0.0.1` without a port. The unit must still listen on
  loopback; the port now comes from `--port` in `CIPHERHORIZON_OPTS`.

## Not tested here

- macOS and arm64 builds. CI and the release workflow build them.
- The Windows service install with `--port` was tested as a unit (`TestServiceURLFollowsPort`), not by installing a
  service on this machine.
