# 06 · QA report

**Role:** QA. **Build under test:** the working tree of this change, built on Windows 11 (Go 1.27, `CGO_ENABLED=0`).
Every number below was produced in this session; "not run" means not run.

## Automated gates

| Gate | Result |
|---|---|
| `go test ./... -count=1` | **371 passed, 0 failed, 2 skipped** in 25 packages (before this change: about 322) |
| `golangci-lint run ./...` | 0 issues |
| `go vet ./...` on Windows and `GOOS=linux` | clean |
| `gofmt -l .` | nothing to format |
| `node --check` on every UI script and the journey | ok |
| Architecture tests (`internal/archtest`) | pass: the collector still links no server, store, scanner or network client |

The two skips are the POSIX file-mode tests (SEC-01), which cannot run on Windows. **They have not been run
anywhere yet**; CI runs them on Linux and macOS. Until then SEC-01 and SEC-02 are implemented and reviewed, not
proven on a POSIX host.

## Live checks against the built binary

| Check | Result |
|---|---|
| `testing/e2e/security.sh` | **33 passed, 0 failed** (was 25 on Windows): now also a one-character token refused, `0.0.0.0/8` and NAT64 metadata refused, control character in a host name refused, `Permissions-Policy` present, failed logins logged without the submitted value |
| Browser journey (`testing/e2e/journey.mjs`, headless Edge, fresh database and fresh demo targets) | **58 passed, 0 failed** (was 44), no script exception, CSP violation or server error |
| Real collector on this machine → upload | The host page shows *Limited access*, *Windows 10.0.26200*, *Standard user*, the 129 unreadable locations and six blind spots, from the real CBOM, not a fixture |
| Upload with the documented `curl` headers | accepted (the three headers the UI shows are the ones the server requires) |

New journey checks (E2E-12.x): two ways to begin on first run; how-to dialog with copyable commands; empty Hosts page
teaches the loop; a CBOM without coverage reads *Not recorded*; coverage card content; blind spots on demand; reason
for a verdict on demand; Hosts list shows system and access; how-to reachable from a populated page; next-step
banner; six cards as three by two; `#/endpoints` alias; neutral not-found page; two-up cards on a phone.

## Visual review

Screenshots at 1280 px and 390 px, light and dark, of: first run, Hosts (empty and populated), host detail,
dashboard, endpoints and the how-to dialog. No horizontal scroll at 390 px; the layout defects found in the audit
(orphan KPI card, one-per-row cards on a phone, cramped chart labels, touching cards) are fixed.

## What was not tested

- **Linux and Administrator/root collector runs**, and any macOS run: no such host is available here.
- **POSIX file modes** (see above).
- **Screen-reader use**, and measured colour contrast of the new tints (spot-checked by eye only).
- **The release workflows, signing, the container image and `make`**: never executed. A GoReleaser snapshot of a
  tagged scratch copy built all twelve archives (six platforms, two programs) and stamped the version; that is the
  extent of the evidence.
- **Multi-user or network-exposed use** beyond the scripted checks; no third-party penetration test.

## Defects found during QA

| Defect | Found by | Fixed |
|---|---|---|
| The Dockerfile's example token (`change-me`) would now be refused by the new 16-character rule | reading every documented token example | yes: example now generates one |
| The first-run and next-step journey checks read the old empty state and a CSS-upper-cased label | first journey run | yes (test corrections, not product defects) |
| A gosec finding (G116) on bidirectional-control literals in the new host-name check | lint | yes: rewritten with Unicode categories, which also cover more characters |
| Host page opened with a wrong id during manual review | reviewer's own mistake | n/a |

## Verdict

**Pass, with the "not tested" list above carried into the release notes.**
