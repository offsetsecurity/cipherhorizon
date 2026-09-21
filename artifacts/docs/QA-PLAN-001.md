# QA-PLAN-001: Posture Workbench (R1)

## Strategy

| Layer | What | Where |
|---|---|---|
| Unit | rules, readiness, hygiene, diff, guard, store | `go test ./...` |
| Integration | API + runner + store + real TLS scanner against hermetic servers | `internal/server/*_test.go` |
| Automated invariants | every finding cited; no external URLs in UI assets; CSP present; no `innerHTML` with data | tests |
| Security | token, Host/Origin, SSRF, XSS-hostile strings | tests + browser |
| **End-to-end in a real browser** | drive the shipped UI against `cmd/demo-targets` | manual session, screenshots |
| Static | `go vet`, `golangci-lint`, fuzz smoke | CI |

## Test targets (all local; no third-party host is ever scanned)

`cmd/demo-targets` starts servers of known posture, so expected results are predetermined:

| Target | Posture | Expected |
|---|---|---|
| `modern-hybrid` | TLS 1.3 + TLS 1.2, `X25519MLKEM768` preferred | readiness **L3**, no HNDL, TLS hygiene Fair only because of the self-signed demo certificate |
| `classical-tls13` | TLS 1.3, classical groups only | readiness **L1**, HNDL exposed |
| `legacy-tls12` | TLS 1.2 only | readiness **L0** |
| `terrible-legacy` | scripted SSLv3 + export/RC4/NULL/anon suites | TLS hygiene Broken, critical findings |
| `dead` | closed port | scan *failed*, clear reason |
| control | `demo-targets` toggles `modern-hybrid` PQ on/off | history diff shows the change |

## Traceability

Filled in `artifacts/.../QA-REPORT-001.md`: every AC → test(s) → result → evidence (log line or screenshot).

## Exit criteria

All P0 ACs pass; P1 ACs pass or are listed as deferred with reason; no open critical/high defect; lint and
fuzz green; artifacts collected and checksummed.
