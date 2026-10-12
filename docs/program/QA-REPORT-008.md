# QA report 008: Post-quantum signatures in TLS (PRD-008 WP-A)

Runs the WP-A checks of [QA-PLAN-006](../product/QA-PLAN-006-pq-signatures-and-ssh.md) against
[PRD-008](../product/PRD-008-pq-signatures-and-ssh.md). Run on 2026-10-12:

- Windows 11, Go 1.27, Edge headless.
- A fresh database, with demo targets built from this tree.

Requirement status is in the [RTM](RTM.md) (PRD-008 section). The SSH work packages (WP-B to WP-F) ship in a separate
pull request and will get their own section here.

## 1. Verdict

**WP-A is met.** All 9 requirements (8 P0, 1 P1) are `done`.

**The defect.** The scanner's TLS 1.3 hellos offered no ML-DSA signature scheme. A server whose only certificate is
ML-DSA, and which picks its certificate before answering (as OpenSSL does), refused every one of them. The endpoint
then read as having no TLS 1.3 and was rated L0. `TestAnMLDSAOnlyServerIsSeen` reproduces it, and fails without the
fix.

## 2. Results

| Suite | Result |
|---|---|
| `gofmt`, `go vet ./...` | clean |
| `golangci-lint run ./...`, Windows and `GOOS=linux` | **0 issues** |
| `go test ./...` | pass |
| `govulncheck ./...` | **No vulnerabilities found** |
| Browser journey (`journey.mjs` with every phase, new `pqs-phase.mjs`) | **191 / 191** |
| `testing/e2e/security.sh` | **124 / 124** |

### New and changed automated checks

**Go:**

- `TestTLS13HellosOfferMLDSA`
- `TestAnMLDSAOnlyServerIsSeen`, `TestAnMLDSAOnlyServerIsL4`
- `TestSignatureStageListsAcceptedSchemes`, `TestSignatureStageControlCatchesServersThatIgnoreTheList`
- `TestDualCertificateServerReachesL4`
- `TestEndpointCBOMListsAcceptedSignatureAlgorithms`
- `TestOldReportsEvaluateUnchanged`
- `TestDocsNameTheGoVersion`

**Browser:**

- E2E-S.1 (`pqs-phase.mjs`) scans the two new demo targets through the UI:
  - base+18 (ML-DSA only) and base+19 (ECDSA + ML-DSA) are both L4.
  - The Configuration tab lists `mldsa65` as accepted (post-quantum).
- T1-E2E.1 now expects 8 stages, including `signatures`.

**`security.sh`:**

- The script used `python` to read JSON. On a machine without Python, five checks failed with misleading results:
  - the system id was empty, so three requests went to `//` paths and got 307;
  - the loopback scan status could not be read.
- A binary built from `main` failed the same five, so this was not a regression. The script now uses `node`, which
  the browser suites already require. With that change, 124 / 124 pass.

## 3. Screen walk

On the Configuration tab of the dual-certificate demo target:

- The key exchange area says the server *can authenticate with ML-DSA-65 (post-quantum) as well as ECDSA*.
- The Authentication dimension says which evidence it rests on.
- The signature-scheme table lists every scheme with a verdict word.

**Found and fixed during the walk.** The L4 summary still read "Hybrid key exchange and a post-quantum certificate".
That is misleading for a server whose default certificate is ECDSA. The text now says "post-quantum authentication"
in the following places:

- the evaluation;
- Help's level scale;
- `docs/methodology.md`;
- the site's methodology page.

This was a copy change only. Go and web tests were rerun after it; the journey was not, and no journey check reads
this sentence.

## 4. Known limits (recorded in PRD-008 §6)

- **TLS 1.2 signature algorithms are not tested.** ML-DSA is defined for TLS 1.3 only.
- **SLH-DSA TLS code points are not probed.** `crypto/tls` does not pin them yet.
- **The stage costs 15 connections per scan.** A server that answers its control hello (one that ignores
  `signature_algorithms`) is reported as *inconclusive*, never as accepting.
