# QA report 008: Post-quantum signatures in TLS, and SSH servers (PRD-008)

Runs the WP-A checks of [QA-PLAN-006](../product/QA-PLAN-006-pq-signatures-and-ssh.md) against
[PRD-008](../product/PRD-008-pq-signatures-and-ssh.md). Run on 2026-10-12:

- Windows 11, Go 1.27, Edge headless.
- A fresh database, with demo targets built from this tree.

Requirement status is in the [RTM](RTM.md) (PRD-008 section). Part one (§1 to §4) is WP-A, shipped in the first pull
request; part two (§5 to §8) is the SSH work packages, WP-B to WP-G.

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

- E2E-PQS.1 (`pqs-phase.mjs`) scans the two new demo targets through the UI:
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

---

# Part two: SSH servers, a page per protocol, the SSH baseline (PRD-008 WP-B to WP-G)

Run on 2026-10-13 with the same machine and tools as part one. For the real-OpenSSH oracle, Podman 6.0.2 ran
Debian 12 (OpenSSH 9.2p1) and Debian 13 (OpenSSH 10.0p2). The scope is PRD-008 as amended on 2026-10-13 after the
owner's STRATEGY-003 decisions. Screens: [UX-DESIGN-007](../product/UX-DESIGN-007-protocol-pages-and-ssh-baseline.md).

## 5. Verdict

**WP-B to WP-G are met, with one requirement deferred.**
- 41 of 42 requirements are `done`.
- **REQ-SHB-7, BSI TR-02102-4 as a second baseline, is deferred.** The BSI publishes the guideline only as image
  PDFs, and the only transcription found is of an older edition, so the tables can't be verified here. It needs a
  verified transcription of the 2026-01 tables (owner item).

What changed from the first SSH build, per the owner's decisions:
- **SSH servers have a page of their own.** The 0 to 100 SSH score is gone from every view, the PDF and the CLI.
- **An SSH server is judged against the CipherHorizon SSH baseline 2026.** It meets it, or the report lists the
  changes and the `sshd_config` lines that make them.
- **The product introduces itself as multi-protocol** everywhere it says what it is.

## 6. Results

| Suite | Result |
|---|---|
| `gofmt`, `go vet ./...` | clean |
| `golangci-lint run ./...`, Windows and `GOOS=linux` | **0 issues** |
| `go test ./...` | pass |
| `govulncheck ./...` | **No vulnerabilities in the code**: see the note below |
| Browser journey (every phase; `ssh-phase.mjs` rewritten, 13 SSH checks) | **204 / 204** |
| `testing/e2e/security.sh` (3 new SSH checks) | **127 / 127** |
| Real-OpenSSH oracle, `testing/ssh/oracle.sh` | **37 AGREE, 0 DISAGREE**; baseline round trip passes on all 4 configurations that needed it |
| Fuzzing (identification, KEXINIT, host key blob, KEX reply) | 3.2M to 5.2M executions each, clean. The parsers are unchanged since. |

**govulncheck.** It reports GO-2026-5932, in `golang.org/x/crypto/openpgp`:
- Nothing calls that package.
- The module (`golang.org/x/crypto` v0.58.0) is used only by tests and `demo-targets`, as an independent SSH
  implementation.
- `TestReleaseBinaryDoesNotImportXCryptoSSH` keeps it out of the release binary.

### The oracle (REQ-SHN-2, REQ-SHB-2, REQ-SHB-4)

For each OpenSSH version and each configuration (default, hardened, legacy), the oracle:
1. scans the server, and compares the key exchange, cipher and MAC lists with `sshd -T`;
2. compares the host key fingerprints with `ssh-keygen -l`, and checks every signature verified;
3. on 10.0, compares the negotiated key exchange with `ssh -vv`.

**The new step: the baseline round trip.** For each configuration that doesn't meet the baseline, the oracle:
1. puts the generated `sshd_config` lines first;
2. requires `sshd -t` to accept them;
3. restarts sshd and scans again.

| | OpenSSH 9.2 (Debian 12) | OpenSSH 10.0 (Debian 13) |
|---|---|---|
| default | AGREE ×5; lines accepted; rescan meets | AGREE ×6; lines accepted; rescan meets |
| hardened | AGREE ×5; meets as configured | AGREE ×6; meets as configured |
| legacy | AGREE ×5; lines accepted; rescan meets | AGREE ×6; lines accepted; rescan meets |

**Stock OpenSSH 10 doesn't meet the baseline, and only because of its MACs.** Its defaults keep `umac-64`, `hmac-sha1`
and the non-ETM forms, which common hardening guides also remove. Debian 12's 9.2 already has strict key exchange (a
Debian backport), so no upgrade note appears there.

### New automated checks

**Go:**
- `TestEveryBaselineEntryIsCited`, `TestCipherHorizonBaseline2026`, `TestBaselineConformance`,
  `TestGeneratedSSHDConfig` (golden), `TestBaselineChoice`
- `TestHardenedServerMeetsTheBaseline` (against x/crypto), `TestBaselineChangesMarkTheirSection`
- `TestSSHRemediationNamesTheDirective`
- `TestSSHHasNoHygieneScore`, `TestFleetBandsCountTLSOnly`, `TestFleetSummaryByProtocol`,
  `TestBaselineIsStoredWithTheScan`
- `TestSSHPDF`, `TestSSHFailOnBaseline`, `TestSSHBaselinesCommand`
- `TestSSHServersAreNamedAndNotScored`, `TestNoSurfaceSaysTLSScannerAlone`

**Browser (`ssh-phase.mjs`):**

| Check | What it covers |
|---|---|
| E2E-H.1 | The page and its preset add dialog |
| E2E-H.1b | Levels and baseline verdicts on six demo servers; no score stored |
| E2E-H.1c | Each list holds only its protocol, with its own columns |
| E2E-H.1d | An old link is redirected |
| E2E-H.1e | The scan-box chip |
| E2E-H.2 | Every report tab |
| E2E-H.2b, H.2d | Phone width |
| E2E-H.2c | The hardened server meets the baseline |
| E2E-H.3 | The Overview cards |
| E2E-H.3b | The Findings filter |
| E2E-H.3c | Reports |
| E2E-H.4 | Help |

`pqs-phase.mjs`'s check is renamed E2E-PQS.1: it had the id of Help's E2E-S.1.

## 7. Screen walk

Walked at 1440 and 390 wide: SSH servers, TLS endpoints, an SSH report's five tabs, a hardened server, the Overview,
Findings, Reports, Help and About.

**Found and fixed during the walk:**

| What was wrong | Fix |
|---|---|
| An SSH report said "Nothing to fix" beside a baseline tile reading "2 changes", because non-ETM MACs are only notes as findings | An unmet baseline is now the first action item, counted in the verdict ("1 thing to fix"), and links to the lines to copy |
| A section read ✔ Good beside "2 that should be off" | An area the baseline wants changed is at least *Needs attention* |
| Adding a server from the SSH servers page's own button left the list stale: the same address fires no navigation | The page draws itself again (found by the journey) |
| At 390 wide, the requirements table broke "Not met" into one letter per line | Requirements are a list |
| A list row's second line read "127.0.0.1:9460 Go" | Now "127.0.0.1:9460 · Go" |
| The action item's badge was amber while the tile and list were red for the same verdict | Made red to match |
| The page title, the systemd and Quadlet units, the Windows service and the package summary still said "TLS scanner" | Changed, and the guard test covers the title |

One copy change was made after the last journey run: each requirement now reads its text first, then Met or
Not met. Web tests were rerun; no journey check reads the order.

## 8. Deviations and limits

- **Key exchanges the prober completes:** MODP group 1/14/16 and the others listed in `docs/ssh-scanning.md`.
  REQ-SHP-3 named group 18 too.
  - Group 18 and group exchange are not implemented.
  - A server offering only those is still judged on its lists. Its host keys are reported as *not fetched*, with
    the reason, never as absent.
- **The web app has no baseline selector.** One baseline ships; the API and CLI take an id (PRD-008 §6).
- **Overview figures.** The *Next certificate expiry* figure is folded into the TLS endpoints card ("N certificates
  expire within 30 days"), so the band stays at six figures.
- **The Findings filter** is one select (everywhere, TLS endpoints, SSH servers, machines) rather than a separate
  protocol select beside the existing one.
