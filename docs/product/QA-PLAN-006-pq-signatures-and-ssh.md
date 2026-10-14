# QA-PLAN-006 · Post-quantum signatures and SSH endpoints

For [PRD-008](PRD-008-pq-signatures-and-ssh.md) and [ENG-HANDOFF-005](ENG-HANDOFF-005-pq-signatures-and-ssh.md).
Results go in `docs/program/QA-REPORT-008.md`; requirement status in the [RTM](../program/RTM.md).

## 1. Levels of evidence

| Level | What | Where |
|---|---|---|
| Unit | Wire parsing, KEX maths, registry, rules, readiness, CBOM, PDF text | `go test ./...` |
| Hermetic integration | The prober scanning **independent** servers on loopback: `crypto/tls` for TLS, `golang.org/x/crypto/ssh` for SSH, scripted servers for what no library will do (SSH-1, hostile banners, servers that ignore `signature_algorithms`) | `internal/tlsprobe`, `internal/sshprobe` tests |
| Oracle | The SSH prober against **real OpenSSH**: 9.2 (Debian 12) and 10.x (Debian 13 or Alpine 3.22) in rootless Podman, configured three ways (default, hardened, legacy). The prober's lists, host key fingerprints and negotiated choice are compared with `sshd -T` and `ssh-keygen -lf`. | `testing/ssh/oracle.sh` |
| Fuzz | Identification, KEXINIT, host key blob, certificate, KEX reply: 1M+ executions each | `go test -fuzz` |
| Mutation | Break a rule or a guard deliberately and confirm a test fails (list in §4) | recorded in the report |
| End to end | The browser journey adds phases for SSH and signatures, on `demo-targets` | `testing/e2e/journey.mjs` |
| Security | `security.sh` unchanged and passing; plus the SSH scope and hostile-banner checks | `testing/e2e/security.sh` |
| Screens | The walk in UX-DESIGN-006 §5, with findings written down and fixed | QA-REPORT-008 |
| Regression | Every existing test, the journey, lint (Windows and `GOOS=linux`), `govulncheck`, the self-scan | all of the above |

## 2. Test cases (beyond the ones named in the PRD)

| ID | Case | Expected |
|---|---|---|
| TC-S1 | ML-DSA-only TLS 1.3 server (Go `crypto/tls`, ML-DSA-65 certificate, X25519MLKEM768) | TLS 1.3 supported; leaf ML-DSA-65; L4; signatures stage accepts `mldsa65` only |
| TC-S2 | ECDSA + ML-DSA dual-certificate server | L4 via the signature stage; Authentication detail says so; both schemes accepted |
| TC-S3 | Classical server | ML-DSA refused; L3 stays L3; no new finding |
| TC-S4 | Scripted server that answers every hello | Control accepted, so the stage is inconclusive; level not raised |
| TC-S5 | TLS 1.2-only server | Signature stage skipped: "TLS 1.3 is not supported" |
| TC-S6 | A stored `tls-report/2` from 0.1.0 | Evaluation identical apart from version; stage *not collected* |
| TC-H1 | x/crypto server with ML-KEM, Ed25519 + ECDSA + RSA keys | L3, 3 keys, all verified, negotiated `mlkem768x25519-sha256` |
| TC-H2 | x/crypto server, classical only | L1, `PQC.HNDL-EXPOSED` |
| TC-H3 | x/crypto server, legacy (`ssh-rsa`, `aes128-cbc`, `diffie-hellman-group14-sha1`, `hmac-sha1`) | Findings for each; Terrapin when CBC+ETM without strict kex |
| TC-H4 | x/crypto server with an `ssh-mldsa-65` host key | L4 |
| TC-H5 | Scripted SSH-1.5 banner | L0, `SSH.PROTOCOL-1`, other areas not applicable |
| TC-H6 | Scripted server advertising only `sntrup761x25519-sha512` | L3 (computed), `SSH.PQ-NOT-FIPS`, host keys inconclusive with reason |
| TC-H7 | Port that speaks HTTP | Failed scan: "did not send an SSH identification line", with the first bytes cleaned |
| TC-H8 | Banner with markup and control characters | Stored cleaned; rendered as text in the UI and PDF |
| TC-H9 | Host certificate (x/crypto `Certificate`) | CA, principals, validity parsed |
| TC-H10 | A server that sends 25 preamble lines | Refused at 20 with a clear reason, no hang |
| TC-H11 | Loopback without `--allow-loopback` | Refused by the guard, as TLS |
| TC-H12 | Cancel during the host-keys stage | Scan canceled; no evaluation stored |
| TC-W1 | Add `ssh://h`, `h:22`, `h:2222` with *SSH*; bulk add with mixed lines | Kinds and ports right; duplicates per kind |
| TC-W2 | Endpoints filter *SSH* | Only SSH rows |
| TC-W3 | Every SSH report tab on the demo targets | Renders; no console error; no TLS words |
| TC-W4 | Schedule an SSH endpoint hourly | Due scan queued by the scheduler |
| TC-W5 | Inventory CBOM after one SSH scan | Contains an `ssh` protocol component; schema-valid |
| TC-C1 | `ssh scan --fail-on 'level<L3'` on classical and hybrid demo targets | exit 3 and exit 0 |
| TC-C2 | `ssh scan --cbom` | CycloneDX 1.7 by default, valid |

## 3. Oracle procedure (REQ-SHN-2)

1. Start `debian:bookworm` (OpenSSH 9.2) and `debian:trixie` or `alpine:3.22` (OpenSSH 10.x) rootless. Install
   `openssh-server`, generate host keys, and run `sshd -D -p 2222` with each configuration file in
   `testing/ssh/configs/`.
2. For each one, record:
   - `sshd -T`: kexalgorithms, hostkeyalgorithms, ciphers, macs;
   - `ssh-keygen -lf` of each host key: the SHA256 fingerprints.
3. Run `cipherhorizon ssh scan --json` from Windows against the forwarded port, or inside the VM if forwarding
   is unavailable (see the dev-environment notes).
4. **AGREE** when, for every configuration:
   - the KEX, host key, cipher and MAC lists equal `sshd -T`, apart from the pseudo-algorithms;
   - each fingerprint equals `ssh-keygen`'s;
   - the negotiated KEX equals what `ssh -vv` reports for OpenSSH 10's client (where available).

## 4. Mutation checks

| Mutation | Must fail |
|---|---|
| Drop ML-DSA from the TLS 1.3 hellos | `TestTLS13HellosOfferMLDSA`, `TestAnMLDSAOnlyServerIsSeen` |
| Skip the control probe | `TestSignatureStageControlCatchesServersThatIgnoreTheList` |
| Encode `K` as an mpint for the ML-KEM hybrid | `TestNegotiationCompletesTheHybridExchange` (signature does not verify) |
| Accept `packet_length` > 35000 | `FuzzKEXINIT` bound test |
| Count `sntrup761` as not post-quantum | `TestSntrupCountsButIsNoted` |
| Treat `kex-strict-s` as a key exchange | `TestKEXINITListsMatchTheServer` |
| Let the SSH scan bypass the guard | `TestSSHScanRespectsTheGuardAndBudget` |
| Import x/crypto/ssh from a release package | `TestReleaseBinaryDoesNotImportXCryptoSSH` |

## 5. Exit criteria

- All P0 requirements done in the RTM, each with evidence.
- Every gate in §1 green, with numbers recorded.
- The screen walk is done and its findings fixed.
- Deviations are listed with reasons.
