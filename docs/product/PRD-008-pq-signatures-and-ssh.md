# PRD-008 · Post-quantum signatures in TLS, and SSH endpoints

Status: baselined 2026-10-12 (owner: "go ahead with the ML-DSA fix, then SSH"). Background:
[STRATEGY-002](../strategy/STRATEGY-002-cryptolyzer-evaluation.md) §4 (gaps G1, G2, G3) and §5 (C1, C2).
Architecture: [ENG-HANDOFF-005](ENG-HANDOFF-005-pq-signatures-and-ssh.md) and
[ADR-0019](../decisions/ADR-0019-ssh-endpoints.md). Screens: [UX-DESIGN-006](UX-DESIGN-006-ssh-endpoints.md).
Tests: [QA-PLAN-006](QA-PLAN-006-pq-signatures-and-ssh.md). Status per requirement: [RTM](../program/RTM.md).

**Delivery is split in two pull requests** (owner, 2026-10-12). WP-A (post-quantum signatures in TLS) ships first,
results in [QA-REPORT-008](../program/QA-REPORT-008.md). WP-B to WP-F (SSH) follow, re-scoped by
[STRATEGY-003](../strategy/STRATEGY-003-multi-protocol-product.md): a page per protocol, and SSH judged by baseline
conformance rather than a 0 to 100 score. Where this document and STRATEGY-003 disagree on SSH, STRATEGY-003 wins until
the SSH requirements are amended.

## 1. Problem

**L4 can't be reached from a live scan, and a post-quantum-only server is misjudged.**
- Our own ClientHellos (`internal/tlsprobe/hellos.go`) offer no ML-DSA signature scheme.
- A TLS 1.3 server whose only certificate is ML-DSA has no certificate it may use with such a hello, so it refuses
  it with an alert.
- The protocol stage then records TLS 1.3 as *not supported*, and the endpoint is rated **L0 Not ready**: the
  opposite of the truth.
- A server with both a classical and an ML-DSA certificate shows us only one of them.
- Nothing in the scan says which signature schemes a server can authenticate with.

**SSH is invisible.** It is the other protocol every estate runs, and recorded SSH sessions are as exposed to
harvest-now-decrypt-later as TLS. OpenSSH has offered a post-quantum hybrid key exchange since 9.0 and made
`mlkem768x25519-sha256` the default in 10.0. Peers already scan SSH (CBOM-Lens, CipherIQ, CryptoLyzer); we
don't. The CBOM vocabulary is already ready (`ssh` is a CycloneDX protocol type).

## 2. Goals and measures

| # | Goal | Measure |
|---|---|---|
| G-1 | A server's post-quantum authentication is seen and judged correctly | An ML-DSA-only TLS 1.3 server is rated L3/L4, never L0; a dual-certificate server is L4 with the evidence named |
| G-2 | Every scan says which TLS 1.3 signature schemes the server accepts | A *Signature schemes* list on the report, in the CBOM and the PDF |
| G-3 | An SSH server gets the same treatment as a TLS endpoint | Readiness level, hygiene score, every check, action items, CBOM, PDF, history, schedule, fleet views, CLI with `--fail-on` |
| G-4 | Nothing is claimed beyond what the server showed | Every SSH fact names how it was seen (advertised, negotiated, presented, verified); every verdict cites its source |

**Non-goals.**
- No authentication attempt. We never send a user name, password or key.
- No exploit traffic.
- No TLS 1.2 signature-algorithm enumeration (later).
- No SSH group-exchange modulus measurement (later).
- No SSHFP/DNS, no HASSH.
- No correlation of SSH host keys with machine inventories (later).

## 3. Users and jobs

| Persona | Job | What this release gives them |
|---|---|---|
| Security engineer | "Is our bastion and fleet SSH protected against harvest-now-decrypt-later?" | `ssh://bastion` → L1/L3 with the reason; fleet list filtered by exposure |
| Platform owner | "Which servers still allow `ssh-rsa`, DSA keys, SHA-1 key exchange or CBC?" | SSH checks with plain remediation (the `sshd_config` line to change) |
| Auditor / GRC | "Show me the cryptography in use on these services" | One CBOM covering TLS and SSH endpoints; PDF per endpoint |
| CI owner | "Fail the build if the jump host regresses" | `cipherhorizon ssh scan --fail-on 'level<L3'` |
| PKI lead | "Can our TLS servers already serve ML-DSA certificates?" | Signature-scheme list per endpoint; L4 when proven |

## 4. Requirements

Priorities: P0 must ship in this PR; P1 should ship; P2 is recorded and deferred.

### WP-A · Post-quantum signatures in TLS (REQ-PQS)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-PQS-1** | Every ClientHello the prober builds that offers TLS 1.3 also offers ML-DSA-44, ML-DSA-65 and ML-DSA-87 (0x0904, 0x0905, 0x0906), pinned against `crypto/tls`; hellos limited to TLS 1.2 and earlier do not | Encoded hellos contain the three schemes exactly when TLS 1.3 is offered | `TestTLS13HellosOfferMLDSA` | P0 |
| **REQ-PQS-2** | A TLS 1.3 server whose only certificate is ML-DSA is reported as supporting TLS 1.3, its suites and groups are enumerated, and its ML-DSA leaf is read and described (`ML-DSA-65`, OID) | Hermetic ML-DSA-only server: TLS 1.3 supported, leaf algorithm `ML-DSA-65`, level L4 with a hybrid group | `TestAnMLDSAOnlyServerIsSeen` | P0 |
| **REQ-PQS-3** | A new scan stage, **signatures**, sends one TLS 1.3 ClientHello per candidate scheme, each offering only that scheme. It records the schemes that get a ServerHello as **accepted**. Candidates: ECDSA P-256/384/521, RSA-PSS (rsae and pss, SHA-256/384/512), Ed25519, Ed448, ML-DSA-44/65/87. | Report lists accepted schemes; a server with ECDSA and ML-DSA certificates shows both | `TestSignatureStageListsAcceptedSchemes` | P0 |
| **REQ-PQS-4** | The signature stage sends a control hello whose only scheme is a private-use code point. If the server answers it with a ServerHello, it isn't choosing a certificate by signature scheme, and the stage is **inconclusive** with that reason. No scheme is reported as accepted. | Hermetic server that ignores `signature_algorithms`: stage inconclusive, no accepted list | `TestSignatureStageControlCatchesServersThatIgnoreTheList` | P0 |
| **REQ-PQS-5** | Readiness reaches L4 when L3 holds and **either** a presented leaf is ML-DSA/SLH-DSA **or** the signature stage proved an ML-DSA scheme accepted. The authentication dimension states which evidence it rests on. | Dual-certificate server whose default leaf is ECDSA: L4, detail "accepted ML-DSA-65 when only ML-DSA-65 was offered" | `TestDualCertificateServerReachesL4` | P0 |
| **REQ-PQS-6** | The report's *Key exchange & post-quantum* area lists accepted signature schemes with a verdict word ("Accepted · post-quantum", "Accepted · fine", "Accepted · legacy"). The PDF has the same list. The endpoint CBOM emits an algorithm component per accepted scheme's algorithm (ML-DSA-65, ECDSA, RSASSA-PSS, Ed25519), with `negotiated` evidence only for observed use. | UI, PDF text and CBOM contain the accepted schemes; CBOM schema-valid | `TestEndpointCBOMListsAcceptedSignatureAlgorithms`, journey E2E-S.1 | P0 |
| **REQ-PQS-7** | Reports made before this version (no signature stage) evaluate exactly as before: the stage shows *not collected*, levels unchanged | Golden evaluations of stored reports unchanged | `TestOldReportsEvaluateUnchanged` | P0 |
| **REQ-PQS-8** | `demo-targets` serves an ML-DSA-only TLS 1.3 server and an ECDSA + ML-DSA dual-certificate server, both with hybrid key exchange (expect L4) | Ports printed; scans give L4 | journey E2E-S.1 | P1 |
| **REQ-PQS-9** | The minimum Go version becomes 1.27 (needed for `crypto/mldsa`); README, CONTRIBUTING, Dockerfile and CI agree | `go.mod` says `go 1.27`; docs say 1.27 | `TestDocsNameTheGoVersion` | P0 |

### WP-B · SSH probe (REQ-SHP)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHP-1** | The prober reads the server's identification line (RFC 4253 §4.2), allowing up to 20 preceding lines / 8 KiB, and records protocol version, software version and comment. A server that offers only SSH-1 is recorded as such and goes no further. | Banner fields parsed; `SSH-1.5` server reported SSH-1 only | `TestIdentificationIsParsed`, `FuzzIdentification` | P0 |
| **REQ-SHP-2** | It identifies itself honestly as `SSH-2.0-CipherHorizon_<version>`. It reads the server's KEXINIT (RFC 4253 §7.1), bounded to 35,000 bytes. It records every name-list: key exchange, host key, ciphers and MACs in each direction, compression. It separates the pseudo-algorithms (`ext-info-s`, `kex-strict-s-v00@openssh.com`) from real key exchanges. | Lists match the server's configuration exactly | `TestKEXINITListsMatchTheServer` (x/crypto server), `FuzzKEXINIT` | P0 |
| **REQ-SHP-3** | **Negotiation as a current client.** It sends the OpenSSH 10.6 client's default lists (pinned, cited from ssh_config(5)) and applies RFC 4253 §7.1 to compute the chosen key exchange, host key algorithm, cipher and MAC. When the chosen key exchange is one it implements (`mlkem768x25519-sha256`, `curve25519-sha256`, ECDH P-256/384/521, `diffie-hellman-group14/16/18`), it completes the exchange up to the server's reply. It verifies the server's signature over the exchange hash. | Against an x/crypto server with ML-KEM: negotiated `mlkem768x25519-sha256`, signature verified | `TestNegotiationCompletesTheHybridExchange` | P0 |
| **REQ-SHP-4** | **Host keys.** For each host key algorithm the server advertises, it runs one key exchange restricted to that algorithm and reads the host key. It verifies the signature where it can: Ed25519, ECDSA, RSA SHA-2 and SHA-1, ML-DSA (`ssh-mldsa-44/65/87`), and the composite `ssh-mldsa44-ed25519`. It groups keys by SHA-256 fingerprint (OpenSSH format) and records which algorithms each key serves. RSA records the modulus size, ECDSA the curve. | Server with Ed25519, ECDSA and RSA keys: three keys; the RSA key lists `rsa-sha2-512, rsa-sha2-256` (and `ssh-rsa` when enabled) | `TestHostKeysAreReadPerAlgorithm` | P0 |
| **REQ-SHP-5** | OpenSSH certificate host keys (`*-cert-v01@openssh.com`) are parsed: key type, CA key type and fingerprint, serial, valid principals (at most 16, cleaned), validity window | Hermetic server with a host certificate: fields parsed | `TestHostCertificatesAreParsed` | P1 |
| **REQ-SHP-6** | Stages are recorded as for TLS (`identification`, `algorithms`, `negotiation`, `host-keys`), each with outcome, reason, connections and probes in words. A host key the scanner can't fetch (no implemented key exchange in common) is *inconclusive* with the reason, never absent. | Server offering only `sntrup761x25519-sha512`: host-keys stage inconclusive, reason names the methods | `TestStagesSayWhatTheyCouldNotDo` | P0 |
| **REQ-SHP-7** | The SSRF guard, scan scope, per-connection timeout, connection budget, rate limit and cancellation apply as for TLS. A scan makes at most 2 + (host key algorithms) connections, capped at 24. | Guard refuses loopback without `--allow-loopback`; budget enforced | `TestSSHScanRespectsTheGuardAndBudget` | P0 |
| **REQ-SHP-8** | Nothing the server sends is trusted: every length is bounded, and names and banners are cleaned of control characters and capped (banner 255 bytes, name 64, list 128 entries) | Fuzzed parsers; hostile banner rendered as text | `FuzzKEXINIT`, `FuzzHostKeyBlob`, journey hostile check | P0 |

### WP-C · SSH evaluation (REQ-SHE)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHE-1** | An SSH report is judged into the **same `Evaluation` shape** as TLS (findings, readiness, hygiene, counts, sections, checks, fix-first, vulnerabilities). Every list, count and ranking that works for TLS works for SSH unchanged. | Fleet findings, counts, systems ranking include SSH endpoints | `TestSSHEvaluationHasTheSameShape`, `TestFleetIncludesSSHEndpoints` | P0 |
| **REQ-SHE-2** | **Readiness, SSH rules** (methodology): **Undetermined**, no KEXINIT read. **L0**, SSH-1 only. **L1**, no post-quantum hybrid key exchange advertised. **L2**, one is advertised but negotiation as a current client did not end on it. **L3**, a current client negotiates a post-quantum hybrid. **L4**, L3 plus a post-quantum host key presented: the composite `ssh-mldsa44-ed25519` (OpenSSH 10.6 default) or `ssh-mldsa87-p384` (draft-miller-sshm-composite-sigs), or `ssh-mldsa-44/65/87` (draft-sfluhrer-ssh-mldsa). HNDL-exposed for L0 to L2. | Table tests per level | `TestSSHReadinessLevels` | P0 |
| **REQ-SHE-3** | Hybrids built on ML-KEM (FIPS 203) count fully. `sntrup761x25519-sha512` (and its `@openssh.com` name) counts as post-quantum for HNDL, but raises a Low finding recommending `mlkem768x25519-sha256` for FIPS 203 alignment. | sntrup-only server: L3 and `SSH.PQ-NOT-FIPS` | `TestSntrupCountsButIsNoted` | P0 |
| **REQ-SHE-4** | Cited checks, each with a pass text. Every rule has a citation (test). | Each rule tested found / not found | `TestSSHRules`, `TestEverySSHRuleIsCited` | P0 |
| | `SSH.PROTOCOL-1`: SSH-1 accepted. Critical. | | | |
| | `SSH.KEX-SHA1`: a SHA-1 key exchange advertised (`diffie-hellman-group1-sha1`, `group14-sha1`, `group-exchange-sha1`). Medium; High for group1, which is 1024-bit, RFC 9142. | | | |
| | `SSH.KEX-WEAK-GROUP`: a MODP group under 2048 bits. | | | |
| | `SSH.HOSTKEY-DSA`: `ssh-dss`. High. | | | |
| | `SSH.HOSTKEY-RSA-SHA1`: `ssh-rsa` signatures. Medium, RFC 8332. | | | |
| | `SSH.HOSTKEY-RSA-SMALL`: RSA under 2048 bits High, under 3072 bits Low. | | | |
| | `SSH.CIPHER-INSECURE`: `none`, RC4/arcfour (RFC 8758), DES, 3DES, Blowfish, CAST. | | | |
| | `SSH.CIPHER-CBC`: any CBC mode. Low. | | | |
| | `SSH.MAC-WEAK`: MD5, 96-bit truncated, `none`, 64-bit UMAC. | | | |
| | `SSH.MAC-SHA1`: Low. | | | |
| | `SSH.MAC-NOT-ETM`: Info. | | | |
| | `SSH.COMPRESSION-PREAUTH`: `zlib`. Info. | | | |
| | `SSH.TERRAPIN`: CVE-2023-48795. `chacha20-poly1305@openssh.com`, or CBC with an ETM MAC, without strict key exchange. Medium, inferred. | | | |
| | `PQC.HNDL-EXPOSED`, `PQC.HYBRID-NOT-NEGOTIATED`: the shared ids. | | | |
| | `SSH.PQ-NOT-FIPS`: Low. | | | |
| | `PQC.CLASSICAL-AUTH`: Info, shared id. | | | |
| **REQ-SHE-5** | The hygiene score uses the same arithmetic and bands, and is labelled **SSH hygiene** wherever an SSH endpoint is shown | Score from findings; label in UI, CLI and PDF | `TestSSHHygieneUsesTheSameArithmetic`, journey E2E-H.2 | P0 |
| **REQ-SHE-6** | Remediation text names the `sshd_config` directive to change (`KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs`, `Compression`) and the OpenSSH version that brings the fix where it matters (9.9 adds ML-KEM, 10.0 makes it the default) | Text present per rule | `TestSSHRemediationNamesTheDirective` | P1 |
| **REQ-SHE-7** | Changes between two SSH scans (algorithms added or removed, level, host key changed) are shown in History, like TLS diffs | Diff lists an added PQ kex and a changed host key | `TestSSHDiff` | P1 |

### WP-D · SSH in the web app (REQ-SHW)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHW-1** | An SSH endpoint is a new asset kind `ssh-endpoint`. It's added by `ssh://host[:port]`, or by port 22 with *Automatic*, or by choosing **SSH** in the add dialog's *Service* select. The scan box on Overview and the scan dialog accept the same. | `ssh://h` → SSH asset port 22; `h:22` → SSH; `h:2222` with SSH chosen → SSH | `TestSSHTargetsAreRecognised`, journey E2E-H.1 | P0 |
| **REQ-SHW-2** | Endpoints lists TLS and SSH endpoints together, with the service named under the address (`SSH · OpenSSH_10.0`, as STARTTLS does today), a *Service* filter, and the hygiene column labelled *Hygiene*. For SSH, the certificate column shows the host key type. | Mixed list renders; filter works | journey E2E-H.1 | P0 |
| **REQ-SHW-3** | The SSH endpoint report has the same tabs (Summary, Configuration, Weaknesses, CBOM, History) and header actions (Scan again, Download, More) as TLS, per UX-DESIGN-006 | All tabs render with demo data; no TLS-only words on an SSH report | journey E2E-H.2; `TestSSHReportCopyHasNoTLSWords` | P0 |
| **REQ-SHW-4** | Overview, Findings, Systems, Reports and Inventory count and list SSH endpoints. The readiness scale descriptions cover both protocols. | Counts include SSH; scale text names SSH | journey E2E-H.3 | P0 |
| **REQ-SHW-5** | Schedules, bulk add (one per line, `ssh://` accepted), scan all, cancel, re-evaluate, delete, tags, notes and systems work for SSH endpoints | Workflow test | `TestSSHEndpointWorkflow` | P0 |
| **REQ-SHW-6** | Help and About explain SSH scanning: what is sent (identification, KEXINIT, key exchanges, never authentication), the readiness rules, the checks | Text present | journey E2E-H.4 | P1 |

### WP-E · SSH outputs: CBOM, PDF, CLI, graph (REQ-SHO)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHO-1** | The endpoint CBOM of an SSH scan has: a protocol component of type `ssh` with the version and the cipher and MAC lists; algorithm components for every advertised key exchange, cipher and MAC that the catalogue knows; host keys as related-crypto-material (`public-key`) with size and fingerprint; and the negotiated choices marked. CycloneDX 1.6 and 1.7 schema-valid. | Schema validation, zero warnings | `TestSSHCBOMIsSchemaValid`, `TestSSHCBOMMarksTheNegotiatedChoices` | P0 |
| **REQ-SHO-2** | The inventory and its merged CBOM include SSH endpoints | Inventory rows from an SSH scan | `TestInventoryIncludesSSH` | P0 |
| **REQ-SHO-3** | `GET /api/v1/scans/{id}/report.pdf` renders an SSH report: verdict, checks, algorithms by category, host keys | PDF text contains the sections | `TestSSHPDF` | P0 |
| **REQ-SHO-4** | `cipherhorizon ssh scan [flags] HOST[:PORT]...` prints the verdict first like `tls scan`; it takes `--json`, `--cbom`, `--spec`, `--fail-on` (same conditions and exit codes), `--details`, `--timeout`, `--max-connections` | Golden text output; `--fail-on 'level<L3'` exits 3 on a classical server | `TestSSHScanPrintsTheVerdict`, `TestSSHFailOn` | P0 |
| **REQ-SHO-5** | SSH scans project into the estate graph: protocol `SSH-2.0`, key exchanges, host key algorithms, ciphers and MACs as *offered*, the negotiated ones as *negotiates*, host keys as key entities | Graph rebuild equals incremental; entities present | `TestSSHScanProjectsIntoTheGraph` | P1 |
| **REQ-SHO-6** | The OpenAPI document describes the SSH report shape and the `protocol` field of an asset | Spec test passes | `TestOpenAPIDescribesSSH` | P1 |

### WP-F · Quality, demo and documentation (REQ-SHN)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHN-1** | `demo-targets` serves SSH servers: post-quantum hybrid (L3), classical (L1), legacy (`ssh-rsa`, CBC, SHA-1 key exchange; Terrapin), ML-DSA host key (L4) and an SSH-1 banner | Ports printed; scans give the stated levels | journey E2E-H.* | P0 |
| **REQ-SHN-2** | The SSH prober is checked against real OpenSSH, not only x/crypto: 9.2 (Debian 12: sntrup, no ML-KEM) and 10.x (ML-KEM default). Results recorded in the QA report. | Oracle script AGREE on both | `oracle:testing/ssh/oracle.sh` | P0 |
| **REQ-SHN-3** | `docs/ssh-scanning.md` (what is sent, limits), `docs/methodology.md` (SSH readiness rules, checks, hygiene label), `README.md` (SSH in the summary and comparison), CHANGELOG | Docs present and linked | docs review | P0 |
| **REQ-SHN-4** | No regression: every existing Go test, the journey, `security.sh`, lint (Windows and Linux) and `govulncheck` pass | All green | QA-REPORT-008 | P0 |
| **REQ-SHN-5** | The new parsers are fuzzed: identification, KEXINIT, host key blob, certificate, KEX reply. At least 1M executions each without failure. | Fuzz run recorded | `FuzzIdentification`, `FuzzKEXINIT`, `FuzzHostKeyBlob`, `FuzzKEXReply` | P0 |

## 5. Decisions taken (owner may revisit)

| # | Decision | Why |
|---|---|---|
| PD-1 | SSH endpoints share the asset and scan tables (a new kind), and the evaluation shape | Every fleet view, count, schedule and ranking works without a second code path; least risk |
| PD-2 | The readiness scale is shared; the SSH rules are stated beside the TLS ones | One question ("is recorded traffic exposed?") across protocols; a second scale would split the fleet view |
| PD-3 | `sntrup761x25519` protects against HNDL but is noted (Low) as not FIPS-aligned | It's a hybrid with X25519, and OpenSSH's default from 9.0 to 9.9. Programmes bound to FIPS 203 need ML-KEM. |
| PD-4 | The *current client* for SSH is OpenSSH 10.6's default lists (released 2026-10-06), pinned with their source | It's the dominant client, and its order decides what a session really uses (RFC 4253 §7.1) |
| PD-5 | The prober is our own (standard library only); `golang.org/x/crypto/ssh` is used only in tests and `demo-targets` as an independent oracle | A scanner must see partial, broken and legacy servers, which a client library refuses. A second implementation in tests catches our own misreadings. |
| PD-6 | Minimum Go 1.27 | `crypto/mldsa` (ML-DSA keys, demo certificates and host keys) arrived in Go 1.27; the toolchain was already pinned to 1.27.2 |
| PD-7 | ML-DSA in SSH host keys and in TLS counts toward L4. SSH: the composite `ssh-mldsa44-ed25519` (enabled in OpenSSH 10.6) and `ssh-mldsa87-p384` (draft-miller-sshm-composite-sigs), and `ssh-mldsa-*` (draft-sfluhrer-ssh-mldsa). TLS: draft-ietf-tls-mldsa. | The algorithm is FIPS 204. The TLS rule already counts ML-DSA certificates whose TLS code points are a draft. |

## 6. Out of scope, recorded

- SSH group-exchange modulus size (`diffie-hellman-group-exchange-*`). Advertised and judged by name only; the
  measured size is P2.
- TLS 1.2 signature algorithms (visible in ServerKeyExchange). P2.
- SLH-DSA TLS code points. Not pinned in `crypto/tls` yet, and no IANA download was approved in this program. P2.
- SSHFP, HASSH, user-authentication method listing, SSH client inventory, and SSH key correlation to machines. P2.

## 7. Change log

| Date | Change |
|---|---|
| 2026-10-12 | Baselined |
| 2026-10-12 | Delivery split: WP-A first; WP-B to WP-F to be amended per STRATEGY-003 (owner decisions) |
