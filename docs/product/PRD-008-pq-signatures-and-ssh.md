# PRD-008 · Post-quantum signatures in TLS, and SSH endpoints

Status: baselined 2026-10-12 (owner: "go ahead with the ML-DSA fix, then SSH"). Background:
[STRATEGY-002](../strategy/STRATEGY-002-cryptolyzer-evaluation.md) §4 (gaps G1, G2, G3) and §5 (C1, C2).
Architecture: [ENG-HANDOFF-005](ENG-HANDOFF-005-pq-signatures-and-ssh.md) and
[ADR-0019](../decisions/ADR-0019-ssh-endpoints.md). Screens: [UX-DESIGN-006](UX-DESIGN-006-ssh-endpoints.md).
Tests: [QA-PLAN-006](QA-PLAN-006-pq-signatures-and-ssh.md). Status per requirement: [RTM](../program/RTM.md).

**Delivery is split in two pull requests** (owner, 2026-10-12). WP-A (post-quantum signatures in TLS) shipped first,
results in [QA-REPORT-008](../program/QA-REPORT-008.md). WP-B to WP-G (SSH) follow, **amended 2026-10-13** per
[STRATEGY-003](../strategy/STRATEGY-003-multi-protocol-product.md) and the owner's decisions there: a page per
protocol in the menu, SSH judged by **baseline conformance** (WP-G) and never by a 0 to 100 score, and the
multi-protocol positioning. Screens: [UX-DESIGN-007](UX-DESIGN-007-protocol-pages-and-ssh-baseline.md), which
supersedes UX-DESIGN-006 where they differ. Architecture: [ENG-HANDOFF-005](ENG-HANDOFF-005-pq-signatures-and-ssh.md) §9.

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
| **REQ-SHE-1** | An SSH report is judged into the **same `Evaluation` shape** as TLS (findings, readiness, hygiene, counts, sections, checks, fix-first, vulnerabilities). Every list, count and ranking that works for TLS works for SSH unchanged. | Fleet findings, counts, systems ranking include SSH endpoints | `TestSSHEvaluationHasTheSameShape`, `TestFleetSummaryByProtocol`, `TestFleetFindingsSpansAssetKinds` | P0 |
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
| **REQ-SHE-5** | **No 0 to 100 score for SSH** (amended). Nothing shows, stores for ranking, sorts or counts a hygiene score for an SSH server: not the report, the lists, Overview, Systems, the CSV or the PDF. An SSH server's quality measure is baseline conformance (WP-G). Fleet hygiene counts and the hygiene sort cover TLS endpoints only. | An SSH scan stores no band and score -1; fleet bands count TLS only; no "hygiene" on an SSH screen | `TestSSHHasNoHygieneScore`, `TestFleetBandsCountTLSOnly`, journey E2E-H.2 | P0 |
| **REQ-SHE-6** | Remediation text names the `sshd_config` directive to change (`KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs`, `Compression`) and the OpenSSH version that brings the fix where it matters (9.9 adds ML-KEM, 10.0 makes it the default) | Text present per rule | `TestSSHRemediationNamesTheDirective` | P1 |
| **REQ-SHE-7** | Changes between two SSH scans (algorithms added or removed, level, host key changed) are shown in History, like TLS diffs | Diff lists an added PQ kex and a changed host key | `TestSSHDiff` | P1 |

### WP-D · SSH in the web app (REQ-SHW)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHW-1** | An SSH server is a new asset kind `ssh-endpoint`. It's added by `ssh://host[:port]`, by port 22 with *Automatic*, or by choosing **SSH** in the add dialog's *Protocol* select. **The Overview scan box says what it will scan before it does**: as the user types, a chip reads *Scan as TLS* or *Scan as SSH* (Automatic, from the scheme or port), and a click switches it. | `ssh://h` → SSH port 22; `h:22` → SSH; `h:2222` with SSH chosen → SSH; the chip shows SSH for `h:22` and switching it to TLS scans TLS | `TestSSHTargetsAreRecognised`, journey E2E-H.1 | P0 |
| **REQ-SHW-2** | **A page per protocol** (amended). The menu's Results group reads *TLS endpoints · SSH servers · Machines · Findings · Inventory*. **TLS endpoints** lists TLS and STARTTLS endpoints only: readiness, TLS hygiene, findings, certificate expiry, last scan. **SSH servers** lists SSH servers only: readiness, baseline (*Meets* or *N changes*), findings, software, host key, last scan, sortable by each. Each page has its own add, scan-all and activity. An SSH report lives at `#/ssh/{id}`; an old `#/endpoints/{id}` link to an SSH server is redirected there. | Each list holds only its protocol; columns as stated; old links redirect | journey E2E-H.1 | P0 |
| **REQ-SHW-3** | The SSH server report has the tabs Summary, Configuration, Weaknesses, CBOM, History and the header actions Scan again, Download, More. The Summary leads with the readiness level and the **baseline verdict**. Configuration lists every algorithm with its baseline verdict and, when the server does not meet the baseline, the generated `sshd_config` lines (UX-DESIGN-007 §4) | All tabs render with demo data; no TLS-only words and no score on an SSH report | journey E2E-H.2; `TestSSHReportCopyHasNoTLSWords` | P0 |
| **REQ-SHW-4** | **Cross-protocol pages** (amended). Overview shows readiness across all protocols (one scale) and **one card per protocol** (TLS endpoints: count, exposed, hygiene bands, certificates expiring; SSH servers: count, exposed, meeting the baseline, SSH-1). The readiness scale states its rules **per protocol** (For TLS / For SSH). Systems rank by readiness and exposure, never by a score. Reports group documents by protocol. Inventory counts SSH servers, with protocol as a facet. | Cards and counts per protocol; the scale names both rubrics | `TestFleetSummaryByProtocol`, journey E2E-H.3 | P0 |
| **REQ-SHW-5** | Schedules, bulk add (one per line, `ssh://` accepted), scan all, cancel, re-evaluate, delete, tags, notes and systems work for SSH endpoints | Workflow test | `TestSSHEndpointWorkflow` | P0 |
| **REQ-SHW-6** | Help and About explain SSH scanning: what is sent (identification, KEXINIT, key exchanges, never authentication), the readiness rules, the checks | Text present | journey E2E-H.4 | P1 |
| **REQ-SHW-7** | **Findings by protocol.** Fleet Findings keeps grouping by problem across protocols, adds a *Protocol* filter (All, TLS, SSH), and tags every affected endpoint with its protocol | Filter narrows the groups; tags shown | journey E2E-H.3 | P0 |
| **REQ-SHW-8** | **Positioning** (STRATEGY-003 §4). The one-liner *Post-quantum readiness for the protocols your organisation runs on: TLS, SSH and, next, VPN* and the three pillars replace the TLS-only wording in the README, CLI help, container label, sign-in panel, About, Help, the sidebar tagline and the Overview eyebrow. PDF titles name their protocol ("TLS security report", "SSH security report"). | Text present; no surface calls the product a TLS scanner | `TestTheProductTellsItsStory`, `TestHelpCarriesTheOneLiner`, `TestNoSurfaceSaysTLSScannerAlone` | P0 |

### WP-G · SSH baseline conformance (REQ-SHB), added 2026-10-13

SSH practice judges a server against a policy, not a score (ssh-audit's policies, BSI TR-02102-4). A **baseline** is
a named, versioned, cited list of what an SSH server may offer and must offer. The answer an SSH administrator wants
is *does it meet the baseline, and which `sshd_config` lines would make it*.

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHB-1** | **The baseline model.** A baseline has an id, a title, a version date and, per kind (key exchange, host key, cipher, MAC, compression), an **ordered allow-list**. It also has **requirements**: at least one of a set (for example a post-quantum hybrid key exchange), strict key exchange, and a minimum RSA host key size. Every entry and requirement cites its source and names the OpenSSH version that first offers it. | A baseline with an uncited entry fails the test | `TestEveryBaselineEntryIsCited` | P0 |
| **REQ-SHB-2** | **CipherHorizon SSH baseline 2026** (`cipherhorizon-ssh-2026`, the default). Key exchange: `mlkem768x25519-sha256`, `sntrup761x25519-sha512` (both names), `curve25519-sha256` (both names), ECDH P-256/384/521, `diffie-hellman-group16-sha512`, `group18-sha512`, `group14-sha256`, `group-exchange-sha256`; **at least one post-quantum hybrid required**. Host keys: Ed25519, ECDSA, `rsa-sha2-512/256` (RSA at least 3072 bits), the ML-DSA and composite types, and their certificate forms. Ciphers: ChaCha20-Poly1305, AES-GCM, AES-CTR. MACs: the encrypt-then-MAC forms of HMAC-SHA-256/512 and UMAC-128. Compression: `none`, `zlib@openssh.com`. **Strict key exchange required** (CVE-2023-48795). Sources: RFC 9142, RFC 8332, RFC 8758, RFC 10042, RFC 9941, RFC 8731, RFC 5656, RFC 5647, NIST SP 800-57 Part 1 Rev. 5. | A stock OpenSSH 10 server does not meet it (umac-64, hmac-sha1, non-ETM MACs); a hardened one does | `TestCipherHorizonBaseline2026`, `oracle:testing/ssh/oracle.sh` | P0 |
| **REQ-SHB-3** | **Conformance.** Each advertised algorithm gets a baseline verdict: *allowed* or *should be off* (not on the allow-list, including names this program doesn't know). Each requirement is met or not. A server **meets** the baseline when nothing offered should be off and every requirement holds. The pseudo-algorithms (`ext-info-s`, `kex-strict-s-v00@openssh.com`) are signals, not judged as algorithms. A server whose lists weren't read is **not judged**, never "meets". SSH-1 only: does not meet. | Table tests: meets, each kind of gap, not judged | `TestBaselineConformance` | P0 |
| **REQ-SHB-4** | **The `sshd_config` block.** When a server does not meet the baseline, the evaluation generates `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` and `MACs` lines (and `Compression no` when needed). Each line holds the allowed algorithms the server already offers, in the baseline's order, plus any required one it lacks, with a comment naming the OpenSSH version needed. A line is never empty: it falls back to the baseline's first entry. A small RSA key or missing strict key exchange gets a comment with the fix (`ssh-keygen -t rsa -b 3072`, OpenSSH 9.6). | Golden blocks; on real OpenSSH 10, `sshd -t` accepts the block and a rescan meets the baseline | `TestGeneratedSSHDConfig`, `oracle:testing/ssh/oracle.sh` | P0 |
| **REQ-SHB-5** | The baseline result is stored with each scan (baseline id, meets, number of changes), so the SSH servers list shows and sorts it. Re-evaluation recomputes it. Older SSH scans are judged on re-evaluation. | Column populated; re-evaluate fills an old scan | `TestBaselineIsStoredWithTheScan` | P0 |
| **REQ-SHB-6** | CLI: `ssh scan --baseline ID` (default `cipherhorizon-ssh-2026`), `--fail-on baseline` exits 3 when a server does not meet it, and `ssh baselines` lists the baselines with their sources. Text output prints the verdict and the `sshd_config` block; `--json` carries them. | Exit 3 on a stock server; 0 on a hardened one | `TestSSHFailOnBaseline`, `TestSSHBaselinesCommand` | P0 |
| **REQ-SHB-7** | **BSI TR-02102-4** (version 2026-01) as a second baseline | Entries match the published tables | — | P1 |
| **REQ-SHB-8** | The SSH PDF shows the baseline verdict, the changes and the `sshd_config` block | PDF text contains them | `TestSSHPDF` | P0 |

REQ-SHB-7 is deferred. The BSI publishes TR-02102-4 only as image PDFs. The only transcription found is of an
older edition: it has no hybrid methods, and its validity years end in 2022 to 2029. A government baseline built from
tables nobody verified would be worse than none. The model makes it a data table plus the citation test, once the
owner supplies or approves a verified transcription of the 2026-01 tables.

### WP-E · SSH outputs: CBOM, PDF, CLI, graph (REQ-SHO)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHO-1** | The endpoint CBOM of an SSH scan has: a protocol component of type `ssh` with the version and the cipher and MAC lists; algorithm components for every advertised key exchange, cipher and MAC that the catalogue knows; host keys as related-crypto-material (`public-key`) with size and fingerprint; and the negotiated choices marked. CycloneDX 1.6 and 1.7 schema-valid. | Schema validation, zero warnings | `TestSSHCBOMIsSchemaValid`, `TestSSHCBOMMarksTheNegotiatedChoices` | P0 |
| **REQ-SHO-2** | The inventory and its merged CBOM include SSH endpoints | Inventory rows from an SSH scan | `TestSSHEndpointWorkflow` | P0 |
| **REQ-SHO-3** | `GET /api/v1/scans/{id}/report.pdf` renders an SSH report: verdict, checks, algorithms by category, host keys | PDF text contains the sections | `TestSSHPDF` | P0 |
| **REQ-SHO-4** | `cipherhorizon ssh scan [flags] HOST[:PORT]...` prints the verdict first like `tls scan`; it takes `--json`, `--cbom`, `--spec`, `--fail-on` (same conditions and exit codes), `--details`, `--timeout`, `--max-connections` | Golden text output; `--fail-on 'level<L3'` exits 3 on a classical server | `TestSSHScanPrintsTheVerdict`, `TestSSHFailOn` | P0 |
| **REQ-SHO-5** | SSH scans project into the estate graph: protocol `SSH-2.0`, key exchanges, host key algorithms, ciphers and MACs as *offered*, the negotiated ones as *negotiates*, host keys as key entities | Graph rebuild equals incremental; entities present | `TestSSHScanProjectsIntoTheGraph` | P1 |
| **REQ-SHO-6** | The OpenAPI document describes the SSH report shape and the `protocol` field of an asset | Spec test passes | `TestOpenAPIDescribesSSH` | P1 |

### WP-F · Quality, demo and documentation (REQ-SHN)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SHN-1** | `demo-targets` serves SSH servers: post-quantum hybrid (L3), classical (L1), legacy (`ssh-rsa`, CBC, SHA-1 key exchange; Terrapin), ML-DSA host key (L4), an SSH-1 banner, and a hardened server that **meets the baseline** | Ports printed; scans give the stated levels and baseline verdicts | journey E2E-H.* | P0 |
| **REQ-SHN-2** | The SSH prober is checked against real OpenSSH, not only x/crypto: 9.2 (Debian 12: sntrup, no ML-KEM) and 10.x (ML-KEM default). The generated `sshd_config` block is applied to the real 10.x server, accepted by `sshd -t`, and the rescan meets the baseline. Results recorded in the QA report. | Oracle script AGREE on both; baseline round trip passes | `oracle:testing/ssh/oracle.sh` | P0 |
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

- A CNSA 2.0 SSH baseline (ML-KEM-1024 only, and so on). P1, after BSI.
- Choosing the baseline in the web app. One baseline ships; the API and CLI take an id, and the web app gets a
  selector when there is a second.
- Baselines for TLS (NIST SP 800-52r2, BSI TR-02102-2). TLS keeps its hygiene score; a later decision.
- A VPN gateways page. It comes with IKE.
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
| 2026-10-13 | SSH amended per STRATEGY-003: REQ-SHE-5 (no SSH score), REQ-SHW-1..4 rewritten, REQ-SHW-7..8 and WP-G (REQ-SHB) added, REQ-SHN-1..2 extended |
