# RESEARCH-002: The TLS / PQC / CBOM tooling landscape, and where CipherHorizon should go next

| | |
|---|---|
| **Role** | Product Manager + security research, before switching to Dev/QA for [PRD-002](PRD-002-evidence-and-coverage.md) |
| **Method** | Web research (dated citations below) plus a re-read of this codebase. Every claim below is tagged **[verified]** (checked against this repo or a primary source), **[reported]** (a vendor's or paper's own claim, not independently reproduced), or **[my inference]**. |
| **Scope** | Not limited to tools that call themselves "PQC scanners" — covers TLS/SSL scanners, PKI/certificate discovery platforms, source/container CBOM tools, and the academic literature on PQC-TLS measurement. |

## 1. Architecture self-assessment (this codebase, before any change)

**[verified]**, from `go build`/`go test`/line counts run against the tree as of this document:

| | |
|---|---|
| Language | Go 1.25, `CGO_ENABLED=0`, one static binary |
| Size | ~11,500 lines of non-test Go across 59 files, 28 test files |
| TLS engine | Own wire-protocol implementation (`internal/tlsprobe/wire`): builds ClientHellos crypto/tls will not send (SSLv2/3, export/anonymous suites, arbitrary group lists), parses ServerHello/HelloRetryRequest/alerts/ServerKeyExchange. crypto/tls used only for certificate retrieval and to show what a real client negotiates. |
| PQC / hybrid detection | **Active, per-group enumeration** via HelloRetryRequest with an empty `key_share` (RFC 8446 §4.1.3 forces the server to name its chosen group with no key generation needed) — see §3 below for why this specific technique matters. |
| Certificate collection | Full chain, trust/name validation against the OS store, ECDSA-only and RSA-only probes to surface dual certificates, PQ-certificate detection by OID when Go's x509 can't name the algorithm. |
| CBOM | CycloneDX 1.6, generated both from host package inventory (`run`) and, as of the previous work session, from an active TLS scan (`tls scan --cbom`) — protocol, cipher-suite, key-exchange-group and certificate components, PQC-annotated. |
| Evaluation | Findings with severity + evidence tier + citation; a PQC readiness level (L0-L4) with a harvest-now-decrypt-later flag; a TLS hygiene score (0-100) derived only from cited findings — this project's own scale, not modelled on any vendor's. |
| CLI / API / UI | `run`, `tls scan` (`--json`/`--cbom`/text), `serve` (JSON API + embedded web UI: dashboard, endpoints, scans, hosts, about). No OpenAPI spec yet. |
| Config | Flags + a YAML file for `run`; flags/env only for `serve`. No central config file for `serve`. |
| Logging | `log/slog`, structured, but only in the server path (`internal/server`, `internal/app/serve.go`); the CLI (`run`, `tls scan`) writes plain text to stderr. **Inconsistent, not broken** — a CLI tool writing prose to stderr is normal; it's the two styles coexisting that's worth naming. |
| Errors | Consistent `fmt.Errorf("...: %w", err)` wrapping (16 files use it); no panics in request/scan paths; the recoverer middleware catches anything that slips through in the server. |
| Tests | Unit + integration (real scanner against hermetic in-process servers, never a live third party), golden-file CBOM comparison, CycloneDX schema validation on every CBOM-producing test, fuzzing on the three wire parsers that read untrusted bytes, a browser end-to-end journey, a live security-check script. All green as of this document. |
| Build/deploy | `go build`, GitHub Actions CI (build+test+lint+fuzz+e2e), no release automation (no goreleaser, no signing) yet. |

**What works well**: the active-enumeration TLS engine and its evidence discipline (nothing stated without a citation) are genuinely ahead of the general-purpose scanners researched below — see §3.1. The evidence-tier concept already exists for *findings* (`observed`/`inferred`/`registry`/`not-measured`), just not yet extended to the CBOM itself or formalized to the level the 2026 measurement literature recommends.

**What's incomplete or weak** (self-assessed, confirmed against research in §7):

- No STARTTLS (SMTP/IMAP/POP3/...): direct-TLS only. Every general-purpose competitor researched supports it.
- No HTTP-layer check (HSTS): the one thing keeping this project's own rating honestly capped below "everything checked."
- No client-certificate/mTLS surface detection at all.
- The CBOM conflates **capability** (every suite/group the enumeration found acceptable) with **negotiation** (what one specific client actually got) — see §3.2, this is the literature's headline finding about why other tools under-report.
- Named curves beyond `x25519` have no catalogue entry, so certs/suites using `secp256r1` etc. get no algorithm reference in the CBOM.
- Single shared bearer token; no OpenAPI; no release signing — known, already documented in `RELEASE-REPORT-001.md`, not re-litigated here.

## 2. Products and projects researched

Grouped by what they actually are, since "PQC scanner" undersells most of this space.

### 2.1 General-purpose TLS/SSL scanners

| Tool | What it discovers | Remote/local | PQC | STARTTLS | CBOM | Notes |
|---|---|---|---|---|---|---|
| **testssl.sh** | Protocols, ciphers, certs, known vulns; bash, no install | Remote | Lists post-quantum ciphers it knows about **[reported]** | Yes (SMTP, IMAP, POP3, FTP, LDAP, XMPP, ...) **[reported]** | No | Widely deployed, single-connection-per-check probing model; a May 2026 measurement paper found its single-probe approach confirmed **0 of 70** independently-confirmed hybrid-capable targets in a controlled comparison ([Delgado 2026], §3.1) — **[reported, from a peer-reviewed-adjacent preprint, not independently reproduced by us]**. |
| **SSLyze** (nabla-c0d3) | Same category; Python library + CLI, multi-threaded | Remote | Not a stated focus | Yes, more protocols than testssl.sh (SMTP, XMPP, LDAP, POP, IMAP, RDP, Postgres, FTP) **[reported]** | No | Same single-probe limitation reported in the same paper. |
| **tlsx** (ProjectDiscovery, Go) | Fast bulk certificate/handshake grabbing (JARM, JA3, SANs, fingerprints) across thousands of hosts | Remote | Not a focus | No | No | Different niche entirely: internet-scale recon speed over per-endpoint depth. Confirms Go is a credible language choice for this problem (**[my inference]**: our per-endpoint depth and tlsx's bulk speed are complementary, not competing). |
| **Nmap `ssl-enum-ciphers`** | Cipher/protocol enumeration | Remote | No | Some (via `--script`) | No | The traditional baseline; no PQC or CBOM story. |
| **SSL Labs (Qualys)** | The reference grading methodology; hosted only | Remote | Not publicly documented as covering PQC | No | No | Free tool, not open source, not self-hostable. This project's own TLS-hygiene score is deliberately modelled on the *published* rating guide but shares no vocabulary or tables with it (see `feedback-own-terminology` decision from the previous session). |
| **Gossling** (checkfix.io) | Go scanner, "methodologically based on testssl.sh and the SSL Labs rating guide" **[reported]** | Remote | Not stated | Yes (stated) **[reported]** | No | Closest same-language, same-methodology-family peer found; a browser-hosted free tool, not clearly open source. No CBOM or PQC differentiation found. |

### 2.2 Certificate / PKI discovery and lifecycle platforms (agent/enterprise tier)

| Product | Discovery model | PQC | CBOM/SBOM | Notes |
|---|---|---|---|---|
| **Keyfactor** | Network scanning **plus** CA synchronization **plus** agent-based collection **[reported]** | Acquired InfoSec Global and CipherInsights (2025) specifically for PQC/crypto-agility capability **[reported]** | Not CycloneDX-CBOM-branded in what we found | Reported ceiling ~500K certificates vs Venafi's 1M+ **[reported]**. |
| **Venafi (CyberArk)** | "Deepest in the category": network scanning + CA sync + agents, extends to SSH keys and code-signing **[reported]** | Reported as "in development" post-acquisition **[reported]** | Not found | The clearest example of what *agent-based* discovery buys you beyond what any remote scanner can: SSH key inventory, code-signing keys — none of that is TLS-observable, ever, remotely. |
| **DigiCert (CertCentral)** | CA-centric; discovery less prominent than Keyfactor/Venafi **[reported]** | PQC at the CA level (customers get PQC cert issuance as DigiCert's own infra updates) **[reported]** | Not found | DigiCert's own 2026 survey (see §4) is one of the better-sourced adoption-gap data points found. |

**[my inference]**: every enterprise platform in this tier treats *remote scanning as the shallowest of several discovery tiers*, never the only one. That is the single most load-bearing fact for §3's answer to "can a meaningful CBOM come from a remote scan alone."

### 2.3 CBOM / SBOM tooling (source, container, and now — with this project — network)

| Tool | Source of truth | What it can see | What it explicitly cannot | Format |
|---|---|---|---|---|
| **sonar-cryptography** (SonarQube plugin, IBM/PQCA) | Java and Python **source code** | Cryptographic API *usage* in code, with file/line location | Runtime materials: deployed certs, keys on disk, `java.security` policy, OpenSSL config **[reported, from the tool's own docs]** | CycloneDX CBOM |
| **CBOMkit-theia** (Go CLI, PQCA) | Container images and local directories (via Anchore Stereoscope for images) | Certificates, keys, secrets, crypto-relevant config files sitting in the filesystem/image layers | Anything not materialized as a file — a TLS session's negotiated behaviour, a remote endpoint it doesn't have filesystem access to | CycloneDX 1.6 |
| **CBOMkit** (web UI + API + OPA policy engine) | Aggregates the above | Compliance evaluation over aggregated CBOMs | Nothing new; it's an aggregation/policy layer | CycloneDX |
| **This project (host side)** | `dpkg`/`apt` status file, more collectors planned | Installed packages that *can* provide an algorithm (capability, explicitly not observed use) | Whether the capability is actually invoked at runtime | CycloneDX 1.6 |
| **This project (network side, new)** | An active TLS scan | What a specific handshake *did* — closer to "observed use" than any of the above, for the TLS surface specifically | Everything the scan doesn't touch: private keys, HSM backing, non-TLS crypto, application-layer crypto, anything requiring auth this scanner doesn't have | CycloneDX 1.6 |

**[my inference, the key finding of this section]**: no tool researched combines *source-code* CBOM, *container/filesystem* CBOM, and *network-observed* CBOM under one evidence model that's honest about which is which. IBM/PQCA ship three separate tools (sonar-cryptography, theia, and now presumably something for runtime) rather than one document type with per-fact provenance. This project already emits CycloneDX from both a host inventory *and* a network scan — the opportunity is to make the *provenance* of every fact in either document explicit and machine-readable, not just described in prose (§6, §8 PRD-002).

## 3. The two things the research says everyone gets wrong

### 3.1 Single-probe scanners under-report hybrid PQC support

**[reported, José Luis Delgado, "Observability for Post-Quantum TLS Readiness: A Multi-Surface Evidence Framework," arXiv:2605.02978 / IACR ePrint 2026/866, May 2026]** — the most directly relevant source found. Key findings as reported by the paper (not independently reproduced against a live server population by us):

- A packet-inspection baseline detected only 2 of 29 local test runs, and **0 of 23 TLS 1.3 runs** — because a single default probe never *offers* the hybrid group, so a server that supports it is never asked.
- In a controlled comparison, testssl.sh and SSLyze's single-probe approach confirmed 0 hybrid-capable targets where **deliberate dual-probe measurement confirmed 70**.
- In a public campaign across 1000 targets, active probing "identifies 310 cases where endpoint capability exceeds what any single classical session view reveals."
- The paper's central design recommendation: **keep capability separate from negotiation** — a dual-probe architecture, with distinct rule sets for "what the server supports" vs. "what it actually negotiated."

This is exactly the failure mode this project's own probe design (`internal/tlsprobe/hellos.go`'s `tls13Hello` with an empty `key_share`) was built to avoid — **[verified]**, our own hermetic tests (`TestReadinessAgainstRealServers`) already assert the hybrid group is found even when it isn't what a default client negotiates. But: our *CBOM output* does not yet mark, as a separate typed fact, which one specific group/suite among the enumerated set was the one a standard client actually got. That's PRD-002 feature 2.

### 3.2 The paper's evidence taxonomy

**[reported, same source]** — the framework's seven "measurement planes" (session behavior, key establishment, endpoint capability, authentication, lifecycle, observability, policy) and, more directly reusable, its evidence classification:

- **Observed** — directly visible from TLS traffic.
- **Inferred** — deduced from observed signals but not explicitly communicated by the peer.
- **Unknown** — cannot be determined through remote inspection.

...plus an explicit statement that "certain aspects of post-quantum cryptography readiness cannot be determined remotely via passive TLS observation," naming internal deployment status, migration schedules, backend readiness, and key material generation/storage as requiring direct endpoint or application access.

**[my inference]**: this maps closely onto — and validates — the evidence-tier concept this project already applies to *findings* (`internal/eval`), but the paper's taxonomy is a genuine three-way split (Observed/Inferred/Unknown) plus, implicitly, a fourth state this project already needed and named: *not applicable* (e.g. "signature algorithm" doesn't apply to a TLS 1.3 group). PRD-002 formalizes a five-state version (§6) and applies it to the CBOM specifically, which nothing researched here does.

## 4. The state of PQC adoption in the wild (grounds the priority list in §7)

**[reported, "Measurement Study of Post-Quantum Readiness of Internet: 2026," arXiv:2606.16473]** — 32,011 domains across sectors:

- **49.3%** support hybrid post-quantum key exchange (e.g. `X25519MLKEM768`).
- **15.7%** of domains — concentrated in banking and government — are still TLS 1.2 only.
- **0%** observed adoption of hybrid/post-quantum *certificates*.

**[reported, DigiCert 2026 Quantum Readiness Outlook]**: 87% of organizations are planning/testing/implementing PQC; only 7% have more than half their certificates on quantum-safe or hybrid crypto. Top blocker cited: legacy system complexity (26%), then performance and budget (19% each).

**[reported, same measurement paper]**: mutual-TLS adoption on public-facing servers is 6.2% overall.

**[my inference, the headline takeaway for PRD-002 prioritization]**: **key exchange is racing ahead of authentication.** Roughly half the web already negotiates a hybrid group, while essentially none of it has moved certificates. A readiness product that reports one blended number hides this. This project's own readiness model *already* separates key-establishment from authentication as distinct dimensions (L3 "hybrid negotiated" vs. L4 "PQ-authenticated") — the research confirms that split is the right one and that L4 will, correctly, stay near-empty across the whole internet for a long time yet. That's a finding worth stating plainly in the product's own UI/docs rather than leaving implicit.

## 5. Remote scan vs. other visibility: what's observable and what isn't

Answering the brief's explicit question directly.

| Fact | Remote TLS scan | Why |
|---|---|---|
| Supported protocol versions | **Observed** | Directly probed (`internal/tlsprobe`, stage 1). |
| Cipher suites accepted, per version | **Observed** | Directly enumerated (stage 2). |
| Key-exchange groups the server will negotiate (capability) | **Observed** | Via HRR with empty `key_share` (§3.1). |
| Which one group/suite a *standard client* actually gets (negotiation) | **Observed**, but today not distinguished from capability in the CBOM (PRD-002 fixes this) | A full handshake (`certs.go`). |
| Certificate chain, subject, issuer, validity, SANs | **Observed** | Sent in the clear (TLS ≤1.2) or via a completed handshake (TLS 1.3). |
| Certificate's signature and public-key algorithm | **Observed** | Parsed from the certificate. |
| Whether the *client's own* certificate would need to be presented (mTLS) | **Not observed today**; observable via a `CertificateRequest` probe (PRD-002 feature 3) | Requires attempting a handshake and watching for the request. |
| HSTS / other HTTP security headers | **Not observed today**; observable with one HTTP request post-handshake (PRD-002 feature 4) | Not part of the TLS layer at all — this is why SSL Labs' A+ needs it and why it's a separate check. |
| DH group matching a known RFC 7919 group | **Partially observed** (prime size + fingerprint only; no lookup table yet) | Known gap, not in PRD-002 (small, P2). |
| **Private key material, HSM/TPM backing, key exportability** | **Not observable, ever, remotely** | The private key never crosses the wire. No remote scanner, ours or anyone's, can see this — confirmed by every agent-based platform researched (§2.2) building a *separate* collection path for exactly this reason. |
| **Whether an algorithm the server's software supports is actually *in use* vs merely linked in** | **Not observable, ever, remotely** — this is the same capability-vs-use line this project already draws for host CBOMs (`ProvidedBy`) | Requires source, binary, or runtime instrumentation (CBOMkit-theia's own stated limitation, §2.3). |
| Non-TLS cryptography (disk encryption, application-level crypto, database TDE, ...) | **Not applicable** to a TLS scanner | Different discovery surface entirely; out of scope for this tool by design, not a gap. |
| Internal migration timelines, governance, vendor contracts | **Not applicable** to any scanner | This is a process/organizational fact, not a technical one — the 75-question PQC readiness checklists researched (§2, Encryption Consulting) are explicitly *process* assessments, not scans. |
| Whether a certificate uses the new IETF Composite ML-DSA hybrid signature | **Partially observable** (the OID is visible; this project doesn't yet recognise the composite OID specifically) | Small, real gap; low urgency given 0% observed adoption today (§4). Tracked as P2. |

**Direct answer to the brief's question: yes, a meaningful CBOM can be built from a remote TLS scan alone** — for the TLS surface specifically, and this project already does it (`tls scan --cbom`, built in the prior session). It is **not**, and cannot become, a complete cryptographic inventory of the endpoint: no remote scanner can see private keys, HSM backing, non-TLS crypto, or actual (vs. capable) use. The right response is not to pretend otherwise; it's what PRD-002 does — make every fact in the CBOM say, machine-readably, which of these it is.

## 6. Proposed evidence model for the CBOM specifically

Extending the paper's three states (§3.2) with the two this project's own findings model already needed:

| State | Meaning | CBOM encoding |
|---|---|---|
| **Observed** | A server reply demonstrated it directly. | `evidence.identity.confidence = 1.0` |
| **Inferred** | A necessary consequence of something observed, not independently confirmed (e.g. "the certificate's key size implies this key-exchange scoring band"). | `evidence.identity.confidence = 0.7` (this project's own choice of number — see PRD-002 feature 1 for why) |
| **Not observable remotely** | This scan, by construction, cannot see it (private key material, HSM backing). | The component/field is **omitted**, with a documented, tested reason — never asserted with low confidence, since "low confidence" still implies an attempt was made. |
| **Not applicable** | The concept doesn't apply to this asset (a TLS 1.3 suite has no separate key-exchange field). | Field simply absent — this is already this project's convention everywhere (`omitempty`). |
| **Unknown / inconclusive** | An attempt was made and failed to produce a result (a timeout, a malformed reply). | Carried today as `Report.Incomplete` + a note; PRD-002 does not change this, it's already handled. |

This reuses CycloneDX's own `evidence` object (confirmed present and used this way by real tooling — CBOMkit's `identity.confidence 0-1` field, §1 research) rather than inventing a new custom-property scheme, keeping the CBOM consumable by any CycloneDX-aware tool, not just this UI.

## 7. Gap matrix and prioritization

| Capability | testssl.sh | SSLyze | Keyfactor/Venafi | CBOMkit family | **CipherHorizon (before this work)** | **After PRD-002** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Deep active TLS/SSL enumeration (SSLv2 → 1.3) | ✅ | ✅ | ❌ (not their job) | ❌ | ✅ | ✅ |
| PQ hybrid *capability* found even when not negotiated | Partial (reported 0/70 in controlled test) | Partial (same) | ❌ | ❌ | ✅ | ✅ |
| PQ hybrid *capability* explicitly separated from *negotiation* in output | ❌ | ❌ | n/a | n/a | ❌ | ✅ (feature 2) |
| STARTTLS | ✅ | ✅ | n/a | n/a | ❌ | ❌ (documented gap, not closed this round — see §9) |
| CBOM output (CycloneDX) | ❌ | ❌ | ❌ (not CBOM-branded) | ✅ (source/container only) | ✅ (host + network, both directions) | ✅, with per-fact evidence |
| Per-fact evidence/confidence in the CBOM itself | ❌ | ❌ | n/a | Partial (identity confidence, no PQC-specific tiering found) | ❌ | ✅ (feature 1) |
| HSTS / HTTP-layer check | Some (reported) | Some (reported) | n/a | n/a | ❌ | ✅ (feature 4) |
| mTLS / client-cert-required detection | Not confirmed | Not confirmed | ✅ (via agent) | n/a | ❌ | ✅ (feature 3) |
| Agent-based / SSH-key / code-signing-key inventory | ❌ | ❌ | ✅ | n/a | ❌ | ❌ (explicitly out of scope — see architecture principle 1, push-not-pull) |
| Self-hosted, open source, no account | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |

**Table-stakes this project still lacks**: STARTTLS, HSTS. Both real, both well-documented, neither closed in this round (§9 explains why, and lists them P1 for next).

**Genuine differentiators after this round**: explicit capability-vs-negotiation separation in a *CBOM*, and a documented, tested, five-state evidence model applied to CBOM output — nothing researched does both together.

## 8. See [PRD-002](PRD-002-evidence-and-coverage.md) for the resulting feature specifications, acceptance criteria and priorities.

## 9. What this research explicitly rules out building this round, and why

- **STARTTLS** (SMTP/IMAP/POP3/...): real, well-evidenced gap (§2.1, §4's "enterprise blind spot" framing). Not attempted this round because it is a genuinely large addition — a protocol-priming layer ahead of the TLS handshake, for several distinct wire protocols, each needing its own hermetic test server to test honestly (this project's own testing discipline, §1, requires that, not a live mail server). Doing it well is a multi-feature project of its own; doing it shallowly would violate this project's "omit, don't guess" ethos by half-supporting it. Tracked P1 in PRD-002's backlog with the scoping already worked out (SMTP first).
- **Composite/hybrid certificate signature recognition**: real per the IETF adoption of Composite ML-DSA into the standards track (§2.3), but **0% observed real-world adoption** (§4) makes it low urgency today. P2.
- **Fleet-wide CBOM merge** (one document across many endpoints): a genuine enterprise want, but secondary to fixing what a *single* endpoint's CBOM says first. P1 backlog.
- **Agent-based / SSH / code-signing inventory**: this is what Keyfactor and Venafi's agent tier does, and it's a different product shape (push-based, credentialed) than this project's stated architecture principle 1 ("push, not pull... nothing logs in to your machines"). Not a gap to close; a deliberate non-goal, restated here so it isn't mistaken for an oversight.
- **JARM/JA3 fingerprinting** (tlsx's niche): useful for internet-scale asset clustering, not for PQC/CBOM depth. Out of scope for this round; not currently planned.
