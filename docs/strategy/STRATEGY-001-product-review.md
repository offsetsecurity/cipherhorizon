# STRATEGY-001 · Product review: is CipherHorizon differentiated, correctly positioned and worth building?

| | |
|---|---|
| **Role** | Product manager and cybersecurity product strategist (the brief in the request) |
| **Date** | 2026-09-26 |
| **Method** | A re-read and measurement of this repository, plus current web research (dated sources at the end). Every claim is tagged **[repo]** (verified against this tree), **[source]** (a primary source or the product's own documentation), **[vendor]** (a vendor's marketing claim, not independently reproduced) or **[inference]** (my judgement). |
| **Supersedes** | The market section of [RESEARCH-002](../product/RESEARCH-002-pqc-tls-cbom-landscape.md), written before several of the open-source competitors below existed or were visible. |
| **Not established** | Pricing (no vendor publishes it), trademark clearance for any name, and anything a vendor's page does not say. "n/d" means *not disclosed on the page I read*, not "absent". |

## 0. The verdict, first

**Reposition and narrow. Do not pivot, and do not stop.**

- **Stop calling it, or building it as, a "CBOM tool".** CBOM is one *output*. The market's own vocabulary is *cryptographic inventory → posture → crypto-agility*, and the buyers' mandates are about **inventory and migration**, not a file format.
- **Stop trying to discover everything.** The open-source field already covers source-code CBOM (IBM's CBOMkit family, `cdxgen`), and several small tools now cover filesystems, containers and Linux hosts. Rebuilding those is a losing race for a small team.
- **Own what is genuinely hard to copy and is currently undersold:** an *evidence-graded* inventory (every statement says how strong its evidence is, and what was *not* seen), the deepest *active* PQC TLS enumeration in the open-source field, and a *native Windows* inventory nobody else documents. Then become the **correlation and posture layer that ingests other tools' CBOMs** instead of competing with them.
- **Fix the one structural weakness the research exposed:** the product is two disconnected models (TLS endpoints and hosts) with a manual link between them. Correlation, not another sensor, is what turns "a set of scanners" into "an inventory".

Full verdict in §13.

---

## 1. What the product is today (current state, not the pitch)

### 1.1 In one paragraph **[repo]**

CipherHorizon is a self-hosted Go program (about 17,900 lines of non-test Go, 11,300 lines of tests, 3,300 lines of vanilla JavaScript and CSS) shipped as two static binaries. `cipherhorizon` runs a web UI and JSON API (30 routes, SQLite with 6 data tables plus a migrations table), an active TLS scanner and a host inventory command; `cipherhorizon-collector` (about 4 MB) is a read-only host inventory program with no network code. The README describes it as "a vendor-neutral, open-source tool for cryptographic posture". Nothing has been published: no repository exists, no release has been tagged, and there are no users.

### 1.2 What it collects, and how

| Source | How | What it yields | Validated on |
|---|---|---|---|
| **TLS endpoints** (`tls scan`, UI) | An **own TLS wire-protocol stack** (`internal/tlsprobe/wire`) that can send hellos Go's `crypto/tls` will not: SSLv2/3, export/NULL/anonymous suites, arbitrary group lists. Post-quantum groups are found by *enumeration* (an empty `key_share` makes the server name its chosen group in a HelloRetryRequest). | Protocol versions, every accepted cipher suite, every accepted key-exchange group including hybrids, certificate chain, trust and name checks, optional HSTS, 17 cited finding rules, a PQC readiness level (L0 to L4), a 0 to 100 "TLS hygiene" score, and a CycloneDX 1.6 CBOM of the endpoint | Hermetic in-process servers, never a third party |
| **Linux hosts** (`run`, sensor `apt`) | Reads the dpkg database from a filesystem | Installed crypto packages, mapped to algorithms from a cited knowledge table | **Fixtures only; never a live Linux host** |
| **Windows files** (sensor `pe-files`) | Walks Program Files, ProgramData and per-user Programs; opens only files whose *name* matches a crypto library; reads the PE version resource, SHA-256 and static import table with a hand-written fuzzed reader | Library, version, hash, dependency edges (`openssl.exe → libssl → libcrypto`), capability mapped from cited knowledge | One Windows 11 machine, standard user, against an independent PowerShell oracle |
| **Windows native** (sensor `windows-cng`) | Asks Windows through CNG, key storage and legacy-CSP APIs; probes ML-KEM and ML-DSA parameter sets | 19 providers, 51 algorithm identifiers, six confirmed PQC parameter sets, retired algorithms with cited status | Same machine, against a C# and `certutil` oracle |
| **Uploaded CBOMs** | `POST /api/v1/hosts/ingest` accepts any CycloneDX JSON, up to 32 MiB | The same PQC classification, coverage card and history | n/a |

**Not collected at all** **[repo]**: certificates or keys on a host, source code, container images, cloud resources (KMS, Key Vault, load balancers), Kubernetes, databases, running processes, application configuration, Schannel or other policy, HSM or TPM contents, SSH, STARTTLS protocols. **RPM/APK, macOS and Windows Server/ARM64 are unsupported or untested.**

### 1.3 What is stored, correlated and shown **[repo]**

- **Stored:** `assets` (a TLS endpoint or a host, with name, address, tags, notes, rescan interval), `scans` (200 kept per asset, with the full report and evaluation as JSON blobs), `scan_events`, `finding_status` (acknowledge/accept), `host_snapshots` (50 per host, raw CBOM plus a summary), `asset_links`. There is **no** owner, environment, business application, criticality or exposure field.
- **Correlated:** only what a person links by hand (`asset_links`: "this host and this endpoint are the same machine"). **Nothing is correlated automatically.** A certificate is not an entity: it lives inside a scan's JSON, so "which certificates expire, and where are they used?" is answered only per endpoint.
- **Shown:** dashboard (readiness, hygiene, ranked findings, expiring certificates, a "next step"), endpoint pages with history and diff, host pages with coverage and blind spots, a findings list with a status workflow, an About page explaining the scales, CSV export of endpoints, a CBOM download per scan or upload.
- **Access:** one shared bearer token, no accounts, roles, audit log or TLS listener; loopback by default.

### 1.4 What the product claims, and where the claim runs ahead of the code

| Claim in the docs and UI | Reality |
|---|---|
| "One place to see what cryptography your endpoints and hosts use" | Two separate views joined by a manual link; host cryptography is limited to what the three sensors can see |
| A nav item and a README bullet called **CBOM** ("CBOM, both directions") | The CBOM is an *export* of an inventory the product already holds; the top-level nav entry is a list that duplicates each asset page |
| "Hosts" page: "the cryptographic software found inside your machines" | Accurate for Windows files and providers and Debian packages; silent on the rest |

**Terminology worth naming:** "CBOM" appears in the UI, README and API where "inventory" or "asset" is meant. The project was already renamed once (from `cbom-scan`), which removed the format from the *name* but not from the *positioning language*.

### 1.5 Architecture, honestly

Decisions worth keeping: sensors observe and never infer; capability comes from *cited* knowledge; nothing is stronger than the weakest evidence; blind spots are data; a small read-only collector separate from the server; strict security defaults. **Costs:** an engineering-heavy, distribution-light project (13 ADRs, 430 tests, zero users), and a split between the TLS side (JSON report blobs) and the host side (an evidence graph).

---

## 2. The competitive landscape

### 2.1 Standards and ecosystem

- **CycloneDX** is the de facto format and is now an international standard. **CycloneDX 1.7 was released on 21 October 2025 and adopted as ECMA-424 2nd edition in December 2025** **[source]**. CBOM (cryptographic asset types for algorithms, keys, certificates and their relationships to software) arrived in 1.6; **1.7 adds a standardised list of algorithm families and elliptic curves and a Cryptography Registry** to fix "inconsistent naming and classification of cryptographic algorithms across different tools" **[source]**.
- **What is standardised versus vendor-specific:** the *schema* is standardised. Which fields a tool fills, how it expresses *confidence* and *evidence*, and how it says "capable" versus "used" is **not**; each tool invents properties. cdxgen documents that `algorithmFamily` and `ellipticCurve` are dropped when downgrading below 1.7 and that unmappable curves degrade to a deprecated free-text field **[source]**. **CipherHorizon emits 1.6 and puts its evidence model in `cipherhorizon:*` custom properties**, which a generic consumer ignores.
- **Government mandates that create demand** **[source, secondary for the EU and NIST timelines]**: OMB M-23-02 and NSM-10 (US federal inventories); **CISA's 2024 strategy for automated cryptography discovery and inventory (ACDI)**; NIST IR 8547 (RSA and ECC deprecated by 2030, disallowed by 2035); the EU roadmap (member states to **initiate cryptographic inventories by the end of 2026**, high-risk use cases migrated by 2030); NIST NCCoE SP 1800-38 (a lab evaluating discovery tools).

**The most useful primary source found: CISA's ACDI strategy (August 2024)** **[source]**. It says M-23-02 asks for nine data items per cryptographic system, that *most cannot be collected by tools*, and that only three can: **(4) the algorithm, the service provided (key exchange, encrypted connection, or signature) and the key length; (5) whether the software is COTS, GOTS or custom, and its vendor; (6) the operating system with version.** It names four discovery types for ACDI tools (**network, file system, database system, software package**), states that CISA "has not been able to confirm" whether tools can detect *embedded* algorithms, and asks for CDM integration and an annual submission. **This is a concrete buyer requirement, and §6 measures us against it.**

### 2.2 Open source

| Project | What it is | What it does, per its own documentation | Notes |
|---|---|---|---|
| **IBM CBOMkit** (Apache-2.0) | A toolset: `sonar-cryptography` ("hyperion"), `theia`, `coeus`, a database with a REST API, an OPA-based compliance check | Scans **git repositories** (not built first) for cryptographic use. Languages: Java (JCA, BouncyCastle light-weight), Python (pyca), Go (standard library; `x/crypto` partial), C# in development. Viewer with statistics; compliance check against a "quantum-safe" allow-list of OIDs and names, extensible with Rego; Docker Compose, Podman, Helm | Latest release listed 2.3.0; a release every one to three months. States its limit plainly: it does not build repositories |
| **CBOMkit-theia** | Filesystem and container scanner in the same family | Directories, Docker/OCI images and registries. Plugins: **certificates**, **secrets/keys** (via gitleaks), **OpenSSL configuration**, **Java security**. Produces or *enriches* a CycloneDX 1.6 CBOM, with confidence levels | "Does not perform source code scanning" |
| **cdxgen** (OWASP) | The CycloneDX SBOM generator, with CBOM support | `cbom` alias or `--include-crypto`: Java and Python source, JavaScript/TypeScript constant propagation through `node:crypto`, WebCrypto and JWT sites, .NET via `dosai` (algorithms only when mappable to a known OID), plus keystores and certificates; server mode and Dependency-Track submission | The ecosystem's reference generator; requires spec 1.6+ |
| **CBOM-Lens** (Apache-2.0, OmniTrustILM) | CLI | **Filesystems, containers and network ports** (nmap for TLS and SSH); certificates, keys, secrets and algorithms **including PQC by OID matching**, deliberately omitting unmapped values rather than guessing; CycloneDX **1.6 and 1.7**; manual, timer and discovery modes; upload to a CBOM repository | The closest architectural neighbour to our sensors |
| **CipherIQ cbom-generator** (GPL-3.0 or commercial) | C11 CLI, **Linux only** | Filesystem, running processes, listening ports, Apache/Nginx/OpenSSH/Postfix configuration, ELF SONAME dependencies; certificates, keys (7 formats), algorithms, libraries, protocols (TLS, SSH, IPsec, QUIC, WireGuard), cipher suites, applications and services **with dependency relationships**; PQC classification (safe, transitional, deprecated, unsafe) with break-year estimates; a migration report; CBOM 1.6 and 1.7 | Small (8 stars at the time of reading); dual licensing signals a commercial intent |
| **cbomscope** (MIT) | Single static Go binary, no server or database | Go sources (AST) and **live TLS endpoints**, observing the *negotiated* version, suite and group ("the only place an inventory can see a hybrid key exchange already in production"); posture classes; CBOM 1.6 with custom properties | Self-described as "early, and narrower than it will be". **Architecturally the most similar to us** |
| **CipherRadar, CryptoScan (QRAMM)** | Source-first scanners | Tree-sitter, taint rules and YARA-X binary scanning (CipherRadar); codebase scanning (CryptoScan) | Small projects |
| **testssl.sh, SSLyze** | Classical TLS scanners | Deep classical TLS assessment | A 2026 measurement paper reports they treat post-quantum group IDs as unknown **[source, secondary; not independently reproduced]** |

### 2.3 Commercial

Sources are the vendors' own pages unless noted. **Treat all capability claims as [vendor].** Several comparison articles ranked these products, but the two most prominent were written by competing vendors (Encryption Consulting, QCecuring), so I used them only to identify names.

| Product (company) | Target customer | Discovery method | What it says it finds | CBOM / CycloneDX | PQC and agility | Integrations and deployment |
|---|---|---|---|---|---|---|
| **AQtive Guard** (SandboxAQ; also owns Cryptosense) | Large enterprise, government | Correlates **code, runtime and network** sources; network analysis, runtime tracing, filesystem | Certificates, deprecated algorithms (MD5, SHA-1, DES, RC4, short RSA), unmanaged keys, unencrypted private keys, quantum-vulnerable key exchange and signatures | "Complete CBOMs" and exportable reporting | Positions itself as **Cryptographic Posture Management**; risk mapping by owner, dependency and blast radius; impact simulation; orchestration of rotations and PQC migration | AWS, ServiceNow, GitLab, SentinelOne, Qualys, GitHub, Palo Alto |
| **AgileSec** (Keyfactor, from InfoSec Global, acquired 2025) | Enterprise; PKI and CLM customers | **Sensors** that scan code, servers, endpoints, cloud workloads and network traffic, or reuse EDR and vulnerability tools | TLS certificates, SSH keys, tokens, algorithms, protocols, libraries | Not stated on the product page (a Keyfactor blog says it builds a CBOM) | Quantum-vulnerable identification and progress tracking; compliance mapping to NIST and PCI-DSS (more on the blog) | CLM, GRC, ITSM and CMDB; on-prem or cloud |
| **Guardium Quantum Safe / Cryptography Manager** (IBM) | Large enterprise | Static code analysis, binary scanning, and IBM's CBOM lineage (Quantum Safe Explorer) | "Cryptographic objects and IT assets"; shadow cryptography; dependencies, ownership, usage | Quantum Safe Explorer generates a CBOM; not on the Cryptography Manager page | PQC risk and feasibility assessment; policy enforcement; key and certificate lifecycle automation | Key management for IBM and non-IBM storage |
| **Quantum Command / ACDI** (Tychon) | US federal | **Endpoint agent** (or agentless queries); partnership to run inside HCL BigFix | Cryptographic libraries, protocols, certificates, algorithms; TLS configuration | n/d | Maps assets to business criticality and compliance; NSM-10 alignment | Sold through GSA MAS, DHS CDM APL, NASA SEWP and DoD ESI BPA |
| **COMPASS** (CryptoNext) | OT, IoT, manufacturing, healthcare | **Passive network probe** (100+ protocols) | Protocols, certificates, algorithms | CBOM format [vendor, via survey] | Quantum-vulnerable detection | Taps and SPAN |
| **CipherInsights** (Quantum Xchange; reported acquired by Keyfactor) | Government, finance | Passive network monitoring | TLS, certificates, suites | n/d | Progress dashboard | Passive |
| **AVX ONE PQC Assessment** (AppViewX) | DevSecOps enterprises | Static code, dependency and configuration analysis, CI/CD, certificates | Application code, libraries, certificates, configs | CBOM and CSV | Readiness score, remediation | CI/CD, plus PKIaaS that issues PQC certificates |
| **CBOM Secure** (Encryption Consulting) | Enterprise | Multi-source (cloud KMS, HSM, vaults, network, code, filesystems) | Broadest claimed | CycloneDX | Native | Agentless plus optional agent. **Vendor-authored comparison; treat with caution** |
| **Others** | | QuSecure (a Gartner "sample vendor" for crypto-agility), ISARA Advance (integrates NDR/EDR data), PQStation QVision (endpoint sensors), QryptoCyber | | | | |
| **Machine-identity and CLM platforms** (CyberArk/Venafi, DigiCert, Sectigo, Entrust, Keyfactor) | PKI teams | Certificate and CA connectors | Certificates, keys, issuance | Increasingly | PQC-ready issuance | **They are competitors for the certificate half of the problem even though they do not say "CBOM"** |

### 2.4 What the survey tells us about the market **[inference]**

1. **Three tiers exist.** (a) Free source and artifact scanners (IBM, cdxgen, and a growing set of small tools); (b) endpoint and network discovery sold to federal and large enterprise (Tychon, AgileSec, AQtive Guard, COMPASS); (c) certificate and machine-identity platforms adding PQC.
2. **The category name is "posture" or "agility", not "CBOM".** SandboxAQ and Entrust write "Cryptographic Posture Management", IBM writes "cryptographic security posture management", Keyfactor and QuSecure write "crypto-agility", and Gartner's own quoted definition is about swapping algorithms and artefacts. The one tool family that leads with the format is IBM's *open-source* toolkit.
3. **Every serious vendor sells breadth plus context plus integration.** None competes on a single scanner.
4. **CISA itself doubts detection completeness.** That is an opening for a product that states, per asset, what it could not see.

---

## 3. Capability matrix

Legend: **Yes** documented, **Part** partial or limited, **No** not present or not documented as present, **n/d** the source does not say, **(v)** vendor claim. "Ours" is verified against the repository and is deliberately not flattering. Columns are ordered by relevance to us.

### 3.1 Discovery

| Capability | **Ours** | CBOMkit family | cdxgen | Other OSS (CBOM-Lens, CipherIQ, cbomscope) | AQtive Guard | AgileSec | Tychon |
|---|---|---|---|---|---|---|---|
| Source-code scanning | **No** | Yes (Java, Python, Go, C# in dev) | Yes (Java, Python, JS/TS, .NET) | cbomscope: Go only | Yes (v) | Yes (v) | n/d |
| Binary scanning | **Part** (PE version, import table, hash; no code analysis) | No | No | CipherRadar: YARA-X binary | n/d | n/d | n/d |
| Container images | **No** (a mounted root can be scanned; no image handling) | Yes (theia) | SBOM yes; crypto n/d | CBOM-Lens: yes | n/d | n/d | n/d |
| OS / package scanning | **Yes** on Debian and Ubuntu (fixtures only) | No | No | CipherIQ (Linux; ELF SONAME) | n/d | n/d | n/d |
| Host scanning | **Part** (Windows files and native; Linux packages) | Part (directories) | No | CBOM-Lens, CipherIQ | Yes (filesystem) | Yes (agent) | Yes (agent) |
| Endpoint agent / fleet | **No** (a collector you run and upload by hand) | No | No | CBOM-Lens timer mode | n/d | Yes | Yes |
| Network scanning | **No** (no passive capture, no port sweep) | No | No | CBOM-Lens (nmap) | Yes | Yes | Yes |
| **Active TLS scanning** | **Yes, deepest in the set** (own stack; every accepted suite and group) | No | No | cbomscope (negotiated only), CBOM-Lens (nmap) | Yes (passive) | Yes (traffic) | Yes |
| Certificate discovery | **Part** (from TLS chains only; no host stores) | Yes | Yes | Yes | Yes | Yes | Yes |
| Key discovery (unprotected keys) | **No** (deliberately never opens key files) | Yes (gitleaks) | Part | CBOM-Lens, CipherIQ | Yes | Yes | n/d |
| Keystore discovery | **No** | Part | Yes | n/d | Yes | n/d | n/d |
| HSM / TPM | **No** (TPM provider listed by name only) | No | No | No | Part | n/d | n/d |
| Cloud (KMS, Key Vault, LB) | **No** | No | No | No | Yes (AWS integration) | Yes (cloud workloads) | Yes (cloud) |
| Kubernetes | **No** | Helm deployment only | Part | No | n/d | n/d | n/d |
| Database | **No** | No | No | No | n/d | n/d | n/d |
| Application discovery | **No** | No | n/d | CipherIQ (applications, services) | Yes (v) | n/d | Yes (v) |
| Runtime discovery | **No** | No | No | No | **Yes** (instrumentation) | n/d | Part |
| Configuration discovery | **No** (Schannel, sshd, web servers all missing) | Part (OpenSSL) | No | CipherIQ (Apache, Nginx, sshd, Postfix) | Yes | Yes | Yes (TLS config) |
| Dependency discovery | **Part** (static imports and provider edges on Windows) | Part (between assets) | Yes (SBOM) | CipherIQ (dependency relationships) | Yes (v) | n/d | n/d |
| **Native OS crypto providers** (CNG, KSP, CSP) | **Yes** (first of its kind that I could find documented) | No | No | No | n/d | n/d | n/d |

### 3.2 Cryptographic detail

| Capability | **Ours** | CBOMkit family | cdxgen | Other OSS | Commercial (claims) |
|---|---|---|---|---|---|
| Algorithms | Yes (family level on hosts; suites and groups on TLS) | Yes (with parameters from code) | Yes | Yes | Yes |
| **Key sizes** | **TLS: yes (certificates). Hosts: no** | Yes (from code) | Part | Yes | Yes |
| Curves | TLS yes; hosts no | Yes | Part | Yes | Yes |
| Cipher suites | **Yes, all accepted** | Part (config) | No | CipherIQ yes | Yes |
| Protocols | Yes (TLS versions) | Part | No | CipherIQ (TLS, SSH, IPsec, QUIC...) | Yes |
| Certificate chains | Yes (TLS) | Part | Part | Yes | Yes |
| Key-to-certificate relationships | **No** | n/d | n/d | n/d | n/d |
| Libraries and versions | Yes (files and packages; the version is what the file claims) | No | Yes | CipherIQ | Yes |
| Hardware crypto, HSM usage | **No** | No | No | No | Part |
| Signing, hashing, encryption, key exchange | Algorithm level only | Yes (from code) | Yes | Yes | Yes |

### 3.3 Context (the enterprise differentiator)

| Question | **Ours** | Open source | AQtive Guard | AgileSec | Tychon |
|---|---|---|---|---|---|
| Where crypto is used / which application / service | **Only which file or endpoint** | Code location (source tools) | Yes (v) | Yes (v) | Yes (v) |
| Which business application owns it; who owns the system | **No** (tags and notes only) | No | Yes (owners, blast radius) | Yes (CMDB) | Yes (criticality) |
| Environment, production or not | **No** | No | n/d | Yes (v) | n/d |
| Internet exposure | **No** (a scanner reaches what you give it; nothing says it is exposed) | No | Yes (v) | Yes (v) | n/d |
| Criticality | **No** | No | Yes (v) | Yes (v) | Yes (v) |

### 3.4 CBOM

| Capability | **Ours** | CBOMkit family | cdxgen | Other OSS | Commercial |
|---|---|---|---|---|---|
| CycloneDX CBOM generation | **Yes, 1.6** (not 1.7) | Yes, 1.6 (a PR to 1.7 exists) | Yes, 1.6 and 1.7 | CBOM-Lens, CipherIQ: 1.6 and 1.7 | Yes |
| Import and view third-party CBOMs | **Part** (upload works but is framed as "hosts") | Yes (coeus) | n/a | CBOM-Lens: uploads to a repository | n/d |
| **Evidence and provenance** | **Yes, the strongest documented** (method, quality, claim class, coverage, blind spots) but in custom properties | Confidence levels (theia) | Minimal | CBOM-Lens: omits rather than guesses | n/d |
| Relationships | Part (provides, dependsOn) | Part | Yes (SBOM graph) | CipherIQ | Yes |
| Machine-readable API, versioned, CBOM diff | API yes (30 routes, no OpenAPI); **CBOM diff: endpoints only** | REST API | CLI and server | n/d | n/d |
| Historical comparison | Endpoints yes; **hosts no** | Database | Dependency-Track | n/d | Yes (v) |

### 3.5 PQC and risk

| Capability | **Ours** | Open source | Commercial |
|---|---|---|---|
| RSA and ECC identification, quantum-vulnerable flag | Yes (cited) | Yes (allow-list) | Yes |
| PQC algorithm identification, hybrids, TLS 1.3 PQC | **Yes, with per-group enumeration** | CBOM-Lens (by OID), cbomscope (negotiated) | Yes (v) |
| ML-KEM, ML-DSA, SLH-DSA | Yes (variants; parameter sets probed on Windows) | CBOM-Lens (also XMSS, HSS-LMS) | Yes (v) |
| PQC certificates | Detected by OID | CBOM-Lens | n/d |
| Harvest-now-decrypt-later | **Yes (flag)** | No | Yes (v) |
| Migration readiness and priority | **Endpoint readiness level; no plan** | CipherIQ (phased timeline) | Yes (v) |
| Weak and deprecated algorithms; certificate problems; misconfiguration | Yes (17 cited rules on TLS; cited legacy status on hosts) | Part | Yes |
| **Risk scoring and prioritisation** | Severity and a hygiene score; **no business context** | No | Yes (owner, exposure, blast radius) |
| Remediation | Text per rule | Part | Orchestration (v) |

### 3.6 Enterprise

| Capability | **Ours** | CBOMkit | Commercial |
|---|---|---|---|
| Multi-tenancy, RBAC, SSO | **No** (one shared token) | n/d | Yes |
| Ownership, tags, groups, business applications | Tags only | No | Yes |
| Audit trail | **No** | n/d | Yes |
| SIEM, ticketing, CI/CD, cloud integrations | **No** (CSV export only) | CI action | Yes (ServiceNow, SIEM, EDR) |
| Distributed collectors, agent management | **No** | n/d | Yes |
| Executive reporting | Dashboard only | Viewer | Yes |

---

## 4. What the product's category really is

**CBOM is a data format. It is not a product category.** It answers "what cryptography does this software or system contain, in an interoperable form". A buyer's questions are different: *where is our vulnerable cryptography, how bad is it, who owns it, what do we migrate first, and can we prove progress to an auditor.* CycloneDX itself frames CBOM as a **capability** of a broader BOM standard **[source]**, and every vendor above sells something wider than the file.

Options considered:

| Category name | Fit | Verdict |
|---|---|---|
| CBOM platform | Accurate for the export only; narrows the market to a niche of developers and standards people; invites a direct comparison with a free IBM toolkit | **Reject as the category** (keep as a capability) |
| Cryptographic inventory / discovery platform | Accurate for what exists; the term buyers and CISA use ("inventory") | **Use today** |
| **Cryptographic posture management** | The term SandboxAQ, Entrust and IBM have converged on; implies inventory + risk + policy + remediation; **promises more than exists** | **Aspire to it; do not claim it yet** |
| PQC readiness platform | Accurate, timely, but narrow and time-boxed (readiness is a project; posture is permanent, as NCCoE itself says discovery should be a long-term programme) | Use as a *feature*, not the category |
| Crypto-agility platform | The Gartner term; means *the ability to swap*, which needs orchestration this product does not and should not attempt | Do not claim |
| Cryptographic exposure management / intelligence | Buzz; no stronger than the above | Avoid |

**Recommendation:** position today as **"cryptographic inventory and PQC-readiness assessment"**, with **cryptographic posture management as the direction**. CBOM is an import and export format, named as such.

---

## 5. Challenging the name

**Current name: CipherHorizon** (with "by Offset Security" as the publisher line).

| Test | Assessment |
|---|---|
| Technically accurate? | Not descriptive, which is normal for a product name. It does not say "inventory", "posture" or "PQC". |
| Would a security executive understand it? | They would infer "something about ciphers, looking ahead". Fine for a brand, weak as an explanation, so the *category tagline* carries the meaning. |
| Sounds like a tool, a format or a platform? | A platform or a product. **Good: it does not sound like a format.** |
| Confuses with CycloneDX or CBOM? | No. The 2026 rename from `cbom-scan` already removed that. |
| Room for future capabilities? | Yes. |
| Enterprise-suitable? | Acceptable, unremarkable. |
| Communicates PQC or agility? | "Horizon" hints at the quantum horizon; nothing states it. |
| Marketable? | **Two risks.** (1) **The name space is crowded with `Cipher*`:** CipherTrust (Thales), CipherIQ, CipherRadar and CipherInsights all appear in this very research, plus CipherLab. (2) **"Horizon" is a heavily used word** in enterprise software (for example VMware's Horizon), which hurts searchability and invites confusion. A web search found no product called CipherHorizon, only a personal site using the domain **[source]**; **that is not a trademark search**, and one is needed before any public launch. |

**Alternatives** (none has been checked for trademark or domain availability):

| Group | Name | Communicates | Gets right | Gets wrong / confusion risk | Recommend |
|---|---|---|---|---|---|
| Technical | **CryptoInventory** | Exactly what it is | Clear in search | Generic, unownable, sounds like a feature | No |
| Technical | **Cryptograph** | Crypto + graph (the dependency and evidence graph) | Points at the real differentiator | Awkward; similar to existing words (cryptography, cryptograph the device) | Maybe |
| Technical | **AlgoLedger** | Algorithms + record | Suggests an auditable record | Sounds like a blockchain product | No |
| Enterprise | **Cryptographic Posture Manager** (descriptive) | The category | Matches how the market speaks | Not a brand; long | As a tagline, yes |
| Enterprise | **CryptoAtlas** | A map of where cryptography lives | Fits inventory and dependency mapping | "Atlas" is heavily used (a database service, a company); still `Crypto*` | Maybe |
| Enterprise | **TrustMap** | Map of trust | Friendly to executives | Says PKI and trust, not algorithms | No |
| Security-product | **Meridian** | A line of reference | Short, calm | No crypto signal; common word | No |
| Security-product | **Sentry-** / **-Guard** names | Protection | Familiar to buyers | Overused; AQtive Guard already occupies "Guard" | No |
| Crypto / PQC | **Postquantum Atlas** | The PQC map | Explicit | Long; "atlas" again | No |
| Crypto / PQC | **QuantumLedger** | PQC + record | Clear timing | Sounds like a quantum-computing or blockchain company | No |
| Crypto / PQC | **Lattice** | The maths behind ML-KEM | Memorable | Unrelated companies own it | No |
| Platform | **CipherAtlas** | Ciphers + map | Keeps the family look | Adds to the `Cipher*` crowd | Maybe |
| Platform | **Horizon** (alone) | Looking ahead | Short | Too generic; VMware | No |
| Platform | **CipherHorizon** (keep) | Cryptography, looking ahead | Already built into the UI, logo and docs; not a format name | `Cipher*` crowd; "Horizon"; not descriptive | **Yes, conditionally** |

**Recommended name: keep CipherHorizon, conditionally.** The name is not the problem; the *positioning language* is (§4). Renaming costs a logo, a module path and a domain for no strategic gain, and none of the alternatives above is obviously better. **The condition is a real trademark and domain search before any public launch.** If it fails, the fallback is **CipherAtlas** (nearest in feel, communicates the map/inventory idea), then **Cryptograph**. The tagline, not the name, should carry the category: *"Cryptographic inventory and PQC-readiness."*

---

## 6. The unique value proposition (the honest version)

**The question:** why would an enterprise use this instead of CBOMkit or cdxgen?

**Short answer: it should not, for source code.** CBOMkit and cdxgen are free, standards-aligned and better at source-level detection. *We should never compete there; we should ingest their output.* The real question is what we offer that they and the small open-source neighbours do not, and that the enterprise suites either lack or do not let you verify.

### 6.1 Differentiators, tested against reality

| Candidate differentiator (from the brief) | Exists today? | Real, defensible, or hollow? |
|---|---|---|
| **Evidence-based inventory** (every fact says how strong its evidence is; coverage and blind spots are data) | **Yes, on hosts** (claim ladder, method quality, coverage, `not-seen`); on TLS via evidence tiers and citations | **Genuine and rare.** CISA itself says tools' completeness is unconfirmed. Only CBOM-Lens ("omit rather than guess") and theia (confidence levels) go part way. But it lives in custom properties, so it is invisible outside our UI. |
| **Deepest active PQC TLS enumeration** | **Yes.** Own stack; per-group enumeration via HelloRetryRequest; certificates; reports *offered versus negotiated* | **Genuine.** cbomscope observes only the negotiated group; CBOM-Lens leans on nmap; classical scanners reportedly do not parse PQ groups (secondary source). Real, but it is one sensor, and a scanner is not an inventory. |
| **Native Windows crypto inventory** (CNG, KSP, CSP, PQC parameter sets) | **Yes** | **Genuine and probably unique in open source.** I found no public documentation of it elsewhere; that is *absence of evidence*. Valuable for Windows-heavy estates; not a company. |
| Network + endpoint + source + runtime discovery | **Partial** (TLS + hosts); no source, no runtime, no passive network | **Hollow as a claim today.** Others (AQtive Guard, AgileSec) have more sources. |
| **Correlation across sources** | **Manual link only** | **The claim that matters most, and it is not true yet.** Building it is the strategy (§7). |
| Certificate-to-application relationships | No | Missing. Certificates are not entities. |
| Crypto dependency graphs | Partial (Windows imports and providers) | Real but narrow. |
| PQC migration planning | No (readiness level per endpoint only) | Missing; CipherIQ has a report; vendors claim orchestration. |
| Historical tracking | Endpoints yes; hosts no | Half. |
| Business application mapping, ownership, risk-based prioritisation | No | Missing; **this is what enterprise buyers pay for.** |
| Continuous discovery | Partial (scheduled endpoint rescans; hosts by hand) | Half. |
| **Air-gapped, single-binary, no phone-home, auditable** | **Yes** | **Genuine.** The commercial suites are SaaS or heavy; regulated and government buyers value this. Modest as a differentiator alone. |

### 6.2 The value proposition that survives

> **A verifiable cryptographic inventory: you can see exactly what was found, how it was found, how sure we are, and what we could not see.**

That is the differentiator: **trust in the inventory itself**, which matters because CISA and the EU are asking agencies to *submit* inventories, and because tools' completeness is openly doubted. It is not "better UI", "more scalable" or "AI".

**The honest audience:** not the Fortune 100 CISO who buys AQtive Guard, but **(a) security architects and PKI/crypto teams at mid-size organisations, (b) assessors and consultancies running PQC-readiness engagements** who need auditable evidence they can hand to a client, and **(c) regulated or air-gapped environments** that cannot use a SaaS. All three value verifiability and low friction over breadth.

### 6.3 Where we lose, plainly

- **Breadth:** no source, container, cloud, runtime, database, key or certificate-store discovery.
- **Context:** no owner, environment, exposure, criticality or business application.
- **Integration:** nothing goes to ServiceNow, a SIEM or a ticket queue.
- **Scale and trust:** one token, one machine validated, Linux unproven, no users.
- **Distribution:** nothing is published. The competitors have communities (IBM), sales forces (Keyfactor, SandboxAQ) or procurement vehicles (Tychon).

---

## 7. The architecture, reviewed as a product manager

```text
Collectors → Discovery → Normalization → Correlation → Knowledge → Risk → PQC / Crypto-agility → CBOM → Reporting / APIs
```

| Stage | Exists today | Missing | Change | Build, delegate, or do not build |
|---|---|---|---|---|
| **Collectors** | TLS prober; `apt`, `pe-files`, `windows-cng` sensors; small separate collector | Certificate stores, config (Schannel, sshd, web servers), RPM/APK/macOS, upload automation, **import of other tools' CBOMs as a first-class source** | Add certificate and config sensors; make **ingest** a collector type | **Delegate** source, container and runtime discovery (CBOMkit, cdxgen, CBOM-Lens, theia); **build** OS-native, TLS and certificate sensors |
| **Discovery / scheduling** | Endpoint rescans | Scheduled host collection, agent/collector registry, enrolment | A tiny push path, not a fleet manager | Build minimal; integrate EDR/RMM for scale |
| **Normalization** | **Two models:** host evidence graph; TLS reports as JSON blobs | One entity model for both | **Unify** (§8): TLS observations become evidence; certificates become entities | Build |
| **Correlation** | Manual `asset_links` | **Automatic identity resolution** (address, hostname, certificate fingerprint, library hash) with a stated confidence | **This is the product's centre of gravity** | Build; it is the moat |
| **Knowledge** | Cited tables (algorithms, libraries, CNG identifiers, legacy status, PQC rules) | Broader library families, version rules, per-family product identifiers (CPE) | Keep the citation discipline; publish the tables as data | Build; consider contributing to the CycloneDX registry |
| **Risk** | Severity, hygiene score, readiness level | Owner, environment, exposure, criticality; a prioritisation that uses them | Add context fields and a simple, explainable prioritisation | Build small; do not build a vulnerability database |
| **PQC / agility** | Readiness (endpoints), verdicts (hosts) | Migration planner; dependency-aware "what blocks migrating X" | Derive from the correlation graph | Build the *plan*; **never** the executor (CLM vendors own issuance and rotation) |
| **CBOM** | Export 1.6 for TLS and hosts | 1.7, the registry, CBOM diff for hosts, faithful evidence mapping | Move to 1.7; keep custom properties minimal and documented | Integrate with the standard; do not extend it privately |
| **Reporting / API** | 30 routes, CSV, dashboard | OpenAPI, webhooks, a report for the CISA M-23-02 items, PDF/executive view | Publish the contract; add the M-23-02 export | Build small |

**What should be delegated to existing tools:** source-code CBOM (CBOMkit, cdxgen), container and filesystem artefact scanning (theia, CBOM-Lens), runtime instrumentation (nobody open source; vendors), passive network capture (Zeek, vendors). **Where to integrate with CycloneDX:** read any CBOM into evidence with its provenance; write 1.7 out. **Where proprietary differentiation should sit:** the evidence model, correlation, the knowledge tables, active PQC TLS enumeration, and the Windows-native sensor.

---

## 8. The role of CBOM: product or output?

| | **Model A: "CBOM product"** | **Model B: inventory and posture platform with CBOM export** |
|---|---|---|
| Market | Developers and standards people | Security architects, PKI, compliance, PQC programmes |
| Competition | A free IBM toolkit, `cdxgen`, several small tools | Enterprise suites (but with a verifiable, open, air-gappable angle) |
| Buyer questions it answers | "Give me a CBOM file" | "Where is my vulnerable cryptography, who owns it, what first?" |
| Defensibility | Low: the format is open and free tools exist | Higher: correlation, evidence and context are hard to copy |
| Mandate alignment | Weak | **Strong** (inventories, migration) |

**Recommendation: Model B.** CBOM is the **interchange format** at the edges: ingest others', export ours, and stay strictly standards-compliant. It is not the product. In the UI, the "CBOM" top-level page should become "Export and import" on each asset, and the README should stop leading with the format.

---

## 9. The data model

### 9.1 What the current model represents

| Concept | Today | Assessment |
|---|---|---|
| Cryptographic asset | Algorithm (catalogue of 52) **[repo]** | Good; family level on hosts |
| System | `assets.kind = host` | Thin: name only |
| Application, service | **Absent** | Missing |
| Certificate | Inside a TLS report's JSON | **Not an entity**: cannot be queried, tracked or correlated |
| Key | **Absent** (by design: metadata only, not yet collected) | Missing |
| Algorithm, library, protocol, cipher | Yes (catalogue; components; TLS report) | Good |
| **Evidence, observation** | **Host graph only** (method, quality, class, claim, coverage) | The best-designed part, but not used for TLS |
| Dependency, relationship | Provides and static imports; manual host-endpoint link | Weak and inconsistent |
| Owner, environment | **Absent** | Missing |
| Risk, finding, recommendation | Findings with a status workflow; hygiene score; text remediation | Good for TLS; thin for hosts |
| PQC status | Cited verdicts and readiness level | Good |

### 9.2 Internal canonical model versus CycloneDX

**Do not copy CycloneDX.** It is an *interchange* format designed to describe a system at a point in time; it has no place for "who owns this", "how sure are we", "when did we last see it", a *claim strength*, or a *finding lifecycle*. CycloneDX's own limits show it: tools invent `cipherhorizon:*`, `cbomscope:*` and other private properties to say what matters.

| | **Internal canonical model** (the product's truth) | **CycloneDX CBOM** (a projection) |
|---|---|---|
| Entities | Asset (system, service, endpoint), Component (library, provider, application), CryptoAsset (algorithm, protocol, certificate, key metadata), Owner, Environment | `components`, `cryptographic-asset`, `metadata.component` |
| Facts | **Observation**: subject, claim class (present, capable, bound, loaded, exercised), method, quality, source, time, privilege | `evidence.occurrences`; `evidence.identity` **only where a numeric confidence can honestly be given** |
| Relationships | Typed, directed edges each with a claim class | `dependencies` (`provides`, `dependsOn`) |
| Coverage and blind spots | First-class | `metadata.properties` (custom) |
| Findings, ownership, lifecycle, history | First-class | Out of scope, or `vulnerabilities` where it fits |
| Identity | Stable internal IDs; correlation keys (address, fingerprint, hash) | `bom-ref`, `purl`, CPE, hashes |

The evidence-graph design already built for hosts **is** the right canonical model. The work is to (a) move the TLS side onto it, (b) promote certificates to entities, and (c) add owner and environment. Then the CBOM becomes a lossless-where-possible projection, and any information CycloneDX cannot carry stays in the internal model rather than in private properties.

---

## 10. Missing capabilities

### Critical gaps (for credibility)

| # | Gap | Why it is critical |
|---|---|---|
| C1 | **Automatic correlation** across endpoint, host, certificate and library | Without it this is a set of scanners, not an inventory. Every enterprise competitor claims it. |
| C2 | **Certificates as first-class entities** (TLS chains now; host stores next) | The PKI persona's whole job; CISA notes certificates "explicitly include" the required data items |
| C3 | **Key length and "service provided" on hosts** | CISA's item 4 asks for algorithm, service and **key length**. Our host inventory cannot supply key length today (it knows families, not sizes). |
| C4 | **Ingest third-party CBOMs** as a supported source with provenance (CBOMkit, cdxgen, CBOM-Lens, theia) | The way to cover source and container discovery *without building it* |
| C5 | **Owner, environment, criticality and exposure** attributes and a prioritisation that uses them | The context enterprise buyers pay for; today "risk" ignores the business |
| C6 | **Live Linux validation** and RPM/APK | Half of enterprise hosts; today Linux has never run on a live machine |
| C7 | **CycloneDX 1.7** output, the registry, and CBOM diff for hosts | Standards credibility; the ecosystem is already moving |
| C8 | **A published API contract (OpenAPI)** and a **CISA M-23-02 export** (algorithm, service, key length, vendor class, OS) | Concrete, testable buyer artefacts |

### Important gaps (to be enterprise-grade)

Accounts, roles, SSO and an audit log; a TLS listener and Postgres; collector enrolment and scheduled/push collection; integrations (webhooks, ServiceNow/Jira, SIEM); STARTTLS and SSH scanning; configuration sensors (Schannel, sshd, web servers); a PQC **migration planner** derived from the dependency graph; executive and audit reports; macOS support; Windows Server and ARM64 validation; an Administrator-tier run.

### Nice to have

Key-store and HSM metadata enumeration beyond names; cloud KMS inventory (delegate or a narrow connector); Kubernetes discovery; more library families (the five unrecognised Windows libraries); a plugin marketplace.

### Things to REMOVE or simplify

| Item | Why |
|---|---|
| The **"CBOM" top-level page** | It duplicates each asset's export and reinforces the wrong category |
| **"Hosts" versus "Endpoints" as separate worlds** in navigation | Present one **Assets/Systems** view with kinds, once correlation exists |
| **The TLS hygiene 0 to 100 score as a headline** | It is our own invented scale, reads as SSL Labs-style, and competes for attention with the evidence and readiness story. Keep the cited findings; demote the number. |
| A second, parallel result model for TLS | The main structural debt (§9) |
| Motion polish and further visual work | Done enough; not a differentiator |

---

## 11. Recommended roadmap

Effort key: **S** under 2 weeks, **M** 2 to 6, **L** 6 to 12, **XL** over 12.

### Phase 1: a credible product (0 to 3 months)

| Feature | Problem | User | Value | Cx | Priority | Competitive advantage |
|---|---|---|---|---|---|---|
| Unify TLS onto the evidence graph; certificates as entities | Two models; certs unqueryable | Everyone | Foundation for every later item | L | P0 | Enables correlation |
| **Automatic correlation v1** (address, hostname, certificate fingerprint, library hash) with stated confidence | "Same machine" is manual | Security architect | The inventory becomes one inventory | M | P0 | The moat |
| **Ingest third-party CBOMs** as evidence with provenance | Source and container coverage we will not build | AppSec, DevSecOps | Breadth without rebuilding | M | P0 | Neutral layer over open source |
| Certificate sensor (Windows stores, Linux trust and service certs, no keys) | CISA item 4 data; PKI persona | PKI team | Key length and expiry on hosts | L | P0 | Metadata-only by design |
| Owner, environment, criticality, exposure fields; explainable prioritisation | Risk without context | CISO, remediation owners | Ranked worklist | M | P0 | Explainable, cited |
| **CISA M-23-02 export** and key-length/service fields | Federal and regulated buyers | Compliance | A concrete deliverable | S | P0 | Direct mandate fit |
| Live Linux validation; RPM/APK | Untested half of the estate | Infra | Credibility | M | P0 | Evidence, not claims |
| CycloneDX 1.7 output, OpenAPI | Standards credibility | Integrators | Interoperability | S | P1 | Standards-aligned |
| README, category and navigation repositioning; trademark search | Wrong category | Everyone | Clear story | S | P0 | n/a |

### Phase 2: enterprise-ready (3 to 6 months)

Accounts, roles, SSO and audit log; TLS listener and Postgres; scheduled and push collection with enrolment; webhooks and a ServiceNow or Jira connector; STARTTLS and SSH; configuration sensors (Schannel, sshd, web servers); executive report; host CBOM diff.

### Phase 3: differentiation (6 to 9 months)

**Dependency-aware migration planner** ("what blocks moving X to PQC: its library, its certificate, its peer"); evidence export that a client or auditor can independently verify; a published, contributable **knowledge repository** (citations included) and a CycloneDX-registry contribution; macOS; ARM64 and Windows Server validation.

### Phase 4: crypto-agility (9 to 12 months)

Policy-driven "should" statements (algorithm and protocol policy per environment) evaluated continuously; drift alerts; migration progress tracking against NIST IR 8547 and the EU timeline; **hand-offs to CLM/PKI platforms** (Keyfactor, Venafi, DigiCert) for the actual rotation rather than building an executor.

---

## 12. Personas

| Persona | Role in the purchase | Uses daily? | Consumes reports? | Owns remediation? |
|---|---|---|---|---|
| **CISO** | **Economic buyer** at an enterprise; sponsor in a mid-size one | No | **Yes** (posture, progress, exposure) | No |
| **Security architect / crypto-agility lead** | **Champion and the realistic first buyer** for this product | **Yes** | Yes | Partly |
| **PKI team** | Strong influencer; certificate half of the problem | **Yes** | Yes | **Yes** (certificates) |
| Cryptography team | Technical validator (they will test the evidence) | Yes | Yes | Advises |
| Application security | Consumes source-level CBOMs | Yes | Yes | **Yes** (code) |
| Cloud security / infrastructure | Owns hosts, cloud KMS, load balancers | Occasionally | Yes | **Yes** (hosts) |
| DevSecOps | Integrates into CI/CD | Yes | No | Yes |
| Compliance / GRC | Needs the M-23-02, EU or PCI evidence | No | **Yes** | No |
| Vulnerability management | Wants findings in their queue | Occasionally | Yes | Routes |
| Enterprise architect | Migration sequencing | Occasionally | Yes | Advises |

**Who is the buyer, really?** For enterprise suites, the CISO with a compliance mandate. **For this product, at this stage, the buyer and the user are the same person: a security architect, PKI lead or assessor who needs a trustworthy inventory now and has no budget for a suite.** That is a smaller, faster and more honest market than "enterprise", and the right one to earn credibility in first.

---

## 13. Final PM verdict

### Product verdict

**Reposition (and narrow).** Not a pivot: the core engineering is sound and differentiated. Not "stop": the mandates create real demand and there is a defensible niche. Not "build as is": the current framing and scope lose to free tools on one side and funded suites on the other.

### Current positioning

A self-hosted "cryptographic posture" tool that generates CBOMs, scans TLS endpoints and inventories hosts; in the UI and docs, effectively a **CBOM tool with a TLS scanner attached**.

### Recommended positioning

**A verifiable cryptographic inventory and PQC-readiness platform**: discover from the sources you have (its own sensors plus other tools' CBOMs), correlate them into one inventory of assets, certificates and dependencies, and show **exactly how sure each statement is and what was not seen**. CBOM is how it imports and exports; cryptographic posture management is the direction.

### Recommended product name

**Keep CipherHorizon, conditional on a trademark and domain search.** Carry the category in the tagline.

> **Update 2026-09-26.** The fallbacks named in the first version of this review (CipherAtlas, Cryptograph) were checked in [RESEARCH-003 §1](../product/RESEARCH-003-ecosystem-standards-and-design-inputs.md) and screened out: an in-category project already uses "CipherAtlas", and "Cryptograph" is crowded and generic. See [ADR-0014](../decisions/ADR-0014-product-name.md). The owner decisions this review asked for were answered (accept reposition-and-narrow; check the name; follow the review's order) and turned into [PRD-003](../product/PRD-003-cryptographic-estate-model.md).

### Primary competitor

- **Open source (mindshare):** **IBM CBOMkit** (and `cdxgen`), with **CBOM-Lens**, **CipherIQ's generator** and **cbomscope** as the nearest architectural neighbours.
- **Commercial (deals):** **SandboxAQ AQtive Guard** and **Keyfactor AgileSec** for enterprise; **Tychon** for federal endpoints.

### Biggest competitive advantage

An **evidence-graded inventory that states its own limits**, combined with the **deepest open-source active PQC TLS enumeration** and a **native Windows inventory**, delivered as small, auditable, air-gap-friendly binaries.

### Biggest weakness

**Breadth and context**, and specifically **no correlation**: it is a set of scanners with a manual link, with no source, certificate-store, key, cloud or runtime discovery, and no owner, environment or criticality.

### Biggest market opportunity

The **mandated inventories** (US M-23-02 and CISA ACDI; the EU's "initiate inventories by end of 2026"; NIST IR 8547's 2030 and 2035 dates) for organisations and assessors that need an **auditable** inventory but cannot buy an enterprise suite. And the **neutral correlation layer** that consumes open-source CBOMs instead of competing with them.

### Biggest product risk

**Being squeezed:** free tools cover source and artefacts, and funded suites cover breadth, integration and sales, while a small team with no users spreads across more sensors. A close second: **claiming "CBOM platform" or "posture management" before the correlation and context exist.**

### Must-have capabilities

Automatic correlation; certificates as entities; third-party CBOM ingest; certificate sensor with key length; owner, environment, criticality and exposure with an explainable prioritisation; CISA M-23-02 export; live Linux validation; CycloneDX 1.7 and OpenAPI.

### Do not build

Source-code scanning; container-image scanning; runtime instrumentation or eBPF; a vulnerability database; a certificate authority or lifecycle executor (rotation and issuance belong to CLM vendors); "AI-powered" anything; a fleet-management agent; a competing CBOM viewer; further UI polish before the model is unified.

### 12-month roadmap

**Q1:** unify the model, certificates as entities, correlation v1, third-party CBOM ingest, Linux validation, repositioning and a trademark search. **Q2:** certificate sensor, context fields and prioritisation, M-23-02 export, 1.7 and OpenAPI, accounts and audit. **Q3:** configuration sensors, integrations, scheduled and push collection, executive report, host CBOM diff. **Q4:** dependency-aware migration planner, policy and drift, CLM hand-offs, knowledge repository and registry contribution.

### One-sentence product definition

> **A cryptographic inventory and PQC-readiness platform that correlates what your own sensors and other tools' CBOMs find into one inventory of systems, certificates and dependencies, and shows for every statement how strong the evidence is and what was not seen.**

---

## 14. Caveats on this research

- **Vendor claims are marketing.** No commercial product was tested. Pricing is not public for any vendor found.
- **Two of the comparison articles were written by competing vendors** (Encryption Consulting, QCecuring); I used them only to identify names. **Entrust's blog returned an access error** and was not read; its category framing is taken from a search snippet.
- **Secondary sources:** the EU and NIST IR 8547 timelines, the Gartner statements (quoted through vendor pages) and the claim that testssl.sh and SSLyze lack PQC group parsing (an arXiv survey) were not checked against primary documents. testssl.sh may have added support since.
- **"CipherHorizon" trademark and domain availability were not established.**
- **Absence of evidence:** where I say no other tool documents native Windows CNG inventory, I mean I found no documentation, not that none exists.
- **Self-review bias:** the repository facts are verified, but the assessment of *our own* differentiators is mine and should be challenged by someone who has not built it.

## Sources

**Standards and government**
- [CycloneDX v1.7 release](https://cyclonedx.org/news/cyclonedx-v1.7-released/), [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/), [CycloneDX Cryptography Registry](https://cyclonedx.org/registry/cryptography/), [ECMA-424](https://ecma-international.org/publications-and-standards/standards/ecma-424/), [IBM Research: "The Anatomy of Cryptography Bills of Materials"](https://research.ibm.com/publications/the-anatomy-of-cryptography-bills-of-materials-standardization-and-practice-in-cyclonedx)
- [CISA: Strategy for Migrating to Automated Post-Quantum Cryptography Discovery and Inventory Tools](https://www.cisa.gov/resources-tools/resources/strategy-migrating-automated-post-quantum-cryptography-discovery-and-inventory-tools) (PDF read in full)
- [NIST NCCoE SP 1800-38](https://csrc.nist.gov/pubs/sp/1800/38/iprd); [NIST IR 8547 (via summary)](https://postquantum.com/security-pqc/nist-ir-8547-ipd/); [EU roadmap and NIST timelines (via summary)](https://thequantuminsider.com/2026/05/08/post-quantum-migration-timelines-government-industry-impact/)

**Open source**
- [CBOMkit](https://github.com/cbomkit/cbomkit), [releases](https://github.com/cbomkit/cbomkit/releases), [sonar-cryptography](https://github.com/cbomkit/sonar-cryptography), [CBOMkit-theia](https://github.com/cbomkit/cbomkit-theia)
- [cdxgen (crypto documentation)](https://github.com/cdxgen/cdxgen/blob/master/docs/ADVANCED.md)
- [CBOM-Lens](https://github.com/OmniTrustILM/cbom-lens), [CipherIQ cbom-generator](https://github.com/CipherIQ/cbom-generator), [cbomscope](https://github.com/polycratia/cbomscope), [more tools](https://github.com/topics/cryptographic-inventory)
- [Survey of PQC support in libraries and scanners (arXiv, secondary)](https://arxiv.org/pdf/2508.16078)

**Commercial**
- [SandboxAQ AQtive Guard](https://www.aqtiveguard.com/), [Keyfactor cryptographic discovery](https://www.keyfactor.com/products/cryptographic-discovery-inventory/), [IBM Guardium Cryptography Manager](https://www.ibm.com/products/guardium-cryptography-manager), [IBM Quantum Safe](https://www.ibm.com/quantum/quantum-safe)
- [Tychon and HCLSoftware](https://www.executivebiz.com/articles/tychon-hclsoftware-quantum-readiness-partnership), [Tychon on Carahsoft](https://www.carahsoft.com/tychon)
- Landscape surveys: [postquantum.com vendor landscape](https://postquantum.com/post-quantum/cryptographic-inventory-vendors/), [Encryption Consulting (vendor-authored)](https://www.encryptionconsulting.com/cryptographic-inventory-vendors/)
- [Gartner crypto-agility statements as quoted by Keyfactor](https://www.keyfactor.com/gartner-post-quantum-report-july-2024/), [QuSecure](https://www.qusecure.com/qusecure-gartner-hype-cycle-crypto-agility/)
