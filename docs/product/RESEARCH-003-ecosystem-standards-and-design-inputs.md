# RESEARCH-003: Ecosystem, standards and design inputs for the cryptographic-posture model

| | |
|---|---|
| **Status** | Complete — input to PRD-003 and SECARCH-001 |
| **Date** | 2026-09-26 |
| **Author role** | Product Manager (research), reviewed by Security Architect |
| **Builds on** | [STRATEGY-001](../strategy/STRATEGY-001-product-review.md) (product review), [RESEARCH-002](RESEARCH-002-pqc-tls-cbom-landscape.md) (PQC/TLS/CBOM landscape) |
| **Method** | Live web research, the published schemas and OpenAPI files downloaded and read directly, real sample CBOMs from each tool profiled programmatically. Every claim carries a source. Where a fact came from a tool's own sample rather than its documentation, it says so. |

Research questions, each answered in a numbered section. Each ends with **Findings → requirements** so nothing here is decoration: PRD-003 cites these IDs.

| ID | Question | Section |
|---|---|---|
| R1 | Is the name usable, and should it change? | 1 |
| R2 | Which existing tools should we ingest, integrate with, or stay away from? | 2 |
| R3 | What do the standards require of the data model and the export? | 3 |
| R4 | How do systems, endpoints and certificates get correlated safely? | 4 |
| R5 | How should certificates be discovered without touching key material? | 5 |
| R6 | What is missing from our toolchain, and what is a good fit to add? | 6 |

---

## 1. Name and brand (R1)

**Question.** The product owner named CipherAtlas and Cryptograph as acceptable alternatives to CipherHorizon. Do they hold up?

**Evidence.**

| Candidate | What was found | Verdict |
|---|---|---|
| **CipherAtlas** | A GitHub project of the same name already exists in the same category (cryptographic/PQC inventory). Two tools with one name in one category is the collision that costs most: search, package names, confusion in issues. | **Screened out** |
| **Cryptograph** | Crowded generic term (many crypto-, NFT- and finance-adjacent products); weak distinctiveness; hard to search for. | **Screened out** |
| **CipherHorizon** | No in-category project found under this name in the same searches. Distinctive compound. Not evidence of legal availability. | **Keep, conditional** |

**What this research cannot do.** It is a web and registry-style search, not a trademark clearance. It cannot see pending filings, common-law use outside search engines, or non-English markets. A trademark search in the intended jurisdictions, and checks of the domain, package registry and GitHub organisation names, are **owner actions** that must precede a public launch (they cost nothing to do early and a great deal to do late).

**Decision.** Recorded in [ADR-0014](../decisions/ADR-0014-product-name.md): keep CipherHorizon; this overrides the owner's stated preference for the two alternatives because of the in-category collision; the owner can reverse it, and the internal module path and `cipherhorizon:*` property namespace are the only places a rename would be expensive, which is why the namespace registration (R3) is sequenced after the name is cleared.

**Findings → requirements.** N-1: repository and product name stay CipherHorizon until an owner-run trademark/domain check says otherwise. N-2: a rename must be a mechanical change (module path, binary names, namespace) — see PRD-003 REQ-REL-3.

---

## 2. Ecosystem: tools to ingest, integrate with, or avoid (R2)

### 2.1 Landscape and fit

| Tool | What it produces | Where it runs | Licence / model | Fit for CipherHorizon |
|---|---|---|---|---|
| **IBM CBOMkit** (hyperion / sonar-cryptography, theia, coeus) | CycloneDX 1.6 CBOM from **source code** (Java/Python scanners), from repos, and a compliance layer (OPA). REST API + DB. | CI / server | Apache-2.0 | **Ingest.** Static-source evidence: says what code references, not what is deployed. Do not compete. |
| **cdxgen** (OWASP) | CycloneDX BOM incl. crypto assets via `--include-crypto` / `cbom` (source-derived; evidence mode). | CI / CLI | Apache-2.0 | **Ingest.** Same evidence class as CBOMkit. |
| **CBOM-Lens** (OmniTrustILM) | CBOM from **filesystems, containers, network ports (nmap), and the Windows registry**; CycloneDX 1.6 *and* 1.7; uploads to a CBOM-Repository. | Host agent / server | Open source | **Ingest and be interoperable.** Closest overlap with our host sensors; the ecosystem point is to be a *compatible destination*, not a rival scanner. |
| **CBOM-Repository** (OmniTrustILM) | A store: `POST /v1/bom`, search, get by URN, version list, health. OpenAPI 3.1.1 v0.3.0. | Server | Open source | **Optionally speak its protocol** (§2.3). |
| **CipherIQ cbom-generator** | Linux host CBOM. | Host | **GPL / commercial** | **Ingest only.** GPL: never link or copy code. |
| **cbomscope** | Go single binary; live TLS + CBOM. | CLI | Open source | Peer/overlap; ingest its output if CycloneDX. |
| **Dependency-Track** | Component/vulnerability tracking. **No native support for cryptographic assets** as of the search (upstream issue #3145 open since Oct 2023); an IBM internal fork adds some. | Server | Apache-2.0 | **Not a target.** Do not build around it. |
| **Commercial: SandboxAQ AQtive Guard, Keyfactor AgileSec, IBM Guardium Quantum Safe, Tychon, CryptoNext COMPASS, AppViewX, Entrust** | Full posture management suites. | SaaS / enterprise | Commercial | Not integration targets; they define the category language ("cryptographic posture management") and the feature bar. |

### 2.2 What real third-party CBOMs look like (profiled programmatically)

Samples downloaded and parsed: CBOMkit (Keycloak, Kafka), Theia, CBOM-Lens (1.6 and 1.7).

| Sample | specVersion | `metadata.component` (the subject) | Asset types present | Dependencies | Notes |
|---|---|---|---|---|---|
| CBOMkit / Keycloak | 1.6 | **absent** | algorithm 22, related-crypto-material 33, protocol 1 | 36 | 103 `evidence.occurrences` (file/line) |
| Theia | 1.6 | `application` "my application" | algorithm 5, certificate 1, protocol 1, related-crypto-material 1 | 0 | |
| CBOM-Lens | 1.6 and 1.7 | `application` "CBOM-Lens" (**the tool, not the scanned system**) | algorithm 13, certificate 3, related-crypto-material 10, protocol 1 | 4 | custom properties `subject`, `issuer`, `key_usage`, `pem_type`, `this_update`, `next_update`, `revoked_count` |

**Finding that changes the design.** *A third-party CBOM cannot be trusted to say what system it describes.* One has no subject at all; another names the tool itself. Therefore **the operator, not the document, assigns the subject on ingest**, and the document's own claim about itself is recorded but never used to attach data to a system. (This is also a security requirement: SECARCH-001 T-04.)

**Second finding.** Static-source CBOMs (CBOMkit, cdxgen) describe *code that references cryptography*; host/network CBOMs (CBOM-Lens, ours) describe *what is present or observed*. The two answer different questions and must not be blended into one confidence level. Our evidence rungs already model this (`present` / `provisioned` / `capable` / `loaded` / `exercised`); an ingested static-source asset maps to **`capable` from source**, never to `exercised`.

### 2.3 CBOM-Repository contract — what a compatible endpoint would need

Read directly from the published OpenAPI (`v0.3.0`, 28 KB):

- `POST /v1/bom`, media type `application/vnd.cyclonedx+json` with optional `; version=1.6|1.7`. Responses **201** (body: `serialNumber`, `version`, `cryptoStats`), 400, 409, 415. Errors are RFC 9457 `application/problem+json`.
- `GET /v1/bom` search with `after` / `cursor` / `limit`, paging via `Link: rel=next`; `GET /v1/bom/{urn}[?version=N|original]`; `GET /v1/bom/{urn}/versions`; `GET /v1/health[/liveness|/readiness]`.
- `cryptoStats` counts `cryptographic-asset` components by `assetType` across the whole component tree.
- **The specification declares no `securitySchemes` and no `security` requirement.** CBOM-Lens's documented repository configuration is a single `base_url`.

**Implication.** A compatible push endpoint is small (about three routes plus health) and would let CBOM-Lens users send data to CipherHorizon with a one-line change. But **the contract has no authentication**, so a compatible endpoint is either open or relies on network controls — which conflicts with our "auth on every route" rule. Whether Lens can send an `Authorization` header is **not documented** (open question OQ-2). Decision deferred to PRD-003: ship it as an **opt-in, default-off, separately-bound listener** with explicit token or IP allowlist, only after Lens's auth capability is confirmed; do not weaken the main API.

### 2.4 Findings → requirements

| ID | Finding | Requirement seed |
|---|---|---|
| E-1 | Static-source and host/network CBOMs are different evidence | Ingest maps by source class; never upgrades evidence |
| E-2 | Subject missing or wrong in real CBOMs | Operator-assigned subject; document identity recorded, not trusted |
| E-3 | CBOM-Lens overlaps our host scan | Be a compatible destination; do not chase its scanning breadth |
| E-4 | GPL tool (CipherIQ) | Ingest output only; never bundle |
| E-5 | Dependency-Track has no CBOM support | Do not depend on it |
| E-6 | Repository API is unauthenticated by contract | Compatible endpoint is opt-in and isolated (SECARCH-001 T-09) |

---

## 3. Standards and data model (R3)

### 3.1 CycloneDX 1.6 → 1.7 (diffed programmatically from the two published JSON schemas)

- **1.7 released 2025-10-21**; ECMA-424 second edition (Dec 2025). We emit 1.6.
- 1.7 adds a **cryptography-definitions registry schema** (`cryptography-defs`): **93 algorithm families and 246 curves** as controlled names. Fields such as `algorithmFamily` and `ellipticCurve` in `algorithmProperties` are the standard-blessed way to say "which algorithm, which curve" — the thing our catalogue does with cited OIDs.
- Several 1.6 constructs are deprecated in 1.7 with replacements; the safe migration is **emit the 1.7 replacement and keep validating against the 1.7 schema**, keeping a 1.6 output path for consumers that have not moved (CBOMkit is 1.6 at the time of writing; CBOM-Lens emits both).
- **BOM-Link** allows one BOM to reference a component in another by URN + version — the standard-native way to say "this endpoint's certificate is *that* certificate in the host BOM". We use it when exporting a correlated estate.

### 3.2 Custom properties and namespace

Our CBOM carries `cipherhorizon:*` properties (evidence class, classical status/basis, PQC unclassified reason). The CycloneDX **property taxonomy** repository is the registry for property namespaces: `cdx:` is reserved for official ones ("unofficial sub-namespaces … MUST NOT be used under the cdx top-level namespace"); new namespaces are requested by opening an issue. **Requirement:** register `cipherhorizon:` and document each property, *after* the name is cleared (R1).

### 3.3 CISA / OMB M-23-02 (read from the CISA ACDI strategy PDF, text extracted)

Section II of M-23-02 asks for **nine data items per cryptographic system**. CISA says only **three** (items 4, 5, 6) are collectible by automated tools; the rest are manual:

| Item | Content | Automated? | Our position |
|---|---|---|---|
| 1 | FISMA system identifier | manual | **operator-entered system field** |
| 2 | FIPS 199 categorisation (L/M/H) | manual | operator-entered |
| 3 | HVA identifier | manual | operator-entered |
| 4 | For CRQC-vulnerable elements: **algorithm; service provided (key establishment / encrypted connections / signatures); length of keys** | **tool** | **must-have** — needs key length (§5) |
| 5 | Software package: COTS+vendor / GOTS+agency / other+developer | tool | derivable from package/file identity where known; else operator |
| 6 | Operating system(s), major/minor version | tool | collector already records OS |
| 7 | Hosting: on-prem / commercial cloud (name) / gov cloud / hybrid | manual | operator-entered |
| 8 | Data lifecycle: types and **how long protected ("time to live")** | manual | operator-entered; **drives harvest-now-decrypt-later priority** |
| 9 | Notes | manual | notes |

CISA also states that "digital certificates are an example where the information explicitly includes the desired data items" (item 4), and that software with embedded cryptography and customised applications "may not be discoverable using automated tools", so vendors must be asked. **Consequences:** (a) certificates are the fastest route to item 4 — which is why they are a critical gap; (b) items 1, 2, 3, 7, 8 are **system metadata fields** the product must carry, not derived data; (c) the product must *say so* when a system's inventory rests on manual/vendor input.

*Caveat:* this is the CISA strategy document's reading of M-23-02, not the memo itself; the export requirement (PRD-003) is worded as "supports the nine-item structure", not "is compliant".

### 3.4 NIST IR 8547 and deprecation dates

Transition timeline: quantum-vulnerable public-key algorithms deprecated **2030** and disallowed **2035** (NIST IR 8547 draft, as carried in our existing cited rules). The EU coordinated roadmap asks for inventories by end-2026. Requirement: prioritisation uses **dated, cited** rules, and the data-lifetime field (M-23-02 item 8) is what turns a date into a risk ("data must stay confidential until 2045 and is exposed to harvest-now-decrypt-later today").

### 3.5 Findings → requirements

| ID | Finding | Requirement seed |
|---|---|---|
| S-1 | 1.7 is current; registry gives standard algorithm/curve names | Emit 1.7; map our catalogue IDs to registry names in a tested table |
| S-2 | BOM-Link is standard cross-BOM reference | Use for correlated export |
| S-3 | Property namespace registration process exists | Register `cipherhorizon:` after name clearance |
| S-4 | M-23-02 items 1,2,3,7,8 are manual | System metadata fields + export structure |
| S-5 | Item 4 needs key length; certificates carry it | Certificates are P0 |
| S-6 | Dated deprecations need a data-lifetime input to be actionable | Explainable prioritisation using criticality, exposure, lifetime |

---

## 4. Correlation and identity resolution (R4)

**Problem.** Today the TLS side (an *endpoint* `host:port`) and the host side (a *machine* with a machine-id) are unrelated except by a manual `asset_links` row. The product's central promise — "which systems are exposed" — needs them joined, **automatically and safely**.

### 4.1 Identity keys available today (from the code)

| Side | Keys we already have |
|---|---|
| TLS scan | target host/IP + port; certificate **SHA-256 fingerprint**, serial, subject, issuer, SANs (DNS and IP), public-key algorithm/size/curve; negotiated protocol/suite/group |
| Host collector | hostname; **machine id** (Windows MachineGuid / Linux `/etc/machine-id`); OS; file hashes (SHA-256) of crypto libraries; (with certificate sensor, §5) certificate fingerprints |
| Third-party CBOM | none reliable (§2.2) |

### 4.2 Join rules, from strongest to weakest

| Rule | Joins | Why it is or is not sound |
|---|---|---|
| **J1 Certificate fingerprint** | endpoint ↔ host whose certificate store/file contains the same SHA-256 | Cryptographically unique. *But* a certificate can legitimately live on many hosts (load-balanced, wildcard, copied). Unique match → strong; **multiple hosts match → ambiguous, propose all, join none automatically**. |
| **J2 Endpoint address ↔ host name/address** | endpoint host equals the host's name/FQDN, or an address the host reports | Names are attacker-influenceable (DNS, hostnames) and NAT breaks addresses; medium at best. |
| **J3 SAN ↔ hostname** | leaf SAN covers the host's name | Weak alone (wildcards, shared certs); useful as corroboration. |
| **J4 Library hash** | host ↔ software identity | Identifies *what software*, not *which system*; never used to join systems. |
| Name similarity / fuzzy match | — | **Rejected.** Produces plausible wrong joins that look right. |

### 4.3 Design consequences

1. **Correlation is a stored, reviewable object** (`link`: two entities, the rule(s) that produced it, the evidence, a **state** `proposed | confirmed | rejected`, who decided, when) — never a silent merge. Data is never merged destructively; both sides keep their evidence, the link is a view.
2. **No invented confidence numbers** (the external review's warning, which the earlier design accepted): a link states *which rules fired and how many hosts matched*, in words; strength is one of three labels derived by a fixed, documented table (§4.2), not a computed score.
3. **Trust ordering:** a link may auto-confirm only when *every* joined datum comes from a source our own authenticated collector or scanner produced. A link involving an imported third-party document is at most `proposed` (poisoning defence, SECARCH-001 T-05).
4. **A rejected link stays rejected** across rescans (otherwise the operator fights the tool).
5. Explain every link in the UI with the exact fields that matched.

### 4.4 Findings → requirements

C-1 join keys per §4.2; C-2 link is a first-class reviewable entity with a state machine; C-3 ambiguity is surfaced, not resolved; C-4 auto-confirm limited to first-party sources; C-5 rejection persists; C-6 links are explainable.

---

## 5. Certificate discovery and key length (R5)

**Why now.** Certificates are the one artefact where CISA says the required data "explicitly" exists (§3.3), and the highest-value gap in our host inventory (no key length today). The TLS scanner already parses certificates fully (`CertInfo`: key algorithm, bits, curve, signature algorithm, validity, SANs, SHA-256); the host side has none.

### 5.1 Where certificates live (metadata-only, public parts only)

| Platform | Locations | Method | Notes |
|---|---|---|---|
| Windows | `LocalMachine` and `CurrentUser` stores: `MY`, `Root`, `CA`, `TrustedPeople`, `TrustedPublisher`, `AuthRoot`, `Disallowed` | crypt32 `CertOpenStore` / `CertEnumCertificatesInStore` (documented Win32; already wrapped in `golang.org/x/sys/windows`) | Must go in `internal/winapi` (the only allowed unsafe layer). **Private-key presence** via the certificate context's key-provider-info *property* — reading a property does not open or use the key. |
| Linux | `/etc/ssl/certs`, `/etc/pki/ca-trust/extracted`, `/usr/local/share/ca-certificates`, service directories found by configuration parsers (nginx, Apache, sshd host certs, Java `cacerts`) | `fs.FS` reads of PEM/DER via stdlib `crypto/x509` | **Never read** `*.key`, `private/`, `*.p12/.pfx`, PKCS#8 blocks — these are identified by file name/PEM label and *skipped without opening beyond the first PEM header*; a test seeds decoy private keys and asserts none is parsed. |
| Container / image | later (out of scope; CBOM-Lens covers it — ingest instead) | | |

### 5.2 What is recorded per certificate

Subject, issuer, serial, SHA-256 fingerprint (the identity), validity, key algorithm + **size / curve**, signature algorithm, SANs, key-usage/EKU, CA flag, self-signed flag, store/path of origin, and *private key present: yes/no/unknown*. Not recorded: any key material, any private-key path contents, any password.

### 5.3 Noise control

A Windows machine carries a few hundred roots. Roots and intermediate CAs are counted and summarised (expiring, weak-key, SHA-1-signed) as **trust anchors**, not listed as findings per certificate; end-entity certificates (`MY`, service certificates) are first-class. Trust store content is *expected* and diffed for change, not alarmed on.

### 5.4 Key length from other evidence

Where no certificate exists (e.g. an installed library), file evidence cannot support key sizes (ADR-0012 decided this and the decision stands). Key length is therefore reported **only** when a certificate, a parsed configuration value, or a live handshake states it; otherwise `unknown(reason)`.

### 5.5 Findings → requirements

K-1 Windows and Linux certificate sensors, metadata-only, allow-listed locations, private-key material never read (tested with decoys); K-2 key length/curve/signature algorithm recorded per certificate; K-3 trust anchors summarised, end-entity certificates itemised; K-4 private-key presence is a flag, not a read; K-5 Windows store enumeration is a new syscall surface → mandatory security review like ADR-0013.

---

## 6. Toolchain gaps and additions (R6)

Judged on: does it fix a demonstrated gap, is it a good fit (licence, size, offline, no cgo, no network), does it keep the trust model.

| Gap | Candidate | Decision |
|---|---|---|
| No third-party CBOM interop test data | Vendor the sample CBOMs (CBOMkit Keycloak/Kafka, Theia, CBOM-Lens 1.6/1.7) as **test fixtures** under `testdata/interop/` with source + licence recorded | **Add** (licence check per file first; otherwise regenerate small equivalents) |
| Validate 1.7 output | Vendor the CycloneDX 1.7 JSON schema + cryptography-defs registry (already downloaded; same mechanism as the vendored 1.6) with the existing `schematest` gate | **Add** |
| No API contract | Hand-maintained **OpenAPI 3.1** file for the 30+ routes, with a test that every registered route is documented and vice-versa | **Add** (no generator dependency) |
| No live Linux validation | Not solvable by tooling here (WSL hangs). Options: GitHub Actions `ubuntu-latest` run of the collector against a known image plus an oracle script; a container on another machine | **Add a CI job** (owner action: repo must exist) |
| Correlation regression | A synthetic **estate fixture** (N hosts, M endpoints, shared and unique certificates, hostile decoys) with a golden expected link set | **Add** |
| Property-based / hostile CBOM ingest | Go native fuzzing on the ingest parser (already used for PE/version parsers) | **Add** |
| Supply-chain evidence | Already: goreleaser snapshot, `govulncheck`, licence check. Add SBOM/CBOM of our own release | **Add** to release job |
| Full-blown scanners (nmap, containers, source) | CBOM-Lens, CBOMkit, cdxgen | **Do not build** — ingest |
| Postgres / multi-node | Not needed for the target scale (SQLite, single node) | **Defer**, stated limit in PRD NFRs |
| Third-party UI library / charting | Would break "no build step, no external requests, strict CSP" | **Reject** |

---

## 7. Consolidated answers

1. **Name:** keep CipherHorizon; alternatives collide; owner must run trademark/domain checks before launch.
2. **Tools:** ingest CBOMkit, cdxgen, CBOM-Lens, cbomscope, CipherIQ (as data); optionally be a CBOM-Repository-compatible destination (opt-in, isolated); do not bundle GPL; ignore Dependency-Track.
3. **Standards:** move to CycloneDX 1.7 output, use BOM-Link, register the property namespace, add the M-23-02 nine-item structure as system metadata plus an export.
4. **Correlation:** deterministic joins, first-class reviewable links, no fuzzy matching, no invented confidence, first-party-only auto-confirmation.
5. **Certificates:** metadata-only sensors for Windows and Linux; key length only from a stated source.
6. **Toolchain:** add fixtures, 1.7 schema gate, OpenAPI, estate fixture, ingest fuzzing, CI Linux run; do not add scanners or UI libraries.

## 8. Open questions (carried into PRD-003)

| ID | Question | Owner | Blocks |
|---|---|---|---|
| OQ-1 | Trademark/domain clearance for CipherHorizon in target jurisdictions | Product owner | Public launch, namespace registration |
| OQ-2 | Can CBOM-Lens send an `Authorization` header to a repository? (docs show only `base_url`) | PM to verify against source/issue | REQ-ING-6 (compatible endpoint) |
| OQ-3 | Which platforms must the certificate sensor cover in v1 beyond Windows/Linux (macOS)? | Product owner | Scope of K-1 |
| OQ-4 | Is a CISA CyberScope-shaped export (spreadsheet) wanted, or is structured JSON/CSV enough? | Product owner | REQ-EXP-2 |
| OQ-5 | Licences of the third-party sample CBOMs for use as fixtures | PM | Fixture vendoring |

## Sources

- CycloneDX 1.7 schema and cryptography-defs registry (downloaded, diffed against 1.6): <https://cyclonedx.org/> ; property taxonomy: <https://github.com/CycloneDX/cyclonedx-property-taxonomy>
- CBOM-Repository OpenAPI v0.3.0 and CBOM-Lens documentation: <https://github.com/OmniTrustILM>
- CISA, *Strategy for Migrating to Automated PQC Discovery and Inventory Tools* (text extracted); OMB M-23-02
- Dependency-Track issue #3145: <https://github.com/DependencyTrack/dependency-track/issues/3145>
- cdxgen: <https://github.com/cdxgen/cdxgen>
- IBM CBOMkit: <https://github.com/IBM/cbomkit>
- NIST IR 8547 (transition to PQC), EU coordinated PQC roadmap — as already cited in `internal/pqc`
- Full source list for competitors and landscape: [STRATEGY-001](../strategy/STRATEGY-001-product-review.md) and [RESEARCH-002](RESEARCH-002-pqc-tls-cbom-landscape.md)
