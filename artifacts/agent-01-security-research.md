# Agent 1 — Security / Cryptography Research

```
AGENT      1 — Security / Cryptography Researcher
DATE       2026-09-24
OBJECTIVE  Determine what an enterprise must know about the cryptography on a HOST to do meaningful
           CBOM, PQC-readiness and crypto-agility assessment — starting from the security problem,
           not from operating systems.
INPUT      The program brief; the current `cipherhorizon run` implementation (read, not assumed);
           the public literature listed under EVIDENCE.
```

## 0. How to read this document

Every statement carries one of three marks. Agent 2 is expected to attack the second and third kinds.

| Mark | Meaning |
|---|---|
| **[P]** | Proved: read in a primary source or in this repository's code during this stage |
| **[S]** | Secondary: reported by a search summary or a vendor/community page; not verified against a primary source |
| **[H]** | Hypothesis: my reasoning, not established by anything cited |

Things that failed while researching are in §11 rather than smoothed over.

---

## 1. The security problem, restated

An enterprise asking "are we quantum-ready and crypto-agile?" is asking five different questions that are
routinely collapsed into one:

1. **Where** is cryptography (which machines, which software)?
2. **What** can it do (algorithms, key sizes, protocols)?
3. **What is allowed** to happen (policy, configuration, enabled/disabled)?
4. **What is actually happening** (which algorithm protects which data flow, today)?
5. **How hard is it to change** (who owns it, what depends on it, is it vendor-controlled)?

Only answer 4 is the exposure. Answers 1–3 are *candidates* and *upper bounds*. Answer 5 is not discoverable
from a host at all.

The most important finding of this stage is that **the regulatory definition of the thing to be inventoried
is about *active* use**. OMB M-23-02, as quoted in CISA's ACDI strategy, defines a "cryptographic system" as
"an active software or hardware implementation of one or more cryptographic algorithms that provide one or
more of the following services: (1) creation and exchange of encryption keys; (2) encrypted connections; or
(3) creation and validation of digital signatures." **[P]** (CISA, *Strategy for Migrating to Automated
PQC Discovery and Inventory Tools*, §Scope.)

So a host collector that reports "OpenSSL 3.5 is installed and can do ML-KEM" has *not* produced an M-23-02
inventory entry. It has produced a **candidate**. This is not a criticism of the current collector, which
says so honestly (`evidence = installed-package-capability`); it is a constraint on what claims the product
may make at each stage.

## 2. What the literature says an inventory must contain

### 2.1 Regulatory / government

- **M-23-02 data items** **[P]**: of nine items per system, CISA says only three "may be collected using ACDI
  or CDM": item 4 (algorithm, service provided, key length), item 5 (COTS/GOTS/custom, vendor), item 6
  (operating system and version). The other six (system identifier, FIPS-199 category, HVA id, hosting, data
  lifecycle, notes) "cannot be detected or collected using currently available automated tools". A host
  collector therefore cannot and should not claim to produce them.
- **Discovery types** **[P]**: ACDI tools provide "network, file system, database system, or software package"
  discovery, "the combination of which enables discovery of encryption for data-in-transit and data-at-rest".
  Host discovery is the *file system* and *software package* half.
- **Stated limits** **[P]**: "software packages with embedded cryptography, customized applications, or certain
  operating systems may not be discoverable using automated tools"; CISA "has not been able to confirm the
  full scope of cryptographic algorithm detection capabilities", e.g. "the embedded algorithms used within
  software packages, such as custom or government developed software". Digital certificates are singled out
  as a case where "the information explicitly includes the desired data items".
- **NIST SP 1800-38 (NCCoE)** **[S]**: discovery is organised across code/CI-CD, operational systems and
  network services, with tools for source code, binaries, network traffic and certificates, output normalised
  and correlated, then risk-ranked. (The NCCoE page returned HTTP 403; this is from search summaries.)
- **NIST CSWP 39 (crypto agility, final Dec 2025)** **[S]**: asset-centric inventory "informed by the
  criticality of the data", covering "application codes, libraries, software, hardware, firmware ... protocols,
  enterprise services, and systems"; and an explicit call for gaps in "enterprise management tools for
  managing assets, configurations, vulnerabilities, and logs" to be closed by automating "identification,
  assessment, characterization, enforcement, and monitoring of cryptography".
- **NIST IR 8547** **[S]**: (initial public draft) RSA/ECDSA/ECDH/finite-field DH deprecated after 2030 and
  disallowed after 2035; 112-bit-strength algorithms such as RSA-2048 and P-256 deprecated by 2030. Claims that
  an executive order and an OMB memo made 2030 a compliance date came from one vendor blog and are **not
  relied on**.

### 2.2 CBOM as a data model (CycloneDX / ECMA-424)

Read from the OWASP *Authoritative Guide to CBOM* **[P]** (extracted locally from the PDF):

- Asset properties matter at *variant* precision: "it makes a difference if one knows the algorithm family
  (e.g. AES) or the specific variant or instantiation (e.g. AES-128-GCM)".
- Dependencies are typed. "Cryptographic libraries 'implement' certain algorithms and protocols, but their
  implementation alone does not reflect their usage by applications. CBOM, therefore, differentiates between
  'provides' and 'uses' dependencies." And for `provides`: "A component that implements another component does
  not imply that the implementation is in use."
- **Configuration is a first-class asset.** The guide's OpenSSL example models `openssl.cnf`
  (`DEFAULT_GROUPS = x25519:SecP256r1MLKEM768`) as a `data` component of type `configuration`, and the
  algorithms it names `dependsOn` it.
- Keys and certificates have **lifecycle state** (keys: pre-activation, active, suspended, deactivated,
  compromised, destroyed; certificates: `certificateState`). State is *management* knowledge; a scanner rarely
  observes it, and inventing it would be evidence inflation.
- The schema's own evidence object **[P]** (vendored 1.6 schema): `evidence.identity` carries `methods[]`
  with a `technique` from a **closed set** — `source-code-analysis, binary-analysis, manifest-analysis,
  ast-fingerprint, hash-comparison, instrumentation, dynamic-analysis, filename, attestation, other` — and a
  per-technique `confidence` in 0..1; `evidence.occurrences[]` carries `location, line, offset, symbol,
  additionalContext`. Note what is absent: there is no field for *what kind of claim* is being made. CycloneDX
  records **how** something was found, not **how strong a statement it supports**. That gap is ours to fill.

### 2.3 Practice: what discovery projects report

- **Prior art on filesystem discovery** **[P]** (IBM `cbomkit-theia` README): scans container images/directories
  for certificates, keys, secrets (via gitleaks), `java.security` (`jdk.tls.disabledAlgorithms`) and
  `openssl.cnf` (protocol versions, cipher suites); adds them to an existing CBOM; and assigns a **0–1
  confidence "how likely it is that this component is actually executable"**. Two lessons: (a) configuration
  parsing is the common way to move from "present" to "possible", and (b) they too separate *presence* from
  *executability* — but with a single scalar, which conflates evidence kind and evidence quality.
  Explicit non-goal: no source-code scanning.
- **Dual-layer discovery** **[P]** (Zelenovic et al., KU Leuven, arXiv 2605.16549, a case study of a large
  European critical-service provider): static discovery finds "cryptographic dependencies embedded within
  application codebases, configuration artefacts"; dynamic discovery "validat[es] cryptographic behaviour
  under real operational conditions" so that discovery "reflects actual system behaviour rather than intended
  configuration states". Their findings that matter here: **"uneven evidence quality across legacy and modern
  environments"**; an **evidence-confidence field (high/medium/low)** on every register entry, introduced
  "to distinguish reliable findings from inferred findings" and which "prevented budget misallocation to false
  positives"; "hidden crypto" zones inside libraries, vendor components and middleware; and that broad
  scanning "may conflict with service stability", forcing staged scanning. Minimum attributes per candidate
  record: asset/service identifier, mechanism (e.g. RSA-2048, ECC P-256, TLS version), system context, observed
  usage.
- **Runtime hooking** **[S]** (vendor/industry summaries): captures dynamically generated keys and legacy
  calls static analysis misses, but "can introduce overhead or instability and may be discouraged in extremely
  sensitive production environments".
- **cdxgen / Hyperion** **[S]**: source-code-level crypto detection; not relevant to a host scan except as a
  reminder that application-embedded crypto is a *different tool's* job.

## 3. The evidence hierarchy — derived, not assumed

The brief offered nine words: *installed, provided, configured, allowed, associated, loaded, observed,
negotiated, used*. Testing them against the literature above gives these findings.

### 3.1 Finding: it is two axes, not one ladder

The literature (and the CycloneDX schema) mixes two independent things, and a single ladder or a single
"confidence" number hides the difference:

| Axis | Question | Example values |
|---|---|---|
| **A. Claim** | *What statement does this evidence support?* | present · capable · configured · bound · loaded · exercised |
| **B. Method quality** | *How reliably was the statement established?* | parsed authoritative database · heuristic filename match · inferred from version · runtime hook |

`cbomkit-theia`'s single 0–1 score and the case study's High/Med/Low both blur them. A `dpkg` entry is
*perfect* method quality for the claim "present" and says *nothing* about the claim "in use". Conversely a
runtime observation might be lower method quality (sampled) for the strongest claim. **[H]** — argued from the
sources, not stated by any of them.

### 3.2 The claim axis: which of the brief's nine words survive

| Brief's word | Verdict | Reason |
|---|---|---|
| installed | **keep, rename "present"** | Not all crypto is *installed* by a package manager (a bundled DLL, a static binary, a file copied in). "Present" (an artefact exists at a location) is the true base claim. Package-database membership is one *method* for it. |
| provided | **keep as "capable"** | The CBOM guide's `provides` = "implements … does not imply … in use". It is a *knowledge-based mapping* (package+version → algorithms), not an observation. Its evidence is a citation, not the host. It must remain visibly a different kind of thing from an observation. |
| configured | **split in two** | Configuration can *enable* (`DEFAULT_GROUPS = …`), *restrict* (`jdk.tls.disabledAlgorithms`, crypto-policies), or be *absent* (defaults apply). Restricting evidence is as valuable as enabling evidence: it *lowers* an upper bound. Recommend "policy" with a direction: `permits / forbids / unspecified`. |
| allowed | **merge into configured/policy** | "Allowed" and "configured" are the same claim from opposite sides; keeping both invites double counting. |
| associated | **keep, and split** | Two different facts: *static association* (this binary links this library; this service is configured to use this certificate) vs *deployment association* (this service is enabled to start). Both are still "could use", not "is using". |
| loaded | **keep** | Requires a process to be inspected; strictly stronger than association because it is a runtime fact, but still not "used" (a loaded library may never be called). |
| observed / negotiated / used | **collapse to "exercised"** | The only host-independent ways to prove use are: seeing a handshake/operation happen. *Negotiated* is that observation for a network protocol and comes from the **network** collector, not the host. "Used" cannot be proved from a static host snapshot at all, only observed. Three words for one rung invites the same inflation the brief warns about. |

### 3.3 One rung the brief does not name: **provisioned material**

Certificates and key metadata are neither software nor configuration: they are *data the machine holds*.
M-23-02 singles certificates out as directly containing the required items **[P]**. Their claim is
"this machine holds a certificate/key of this algorithm and size", which is stronger than "capable" (the
algorithm is *demonstrably in the deployment's trust or identity material*) yet not "in use". It deserves its
own rung, and it is where the direct-evidence items 4 (algorithm, key length) actually come from.

### 3.4 Proposed claim ladder (input to Agent 3, not a decision)

```
 present      an artefact exists here (package db row, file, store entry, service registration)
   ▼
 capable      cited knowledge says this artefact can perform algorithm X   (knowledge, not host evidence)
   ▼
 policy       configuration/policy permits or forbids X   (direction matters)
   ▼
 provisioned  the host holds key/certificate material of algorithm X, size N   (metadata only)
   ▼
 bound        a named application/service is configured or linked to use artefact/material Y
   ▼
 loaded       a running process has artefact Y mapped
   ▼
 exercised    an operation of X was observed (handshake, signature, decryption)
```

Rules that follow from the sources and must survive into design **[H]**:

1. A relationship may never imply a rung higher than the weakest evidence on its path. (`nginx` *bound* to
   OpenSSL, OpenSSL *capable* of ML-KEM ⇒ "nginx *could* offer ML-KEM", never "nginx uses ML-KEM".)
2. `policy = forbids` **lowers** the upper bound of everything downstream. It is evidence *against* a
   capability being reachable and must be represented, not dropped.
3. Correlation between host and network (`exercised`) must remain two separate evidence records that a
   third, explicitly-labelled *assessment* joins (§5).
4. Absence is not evidence of absence. "No policy found" ≠ "unrestricted".

## 4. Required inventory, by what the enterprise decision needs

What the migration decision needs, mapped to what a host can supply:

| Enterprise question | Data required | Host can supply? | Best claim rung |
|---|---|---|---|
| Which machines run which crypto libraries/versions? | package/library identity + version + location | **Yes**, reliably | present |
| What can those libraries do (incl. PQC)? | version → algorithm mapping, cited | **Yes**, as knowledge | capable |
| What is switched on/off? | crypto-policy, library and service configuration | **Partly** (per stack) | policy |
| What identity/trust material exists and how strong is it? | certificate/key algorithm, size, curve, validity, issuer, store | **Yes** (metadata only) | provisioned |
| Which application depends on which library/material? | linkage, service config, process maps | **Partly** | bound / loaded |
| What is really happening on the wire? | handshakes | **No** — network side | exercised (network) |
| How long must the data stay confidential? Who owns it? | classification, retention, RACI | **No** — governance | out of scope |
| Is the vendor going to fix it? | vendor roadmap | **No** | out of scope |

The bottom three rows are why the case study calls discovery "a governance capability": the host scanner feeds
the register; it is not the register.

## 5. Host evidence and network evidence must stay separate

The brief's boundary (`tls scan` = outside, `run` = inside) is supported by every source: NCCoE integrates
"network services" as a *separate domain* from operational systems; the case study treats "dynamic telemetry
(TLS handshakes …)" as its own input stream. **[S]/[P]**

Correlation requires an identity link that neither side owns: host `web01` ↔ endpoint `web01.example:443`.
That link can itself be wrong (load balancers, NAT, shared certificates, containers). The existing product
already has a manual `link` between a host and an endpoint (the UI's "Link a host") **[P]** (repo). Recommended
rule **[H]**: correlation output is a *separate, labelled record type* ("assessment"), always carrying (a) both
source evidence references, (b) the link's own evidence (manual / certificate match / address match) and
(c) a claim rung no stronger than the *weakest* input. It is never written back into either side's record.

## 6. Known blind spots (a host scanner cannot see these — say so in the product)

| Blind spot | Why | Source |
|---|---|---|
| Crypto embedded in application code/binaries (static linking, Go/Rust, custom) | no package metadata, no shared library | CISA **[P]** ("embedded algorithms … custom or government developed software") |
| Configuration the application computes at runtime | not in any file | **[H]** |
| Keys/certs in HSMs, TPMs, smart cards, cloud KMS | material never on disk; only a reference is | **[H]** (CBOM guide models HSMs separately **[P]**) |
| Cryptography in SaaS/third-party services | not on the host | case study **[P]** ("cryptographic inheritance risk") |
| What is actually used | requires observation | §3 |
| Containers' *own* crypto | separate filesystem view per image | **[H]** |
| Data at rest encryption choices in databases/disks | database/volume metadata, not the OS package set | CISA lists "database system" as a separate discovery type **[P]** |
| Crypto in scripts and interpreted runtimes (Python `cryptography`, Node, Java JARs) | lives in language ecosystems | **[H]**, partly visible via the OS package manager |
| Firmware / BIOS / device crypto | below the OS | **[H]** |
| Tamper: a compromised host can lie to any host-side collector | attacker controls the observer | **[H]** |

## 7. Security requirements (for the collector itself)

The collector reads sensitive machines. These are requirements, not suggestions; each is testable.

| ID | Requirement | Rationale |
|---|---|---|
| SR-1 | **Never read, copy, hash or transmit private-key contents, passwords, tokens, cookies, API credentials.** Where the *existence or protection state* of a key is valuable (unencrypted key on disk), obtain it without exposing the secret, e.g. by file name/permissions and at most a fixed-length armor-label prefix, discarded immediately and never logged. | Brief §25; the collector must not become the exfiltration tool it is meant to find |
| SR-2 | **Read-only.** No writes to the host except its own temp/state, none to system config. | Brief §25; `collector.Collector` already states it |
| SR-3 | **Least privilege by default;** anything that needs elevation is a separately-enabled, separately-reported capability, and the CBOM records what privilege each observation used. | The platform research will show which evidence needs root/Administrator |
| SR-4 | **No arbitrary subprocess execution driven by host data.** Prefer APIs and file parsing; where a subprocess is unavoidable, fixed argv, no shell, absolute path, bounded output/time. | Command injection; prior code already avoids subprocesses **[P]** |
| SR-5 | **Path safety.** Reads confined to an explicit root; no following symlinks out of it; bounded sizes and depth; no reading of special files. | The `fs.FS` design gives this for free **[P]**; new collectors must keep it |
| SR-6 | **Treat every string from the host as attacker-controlled** (certificate subjects, config values, package names) — already a UI rule **[P]**; extends to CBOM consumers. | A host under attack controls its own metadata |
| SR-7 | **No network access during collection;** upload is a separate, explicit, authenticated, encrypted step. | Brief §25 |
| SR-8 | **Deterministic, auditable output.** Same host state → byte-identical CBOM; every fact carries source location, method and privilege. | Reproducibility, audit |
| SR-9 | **Bounded cost.** Time, memory, file-count and I/O budgets; staged/throttled scans; never scan network shares or pseudo-filesystems by default. | Case study: scanning "may conflict with service stability" **[P]** |
| SR-10 | **Integrity of the collector itself:** signed distribution and verifiable version. | Brief §24; separate workstream |
| SR-11 | **Honest failure.** A collector that could not see something says *unknown*, never *none*. | Blind spots |
| SR-12 | **Data minimisation on upload:** hostnames, paths and usernames are sensitive in themselves; make redaction/opt-in explicit. | **[H]** |

## 8. Proposed discovery levels — Agent 1's view

The brief's seven levels are a fair *delivery* order but conflate the two axes in §3. Proposal to Agent 3:

| Brief's level | Agent 1 comment |
|---|---|
| 1 Installed software | Keep; it is the *present* rung and the anchor for everything else. **Rename** to "present" and include non-package artefacts (loose libraries, standalone binaries) as a stated later extension. |
| 2 Capabilities | Keep, but note it is **not host evidence** — it is a cited knowledge table applied to level-1 evidence. It should be a *derivation stage*, possibly with its own versioned knowledge base, not a collector. |
| 3 Configuration | Keep; **highest value-per-effort** after level 1 because it is where crypto policy lives and it *reduces* false positives. Make direction (`permits/forbids/unspecified`) explicit. |
| 4 Certificates & key metadata | Keep; arguably belongs *before* 3 in value terms because it is the only host evidence that directly carries algorithm and key length (CISA item 4). Ordering is an architecture decision, not a security one. |
| 5 Application association | Keep; but note it splits into static (linkage/config) and deployment (service enabled). |
| 6 Runtime | Keep, but treat as **optional and separately privileged** (needs process inspection; the sources call it destabilising in sensitive environments). |
| 7 Host/network correlation | Keep as a **joining layer, not a collector** (§5). |

Because the levels consume each other (brief §12), the recommended *evidence-graph* rule is: **every record at
rung N must reference the record(s) at rung < N that it depends on.** That single rule turns seven scans into
one graph and makes "never stronger than the weakest link" mechanically checkable.

## 9. Open questions for Agent 2 (what needs the platform to answer)

1. Can `policy` evidence be obtained on each OS **without privilege and without running a subprocess**?
   (Windows: Schannel/TLS settings; Linux: crypto-policies, `openssl.cnf`, `sshd_config`, `java.security`.)
2. Can certificate **metadata** be enumerated on each OS **without** touching private keys, and can a private
   key's *presence/protection* be established without reading it? (SR-1)
3. What is the cheapest reliable source of `bound` (application ↔ library/material) on each OS, and what
   privilege does it need?
4. What does each OS expose about a **running** process's loaded crypto modules without invasive hooking?
5. Which **package managers** are readable directly (files/databases) versus only through a tool?
6. What does "FIPS mode" look like as evidence on each OS, and can it be read without a subprocess?
7. Which of the platforms can be tested by us now (Windows: this machine; Kali: needs a session) vs by
   container/VM?

## 10. Recommendations

1. **Adopt the two-axis model** (claim × method quality) rather than one confidence number; carry the claim
   rung explicitly on every record. (§3.1)
2. **Treat "capable" as knowledge, not observation,** stored and versioned as such, with its citations. (§3.2)
3. **Add "provisioned" as its own rung** and prioritise it for early delivery because it is the only host
   source of direct algorithm/key-length evidence. (§3.3)
4. **Represent policy with a direction,** including "forbids", since restricting evidence is the main way to
   remove false positives. (§3.2)
5. **Never emit a relationship stronger than the weakest evidence on its path;** enforce mechanically. (§3.4)
6. **Keep host and network evidence as separate record streams; correlation is a labelled third artefact.** (§5)
7. **Make blind spots first-class output:** a CBOM section stating what this collector *cannot* see on this
   host, so silence is never read as safety. (§6, SR-11)
8. **Hard-wire SR-1 as a test,** not a guideline: a corpus of secret-bearing files that must never appear in
   output. (§7)
9. **Do not claim M-23-02 inventory coverage** until rung `exercised` or an equivalent "active" determination
   exists; until then call the output *candidates and upper bounds*. (§1)

## 11. What failed / could not be established

- The NCCoE SP 1800-38 practice-guide page returned **HTTP 403**; its content here is **[S]** only.
- Three PDFs came back from the fetch tool as unreadable binaries; they were saved and text-extracted locally
  with `pdftotext` (the CISA strategy, the CBOM guide and the KU Leuven paper), so those quotes are **[P]**.
- I did **not** obtain: the NIST SP 1800-38B test results (which tools detected what), CNSA 2.0 guidance, the
  ENISA/ETSI inventory guidance the case study cites, or any evaluation of false-positive rates of host
  crypto scanners. **The false-positive claim in §3 is therefore [H]**: the sources say confidence scoring
  prevented false-positive spend, not how large the problem is.
- The industry-vendor pages surfaced by search (cryptographic-inventory vendor lists) were treated as
  **[S]** and not used for any design claim.

## 12. Assumptions and risks

| # | Assumption | If wrong |
|---|---|---|
| A1 | Enterprises will accept "candidate / upper bound" language for early levels | The product's early output is seen as incomplete rather than honest |
| A2 | The two-axis model is implementable in CycloneDX 1.6 without inventing incompatible fields | Need namespaced properties (already the project's practice) and a documented mapping |
| A3 | Certificate/key *metadata* can be obtained without exposing key material on all platforms | SR-1 conflicts with the "provisioned" rung on some platform and it must be dropped or gated there |
| A4 | Presence of policy evidence is common enough to be worth a level | Level 3 yields mostly `unspecified` and adds effort without reducing false positives |

| Risk | Severity | Mitigation |
|---|---|---|
| Evidence inflation (claiming use from presence) | High | Rule §3.4-1, enforced mechanically, reviewed by Agents 6 and 8 |
| The collector becomes a secret exfiltration channel | High | SR-1 as a test corpus |
| Cost/instability of scanning production hosts | Medium | SR-9, staged scans |
| Misleading completeness (no blind-spot statement) | High | Recommendation 7 |

## 13. Handoff

See `artifacts/handoff-01-security-to-platform.md`.

## Sources

Primary (read):
- CISA, [Strategy for Migrating to Automated PQC Discovery and Inventory Tools](https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf) (Sept 2024)
- OWASP CycloneDX, [Authoritative Guide to CBOM](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf)
- Zelenovic, Taghizadeh, Pena-Gonzalez, Gómez García, Preneel (KU Leuven COSIC), [Post-Quantum Discovery as a Governance Capability](https://arxiv.org/pdf/2605.16549)
- IBM, [cbomkit-theia](https://github.com/IBM/cbomkit-theia) README
- CycloneDX 1.6 JSON schema, vendored at `testing/schema/bom-1.6.schema.json` (evidence and technique enumerations)
- This repository: `internal/collector`, `internal/plugins/apt`, `internal/scan`, `internal/cbom`, `docs/writing-a-plugin.md`

Secondary (search summaries; not verified against the primary):
- [NIST SP 1800-38 (NCCoE)](https://www.nccoe.nist.gov/publications/practice-guide/migration-post-quantum-cryptography-nist-sp-1800-38-practice-guide) — page returned 403
- [NIST CSWP 39, Considerations for Achieving Crypto Agility](https://csrc.nist.gov/pubs/cswp/39/considerations-for-achieving-cryptographic-agility/2pd)
- [NIST IR 8547 (initial public draft)](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)
- [CBOMkit](https://github.com/cbomkit/cbomkit), [cdxgen](https://github.com/cdxgen/cdxgen), [PQCA CBOMkit announcement](https://pqca.org/blog/2025/pqca-announces-cbomkit-advanced-tools-for-generating-and-analyzing-cryptographic-bills-of-materials/)
