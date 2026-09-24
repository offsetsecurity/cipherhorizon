# Agent 3 — Security Architecture

```
AGENT      3 — Security Architect
DATE       2026-09-24
OBJECTIVE  Decide whether the proposed evidence and platform findings can actually deliver the evidence an
           enterprise CBOM needs, then design the first implementation level.
INPUT      artifacts/agent-01-security-research.md + handoff-01
           artifacts/agent-02-platform-research.md + handoff-02
OUTPUT     this document; artifacts/evidence-model.md; artifacts/collector-contract.md;
           artifacts/handoff-03-architecture-to-builder.md; docs/decisions/ADR-0001..0008
```

## 1. I challenge both handoffs first

The brief asks one question of me: **does the proposed architecture actually provide the evidence required for
an enterprise CBOM?** Before answering it, the inputs.

### 1.1 Challenge to Agent 1 (requirements)

| Agent 1 position | My verdict | Reason |
|---|---|---|
| The regulatory object is *active* use; presence/capability are candidates | **Accept — and it caps what we may claim** | Sourced from CISA quoting OMB M-23-02. It is the single most important constraint on wording. |
| Two axes (claim × method quality) | **Accept, with Agent 2's refinement** | Method quality declared per method, overridable downward only. No invented numeric confidence: no source measured a false-positive rate (Agent 1 §11), so a number would be fiction. |
| `capable` = knowledge | **Modify** | Agent 2 showed capability can be *probed* from the OS. Two kinds. |
| Add a `provisioned` rung | **Accept** | It is the only host source of direct algorithm/key-length evidence (CISA item 4). |
| `policy` with direction | **Accept**, and made a *modifier*, not a chain link | Policy does not strengthen a path; it changes what it means. |
| Blind spots as first-class output | **Accept → Coverage record** | Made structural, not a note. |
| SR-1…SR-12 | **Accept**, and made *testable* | Every SR maps to a control and an automated test (§6). |
| "Do not claim M-23-02 inventory coverage until an *active* determination exists" | **Accept** | Wording rule for every level's release notes. |
| Hostnames/paths redaction (SR-12) is "[H]" | **Partly reject as a requirement for Level 1** | Redaction needs a consumer to define what to redact. Level 1 makes it *possible* (allow-listed attributes, salted host ID) without shipping a policy. Recorded as an open decision. |

### 1.2 Challenge to Agent 2 (platform)

| Agent 2 position | My verdict | Reason |
|---|---|---|
| Ladder is a partial order | **Accept, compress** | A partial order alone is not computable. I added four **strength classes** (E0–E3) so path composition is a `min`. |
| `bound` one rung + edge kinds | **Accept** | |
| Windows without PowerShell (API/file only) | **Accept → ADR-0004** | Subprocess = SR-4; PowerShell 5.1 dependence; every probe had an API equivalent. |
| Linux is almost entirely `ʳ` researched | **Accept, and it changes scope** | *I will not design the first level to depend on any Linux mechanism nobody has run.* Linux in Level 1 is limited to the **existing Debian/Ubuntu package collector** (already exercised by fixtures) and any Linux host the user can provide for validation. |
| Stub-module trap | **Accept → `unknown(stubbed-source)`** | The most valuable finding in the platform work: a source that fails *silently* must be modelled. |
| Standard-user tier is the default | **Accept → ADR-0005/privilege tiers** | |
| Distribution: signed standalone + native packages | **Accept the direction; separate workstream** | See §7. |
| "x/sys does not wrap `CertGetCertificateContextProperty`/CNG" | **Accept as a constraint and a risk** | The handwritten syscall layer is the highest-risk code in the program. |
| Matrix cells marked `✓ᵀ` for Windows | **Qualify** | Tested on one standard-user machine; not "Windows". Every release statement must carry that scope. |

### 1.3 Things neither handoff resolved (my decisions)

| Open item | Decision |
|---|---|
| Does host-observed network activity count as host evidence? | **Yes, by observer** — stream is defined by who observed it; correlation is a separate Assessment (ADR-0006). |
| Should cross-platform levels have one order? | **No.** The evidence shows different cheap-first orders. Levels are increments defined by *evidence kind*, delivered platform by platform, with a per-platform status (§4). |
| Where does capability mapping live? | **Out of collectors**, in a versioned knowledge base keyed by (family, version), so a loose DLL and a package get the same mapping. |

## 2. Does the architecture provide enterprise-grade evidence? (the gate question)

Honest answer by level, against the enterprise question in the brief:

> *What cryptography exists across my machines, where does it come from, what applications can use it, what
> is configured, what certificates and key metadata are present, what is actually being used where we can
> prove it, and what does that mean for PQC migration and crypto-agility?*

| Part of the question | Answerable at | Answer quality | Still cannot answer |
|---|---|---|---|
| What exists / where from | L1 | **Strong** for package-managed and (Windows) loose libraries; **blind** to statically linked and embedded crypto | custom/embedded crypto |
| What can it do (incl. PQC) | L2 | Strong (mapped: cited; probed: from OS) | what it *does* |
| What certificates/keys are present | L3 | **Strong, direct** — the only host evidence that carries algorithm and size | key lifecycle/state; HSM-held keys |
| What is configured | L4 | Strong on RHEL-family/AL2023/SLE15SP4+/Windows; weak on Debian-family (no system policy) | runtime-computed config |
| What applications can use it | L5 | Partial: static imports, package deps, service config — **with a known false-negative class (dynamic loading)** | applications that load crypto dynamically until L6 |
| What is actually used, provably | L6 (host loaded) + network (`exercised`) | **Host collector can never prove "used"**; it can prove "loaded" | actual use without the network stream or logs |
| What it means for PQC migration | out of the collector | needs governance data (data lifetime, ownership, vendor roadmap) | by design |

**Verdict: PASS with a stated limit.** The architecture can supply *candidate and upper-bound* evidence
(E0–E1) reliably, *loaded* evidence conditionally (E2), and **cannot** supply *exercised* evidence from the
host at all. That is not a defect to engineer away; it is the boundary of the product and must appear in
the wording of every report ("candidate", "could use", "was loaded"). It is the same conclusion Agent 1 drew
from the regulatory definition, now reached from the design.

## 3. Discovery levels — decision

The brief's seven levels were a hypothesis and I am allowed to change them. Three changes and one addition:

| # | Level | Adds (sensors) | Adds (derivation) | Change from the brief |
|---|---|---|---|---|
| **L0** | **Foundation** | none — the contract, method registry, `unknown`/Coverage, canary corpus, host identity, contract validation, fail-closed projection | — | **New.** Nothing can be built honestly without it; Level 1 has nowhere correct to emit otherwise. |
| **L1** | **Present** | package DBs (Debian/Ubuntu: existing) ; Windows: uninstall registry + bounded file walk + PE version/signature | — | Renamed from "Installed software": includes non-package artefacts, which Windows proved essential. |
| **L2** | **Capable** | Windows: CNG algorithm probe (probed) | capability mapping via the knowledge base (mapped), incl. for loose files | Now explicitly a *derivation* stage; only Windows gains a new sensor. |
| **L3** | **Provisioned** (certificates, key metadata) | cert stores (Windows), certificate directories (Linux) | algorithm/size → catalogue verdicts | **Moved before configuration** (brief: L4). Reason: cheapest, direct, CISA item 4; on the test machine it already found RSA-1024/512 roots. |
| **L4** | **Policy** (configuration) | Schannel/GPO/FIPS (Windows); `crypto-policies`, `openssl.cnf` (Linux) | policy modifier on paths | Moved after certificates. Per-application config parsers are separate, opt-in work items. |
| **L5** | **Bound** (application association) | PE/ELF imports, package deps, services | E1 path claims | Static imports + package deps first; dynamic-load *hints* only. |
| **L6** | **Loaded** (runtime) | process modules — separately privileged, **stub-aware** | E2 claims | Optional; never default. |
| **L7** | **Correlation** | none (joins streams) | Assessment records | **A joining layer, not a collector**; labelled and capped by the weakest link. |

Cumulative rule (brief §12, mechanical): each level's derived facts list `BasedOn`; the validator rejects a
level-N derived fact whose inputs are not present. Level 4 therefore *needs* Level 1's artefact identity to
say which library a config belongs to, and Level 5 *consumes* Levels 1–4 to say "could use X, restricted by
policy P".

## 4. The first implementation level

**Decision (for Agent 4/5): implement L0 + L1, with the existing capability mapping re-expressed as L2's
mapped derivation. Nothing else.**

Why this cut ("start with the highest-value *validated* level"):

- **Validated:** Windows `present` methods were each *tested* by Agent 2 on a real machine; Debian/Ubuntu
  already has fixtures and goldens. Nothing in L1 depends on an unrun Linux mechanism.
- **High value:** L1 alone fixes the biggest correctness problem — the CBOM currently conflates
  package-found and capability-inferred facts — and it finds bundled crypto on Windows that no package
  database lists (OpenSSL 3.5.7, GnuTLS, NSS on the test box).
- **Smallest step that makes every later level honest:** L0 is the contract; without it L3+ would repeat
  the existing mixing.

Per-platform status the release must state (and the gatekeeper will check):

| Platform | L0 | L1 | L2 (mapped) | Tested how |
|---|---|---|---|---|
| Debian / Ubuntu | ✓ | ✓ (refactor of existing) | ✓ (moved to KB) | fixtures/goldens; **live host not yet available** |
| Kali | ✓ | ✓ (dpkg) | ✓ | **only if the user provides a session**; otherwise "not validated" |
| Windows | ✓ | ✓ new | (probed capability → next increment) | this machine, standard user |
| RHEL/SUSE/Alpine/Amazon | contract ready | ✗ not implemented | ✗ | not implemented |
| macOS | — | ✗ | ✗ | **not implemented, not validated** |

## 5. Architecture in one picture

```
          ┌──────────────── OS-specific (build-tagged) ────────────────┐
          │  debian.dpkg   windows.uninstall   windows.fs.walk          │   SENSORS
          │  (Sensor → Batch{Observations, Coverage})                   │   emit only evidence
          └───────────────────────────────┬─────────────────────────────┘
                                          ▼
                       NORMALISE  (canonical keys, merge, validate contract)
                                          ▼
              ┌───────────── KNOWLEDGE (versioned, cited) ─────────────┐
              │  capability mappings keyed by (family, version-range)  │
              └───────────────────────────┬────────────────────────────┘
                                          ▼
                       DERIVE  (capable(mapped), path = min(edges), policy effect, incomplete)
                                          ▼
                       PROJECT  (fail-closed CycloneDX 1.6, deterministic)  ──►  host CBOM
                                          ▲
                         Coverage / blind spots ───────────────┘
```

Design principles, each with the reason it is here:

1. **Evidence pipeline, not collectors** (brief §12) — every derived fact names its inputs.
2. **OS code stops at the observation** — derive/project cannot import platform packages (checked by test).
3. **Fail closed** — an over-claiming edge is a build error, not a warning.
4. **Absence is earned** — `unknown(reason)` is first-class; `confirmed-absent` only from authoritative methods.
5. **Standard-user default** — elevated evidence is a separate, reported capability.
6. **Deterministic** — same host state, same bytes.

## 6. Security architecture

### 6.1 Trust boundaries and adversaries

```
 [attacker-controlled host content] ──► SENSOR ──► Batch ──► pipeline ──► CBOM ──► (upload, later) ──► server/UI
   files, certs, configs, package                 (trust boundary 1)              (trust boundary 2)
   names, registry values
```

Adversaries considered: (a) **the host itself** — a compromised machine lies to any host collector; (b)
**malicious content** — crafted certificates/configs/PE files aimed at parsers (DoS, memory exhaustion,
injection into reports); (c) **the collector as a weapon** — coerced into reading secrets or executing code;
(d) **tamper in transit** (later, upload). (a) cannot be fixed by the collector: it is a *stated blind
spot* ("a compromised host can lie", Agent 1 §6), and signed/attested collection is future work.

### 6.2 SR → control → test

| SR | Control (design) | Automated verification (the gate) |
|---|---|---|
| SR-1 no secrets | Attribute allow-lists; no key-open calls; orphan keys = presence only; cert-paired derivation | **Canary corpus** on test hosts (synthetic private keys, passwords/tokens in configs, `ssl_password_file` targets) must appear **nowhere** in `Batch`, CBOM, logs or errors; forbidden-symbol test on the syscall layer |
| SR-2 read-only | Read-only APIs; no write calls in sensor packages | Package test for forbidden write functions |
| SR-3 least privilege | Standard-user tier is complete in itself; elevation per capability, recorded | Test: default run needs no elevation; elevated methods refuse without it and report `unknown(permission)` |
| SR-4 no subprocess | `os/exec` forbidden in sensors; API/file paths only | Import test |
| SR-5 path safety | `fs.FS` confinement; allow-listed walk roots; size/depth caps; no symlink escape | Fixtures with symlink loops, huge files, deep trees |
| SR-6 hostile strings | Data only; never interpreted; report/UI already escape | Fixtures with control characters, `../`, very long names |
| SR-7 no network at collection | No net imports in sensors | Import test |
| SR-8 deterministic/auditable | Sorted, no PIDs/timestamps in observations; IDs are content hashes | Byte-identical golden reruns |
| SR-9 bounded | Budgets on every walk/parse, reported as Coverage | Test: budget hit ⇒ `partial` + reason, never silent |
| SR-10 collector integrity | Signed distribution (§7) | Release verification |
| SR-11 honest failure | `unknown(reason)`, stub wrapper | Test: stubbed source ⇒ `unknown`, not a negative |
| SR-12 minimisation | Salted host ID; allow-listed attributes; redaction *hook* (policy TBD) | Test: raw machine id never emitted |

**The highest-risk code** is the hand-written Windows syscall layer (Agent 2 §2.5: `x/sys` lacks the wrappers).
It is a small, review-gated package with a fixed function set; no `Export*`/private-key symbol may appear.

### 6.3 Privilege tiers

| Tier | Contents | Default |
|---|---|---|
| `user` | everything tested in Agent 2 §2.9 for Windows; package DBs, `/etc`, cert dirs on Linux | **on** |
| `admin` | TPM, machine key metadata, other users' modules, event logs | off; separate switch |
| `debug` | process memory/handle inspection | off; separate switch; L6 only |

The CBOM records the highest tier *used*.

## 7. Deployment architecture (separate workstream — recommendation, not build)

Agent 2's findings point to: **signed standalone collector + native packages + optional ephemeral execution;
persistent agent deferred to its own decision (ADR-0007).**

| Model | Fits | Trade-off |
|---|---|---|
| Signed standalone (Authenticode on Windows; cosign/SLSA already built for archives) | ad-hoc, ephemeral, air-gapped | SmartScreen reputation is per certificate thumbprint and resets on renewal (Agent 2 §10) |
| Native packages (MSI/MSIX; `.deb`/`.rpm` from a signed repository) | enterprise deployment (Intune/SCCM; APT/DNF) | repository signing infrastructure is not built |
| Ephemeral execution (push, run, collect, delete) | minimal persistence, SR-2/SR-7 | needs a deployment channel and credentials |
| Persistent agent | continuous evidence, scheduling | **changes the threat model** (persistence, network, updates); must be its own architecture review |

**Built today:** cosign keyless signing, SLSA provenance and SBOMs for the standalone archives.
**Not built:** Authenticode, MSI/MSIX, `.deb`/`.rpm`, signed repositories, notarization. None of this is on the
critical path of L0/L1; none may be claimed.

## 8. CBOM projection (summary; full rules in `evidence-model.md` §8)

- Package/loose artefact → `library`/`application` + `evidence.occurrences`.
- `capable(mapped)` → `provides` **plus** claim + knowledge-base citation.
- `bound` → `dependsOn` **plus mandatory** `cipherhorizon:claim=bound` and `binding-kind`. CycloneDX reads
  `dependsOn` as "uses"; we may only say "could use", so an edge without the claim property is a **build error**.
- Certificates → the certificate/public-key/algorithm structure already implemented for endpoints.
- Coverage and privilege → `metadata.properties`.
- Evidence technique → CycloneDX's closed list (`manifest-analysis`, `binary-analysis`, `filename`, …); numeric
  confidence only for authoritative methods.

## 9. Testing architecture (input to Agent 7)

- **Ground-truth lab**: known-crypto hosts with expected sets — OpenSSL (3.0 and 3.5), GnuTLS, OpenSSH, Java,
  RSA/ECDSA/Ed25519 certificates, PQC-capable and legacy configurations. Compare
  `EXPECTED / DETECTED / MISSING / FALSE-POSITIVE / EVIDENCE / CLAIM`.
- **Canary corpus** for SR-1 (a release gate, not a nice-to-have).
- **Trap fixtures**: stubbed sources, empty override sets (`unspecified`), symlink loops, hostile strings.
- **Environments**: Windows (this machine, standard user; elevated run as a deliberate, documented step);
  Linux via the user's Kali *if provided*, otherwise CI containers (Debian, Ubuntu, Alpine, Rocky/Alma,
  openSUSE, Amazon Linux, Kali) — with the caveat that kernel-level evidence is not faithful in containers.
- **Oracle**: PowerShell on Windows (and `openssl`, `update-crypto-policies` on Linux) run **by the test harness only** to cross-check the Go
  collector's output.

## 10. Risks and what would make me change this

| Risk | Sev. | Response |
|---|---|---|
| Over-engineering: the model outgrows the first customers' needs | M | L1 uses two rungs, one class; the rest exists so later levels cannot break the model |
| CycloneDX consumers misread `dependsOn` | H | mandatory claim property; document-level statement; fail-closed |
| Refactor destabilises the existing Debian output | M | compatibility test on components and `provides` edges; golden diffs reviewed line by line |
| Hand-written syscalls read something they shouldn't | H | narrow fixed wrapper set; forbidden-symbol test; canary corpus; Agent 6 review |
| Linux claimed without a live test | H | status table in §4; gatekeeper checks wording |
| Scope creep into application config parsers | M | opt-in, one work item each, allow-list only |

**Reopen the architecture if:** the canary corpus finds any leak path; a platform makes `unknown` the dominant
outcome; or a real customer needs a per-fact numeric confidence that cannot be replaced by the method/claim pair.

## 11. Decisions that need the user (not the agents)

1. **A Linux test host.** The Kali machine must be reachable (SSH) or the user must run a provided script and
   return its output; otherwise Debian-family stays "fixtures only".
2. **Redaction policy** for hostnames/paths in uploads (SR-12): a customer-facing decision.
3. **Privilege posture:** confirm standard-user-as-default is acceptable to the intended customers.
4. **Whether to proceed to build** (Agents 4–5) on this scope (L0 + L1).

## 12. Handoff

See `artifacts/handoff-03-architecture-to-builder.md`. Decisions are recorded in `docs/decisions/ADR-0001…0008`.
