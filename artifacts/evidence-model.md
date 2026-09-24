# Evidence model (host-side)

```
OWNER    Agent 3 — Security Architect
STATUS   Proposed for Level 0/1. Not yet implemented. Derived from Agents 1 and 2, changed by Agent 3 where noted.
SCOPE    Host evidence only. Network evidence (`tls scan`) is a separate stream (ADR-0006).
```

## 1. Purpose

The model exists to make one rule mechanical:

> **No statement in a CBOM or report may be stronger than the weakest evidence on the path that supports it.**

Everything below is in service of that rule and of the brief's chain
`installed ≠ capable ≠ configured ≠ associated ≠ running ≠ used`.

## 2. Four kinds of thing (never mixed)

| Kind | What it is | Made by | Example |
|---|---|---|---|
| **Observation** | A fact a sensor saw on the host. Immutable. | OS-specific collector | "`libcrypto-3-x64.dll` exists at `Program Files/Git/mingw64/bin`, `FileVersion 3.5.7`" |
| **Knowledge** | A cited statement about the world, independent of any host. Versioned. | Maintainers | "OpenSSL ≥ 3.5.0 implements ML-KEM (OpenSSL 3.5.0 CHANGES)" |
| **Derived fact** | Output of a rule applied to observations and knowledge. Carries the rule and its inputs. | Derivation stage (OS-agnostic) | "That file is *capable (mapped)* of ML-KEM" |
| **Assessment** | A judgement joining streams (host + network) or applying risk. Out of scope for the host collector. | Later | "host and endpoint suggest exposure" |

Only Observations are *host evidence*. A Derived fact is labelled as derived and cites both its inputs and its
knowledge entry. This is the resolution of Agent 1's "capable is knowledge, not observation" (A5), refined by
Agent 2's finding that some capability **can** be observed (probed).

## 3. Claims

A **claim** says what an observation asserts. The set is a **partial order**, not a ladder (Agent 2, A2), with a
small number of **strength classes** so that composition is computable.

### 3.1 Claim rungs

| Rung | Asserts | Sub-kind / qualifier | Class |
|---|---|---|---|
| `present` | an artefact exists here (package row, file, registry/store entry, service registration) | — | **E0 existence** |
| `provisioned` | the host holds key/certificate *material* of algorithm X, size N (metadata only) | — | **E0 existence** |
| `capable` | the artefact can perform algorithm X | `probed` (asked of the running system) **or** `mapped` (cited knowledge applied to a present artefact) | **E0 existence** |
| `policy` | configuration permits or forbids algorithm/protocol X | direction: `permits` · `forbids` · `unspecified` | modifier (see §3.3) |
| `bound` | a named application/service is linked or configured to use artefact/material Y | edge kind: `static-import` · `package-depends` · `service-config` · `dynamic-load-hint` | **E1 reachable** |
| `loaded` | a running process has artefact Y mapped | — | **E2 loaded** |
| `exercised` | an operation of X was observed (handshake, signature, decryption) | — | **E3 exercised** |

Changes from the inputs, and why:

- **`capable` has two kinds** — `probed` vs `mapped` (Agent 2, A5). CNG opened `ML-KEM` on the test machine
  (probed); "OpenSSL 3.5.x provides ML-KEM" is mapped. Different strength, different falsification.
- **`bound` is one rung with edge kinds**, not two rungs (Agent 2). Static and deployment association both mean
  "could use".
- **`exercised` is defined but not produced by the host collector.** It belongs to the network stream and to a
  future log-based sensor (§7). It is in the model so that nothing else can borrow its name.
- **`provisioned` is E0, not a step above `capable`.** A certificate proves *material exists*, not that anything
  uses it.

### 3.2 Strength classes and composition

```
E0 existence  <  E1 reachable  <  E2 loaded  <  E3 exercised
```

A **relationship** (an edge in the evidence graph) has a class. A **path** — application → library →
algorithm — has the class of its **weakest** edge, and the words a report may use follow the class:

| Class | Permitted wording | Forbidden wording |
|---|---|---|
| E0 | "is present", "holds", "can perform (mapped/probed)" | "uses", "supports" (ambiguous) |
| E1 | "could use", "is configured to permit" | "uses", "is using" |
| E2 | "has loaded" | "uses" |
| E3 | "was observed performing" | — |

Worked example (the brief's own):

```
present   OpenSSL 3.5.7 (file, PE version)            E0
   ▼ capable(mapped)  →  ML-KEM                       E0
   ▼ bound(static-import)  ← nginx                    E1
   ► path: "nginx could use ML-KEM"                   E1   (never "uses")
     loaded(nginx has libcrypto mapped)               E2   → "has loaded", still not "uses"
```

### 3.3 `policy` is a modifier, not a rung on the chain

Policy does not *strengthen* a path; it **changes what the path can mean**.

- `permits` — the path stays as computed; the policy fact is attached as its *reason*.
- `forbids` — the path is marked `effective = blocked`. It is **retained**, not deleted: "capable of ML-KEM,
  forbidden by policy" is a different (and useful) finding from "not capable".
- `unspecified` — defaults apply; recorded as `unspecified (defaults)`, **never as `none`**. (On the test
  machine `SCHANNEL\Protocols` exists and is empty: that is `unspecified`, not "no protocols".)

### 3.4 Outcomes: absence is not a fact

Every observation has an outcome:

| Outcome | Meaning |
|---|---|
| `observed` | the sensor saw it |
| `confirmed-absent` | the sensor looked authoritatively and it is not there (allowed **only** for methods declared `authoritative`; e.g. a complete package database read) |
| `unknown` + reason | the sensor **could not** see. Reasons: `permission`, `budget`, `unsupported`, `stubbed-source`, `error` |

`stubbed-source` exists because of a **measured** trap: Windows `Process.Modules` returns a one-entry stub for
protected processes without raising an error. A collector that records "1 module, no crypto" would be asserting
a negative it never earned. Any source known to be able to fail silently must be wrapped so that suspicious
results become `unknown(stubbed-source)`.

`unknown` **propagates**: any path containing an `unknown` edge is `incomplete`.

## 4. Two axes: claim × method quality

(Agent 1, A1; modified by Agent 2.)

| Axis | Question | Values |
|---|---|---|
| **Claim** | what does this assert? | §3 |
| **Method quality** | how reliably did the method establish it? | `authoritative` (a complete authoritative source parsed: dpkg status, rpmdb, the OS asked directly) · `parsed` (file/config parsed, format-stable) · `heuristic` (name/pattern match) · `sampled` (a runtime observation that may miss) |

**Method quality is declared once per collection method** (in the method registry, §5.2) and inherited by every
observation it makes. A fact may **override downward** with a stated reason (never upward). That keeps records
small and auditable while still handling the stub case.

**No numeric confidence is invented.** The literature uses High/Medium/Low or an uncalibrated 0–1
(`cbomkit-theia`). We have no calibration data (Agent 1 §11: no false-positive rate was found), and a number
would suggest precision we do not have. CycloneDX numeric `evidence.identity.methods.confidence` is emitted
**only** for `authoritative` methods (1.0, as the TLS builder already does for wire observations); other methods
omit it and carry the quality enum in a `cipherhorizon:method-quality` property (ADR-0002). If a method is
later calibrated, the number is added with its calibration source.

## 5. Records

Exact field definitions are in `collector-contract.md`. In this model:

### 5.1 Subject identity (what evidence is *about*)

Every subject has a **canonical key** so that the same thing seen by two methods becomes one node:

| Subject kind | Canonical key |
|---|---|
| package | Package URL (purl) |
| artefact (file) | `file:<normalised host-relative path>` (+ `#sha256:<hash>` when hashed) |
| certificate | `cert:sha256:<fingerprint of the DER certificate>` |
| public key | `key:pub:<cert fingerprint>` (cert-paired) |
| orphan private key | `keyfile:<path>` — **presence only** (SR-1); never a hash of contents |
| provider | `provider:<platform>:<name>` |
| algorithm | `algo:<catalogue ID>` (existing catalogue, incl. variants such as `AES-128-GCM`) |
| configuration | `config:<path>` |
| service | `service:<platform>:<name>` |
| process image | `image:<path>` — **never a PID** (volatile; would break determinism) |

Merging rule: same key ⇒ same node. Two observations of one node keep **both** (different methods), and the
node's displayed claim is the strongest **within the same claim kind**; observations are never averaged.

### 5.2 Methods

A **method** is a named, versioned way of sensing (`windows.certstore.enum@1`, `debian.dpkg.status@1`,
`windows.fs.walk@1`, `windows.cng.probe@1`). It declares: technique (mapped to CycloneDX's closed
`technique` list: `manifest-analysis` for package databases, `binary-analysis` for PE/ELF inspection,
`filename` for name matches, `instrumentation`/`dynamic-analysis` for runtime, `other` otherwise), quality,
minimum privilege, and **secret proximity** (`none` / `adjacent`), which drives extra review and tests (ADR-0005).

### 5.3 Coverage (blind spots are data)

Each collector also reports, per scope, what it **attempted** and what it **could not see**. Coverage is not a
log; it is part of the evidence and ends up in the CBOM (§8), so silence is never read as safety (Agent 1,
Recommendation 7; SR-11). Example: `windows.fs.walk` — `partial`, roots `Program Files, Program Files (x86)`,
depth 6, file budget hit = no; **unseen**: "statically linked applications", "per-user installs outside
`%LOCALAPPDATA%\Programs`".

## 6. The pipeline (the levels consume each other)

```
 SENSE (OS-specific)              NORMALISE            DERIVE (OS-agnostic)            PROJECT
 ───────────────────              ─────────            ───────────────────             ───────
 dpkg / registry / file walk  ─►  identity, dedupe ─►  knowledge + rules:          ─►  CBOM
 cert stores / CNG probe /        merge methods        capable(mapped), path             (deterministic)
 configs / imports / modules                            claim = min(edges),
                                                        policy effect, unknown→incomplete
        │                                                    ▲
        └── Observations ────────────────────────────────────┤  every derived fact lists BasedOn
            Coverage ────────────────────────────────────────┘  (validated: no derived fact without inputs)
```

Enforcement, not aspiration:

- A **derived fact without `BasedOn`** is invalid and fails the build's validation.
- A **relationship whose claim class exceeds the weakest class in its `BasedOn` closure** is invalid.
- **OS-specific code stops at Observations.** `derive` and `cbom` must not import platform packages (checked
  by a test; ADR-0004).

## 7. What is and is not host evidence

| Rung | Host collector produces it? |
|---|---|
| `present`, `provisioned`, `capable`, `policy`, `bound` | **Yes** (levels 1–5) |
| `loaded` | **Optionally**, separately privileged and separately reported (level 6) |
| `exercised` | **No.** Network handshakes are network evidence. A future host-log sensor would still be `sampled` and separate. |

**Ruling on Agent 1's open item** (local `exercised` evidence sits on the boundary): the stream is defined by
**who observed it**. A record made by a host collector is host evidence *even when it is about network
activity*; a record made by `tls scan` is network evidence. They are correlated only by an **Assessment** that
names both sources and the link between them (ADR-0006). The link itself is evidence (manual / certificate
match / address match) and caps the assessment's class.

## 8. CBOM projection rules

The CBOM is a **projection** of the evidence graph, not a store. It never contains anything the graph does not.
(Detailed mapping in `agent-03-architecture.md` §8.)

| Evidence | CycloneDX 1.6 |
|---|---|
| present (package) | `library`/`application` component with purl, `evidence.occurrences[].location` |
| present (loose artefact) | same, keyed by file; identity technique `binary-analysis`/`filename` |
| capable(mapped) | `provides` edge to the algorithm, plus `cipherhorizon:claim=capable-mapped`, KB citation (as today's `capability-basis`) |
| capable(probed) | property `cipherhorizon:claim=capable-probed` and method on the algorithm/provider component |
| provisioned | `certificate` + `related-crypto-material` public key (already produced by the TLS builder; reused) |
| policy | configuration as a `data` component (as the CycloneDX guide models `openssl.cnf`); `cipherhorizon:policy=permits|forbids|unspecified` |
| bound | `dependsOn` edge **plus** `cipherhorizon:claim=bound` and `cipherhorizon:binding-kind`. (CycloneDX's `dependsOn` means "uses"; ours may only mean "could use", so **the claim property is mandatory on every edge** and a consumer that ignores it is misled — see risk R1.) |
| loaded | `cipherhorizon:claim=loaded` on the edge |
| coverage / blind spots | `metadata.properties` (`cipherhorizon:coverage-*`) and a human-readable section |
| privilege used | `cipherhorizon:privilege` on each observation-derived component; a document-level summary |

The projection is **fail-closed**: an edge missing its claim property, or whose claim exceeds its evidence, is
a build error, not a warning.

## 9. What the model does not do

- It does not decide risk, priority or migration waves (governance, per Agent 1 §4).
- It does not invent confidence numbers (§4).
- It does not treat correlation as fact (§7).
- It does not attempt M-23-02 items 1–3 and 7–9, which are manual per CISA (Agent 1 §2.1).

## 10. Known risks in the model

| ID | Risk | Mitigation |
|---|---|---|
| R1 | CycloneDX consumers read `dependsOn` as "uses" and ignore our claim property | Mandatory claim property on every edge; also a document-level statement (as the TLS CBOM already does with `tls-graph`); consider a `cipherhorizon:` extension section |
| R2 | The partial order/strength classes are more machinery than the first customers need | The first level (L1) uses only `present` and `capable` with one class each; the rest exists so later levels cannot break the model |
| R3 | `unknown` overwhelms output on real estates | Coverage summarises by reason and scope; detail is on request |
| R4 | Method quality is a coarse enum and may be gamed by adding methods | Methods are registered, versioned and reviewed; adding one is a code change with a test |
