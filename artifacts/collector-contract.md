# Collector contract

```
OWNER    Agent 3 — Security Architect
STATUS   Proposed. Types below are a design sketch, not code in the repository.
BUILDS ON  artifacts/evidence-model.md   (read that first)
```

## 1. Goal

```
OS-specific collectors  ──►  common evidence model  ──►  normalisation  ──►  CBOM generator
       (sensors)               (Observation, Coverage)     (identity, dedupe)      (projection)
```

**Not:** a Windows script, a Linux script, and JSON of a different shape. A collector's *only* output is
`Batch`. Nothing OS-specific is allowed downstream of it.

## 2. What exists today, and what changes

Today (`internal/collector`): `Collector` has `Metadata`, `Detect`, `Collect() ([]CryptoAsset, error)` where
`CryptoAsset` **is already a CycloneDX component plus `provides`/`dependsOn`**. That shape is fine for a
package inventory, but it means the *collector itself* decides CBOM structure and puts capability edges in
at collection time (the apt rules do), which is exactly the mixing of observation and derivation this program
must stop. Kept: the registry, `Detect`, context/cancellation, read-only rule, `fs.FS` discipline, partial
results with an error. Changed: **what `Collect` returns.**

## 3. Types (sketch)

```go
// Package evidence: the normalised record. Platform-neutral. No cdx, no OS imports.

type Stream string        // "host" (this program) | "network" (tls scan, later)

type Rung string          // present provisioned capable policy bound loaded exercised
type CapableKind string   // probed | mapped
type Direction string     // permits | forbids | unspecified
type BindingKind string   // static-import | package-depends | service-config | dynamic-load-hint
type Outcome string       // observed | confirmed-absent | unknown

type Claim struct {
    Rung      Rung
    Capable   CapableKind // only when Rung == capable
    Direction Direction   // only when Rung == policy
    Binding   BindingKind // only on a bound relation
}

type Subject struct {
    Kind  string            // package artefact certificate publickey privatekey-ref provider algorithm config service image
    Key   string            // canonical key, see evidence-model §5.1
    Name  string
    Attrs map[string]string // ALLOW-LISTED per Kind (see §6); never free-form
}

type Relation struct {
    Kind  string            // e.g. holds, imports, depends, provides, configures, signed-by
    To    string            // Subject.Key
    Claim Claim
}

type UnknownReason struct { Code string /* permission budget unsupported stubbed-source error */; Detail string }

type Observation struct {
    ID        string        // sha256 of the canonical encoding of the fields below (deterministic)
    Stream    Stream
    Origin    string        // observed | derived  (knowledge is separate: KnowledgeRef)
    Subject   Subject
    Claim     Claim
    Outcome   Outcome
    Unknown   *UnknownReason // iff Outcome == unknown
    Relations []Relation
    Method    string        // "windows.certstore.enum@1" — must exist in the method registry
    QualityOverride *QualityOverride // downward only, with reason
    Source    Source        // where on the host (kind + normalised location)
    Privilege string        // tier actually used: user | admin | debug
    BasedOn   []string      // Observation IDs; REQUIRED and non-empty iff Origin == derived
    Knowledge *KnowledgeRef // {ID, Version, Citations}; required for capable/mapped
}

type Source struct { Kind string /* file registry api database procfs */; Location string }

type Method struct {            // declared once, in a registry
    ID, Version   string
    Technique     string        // maps to CycloneDX evidence technique (closed list)
    Quality       string        // authoritative | parsed | heuristic | sampled
    MinPrivilege  string
    SecretProximity string      // none | adjacent   (adjacent => extra review + canary tests)
}

type Coverage struct {          // what was attempted and what could not be seen
    Method   string
    Scope    string             // e.g. "windows certificate stores", "Program Files depth<=6"
    Status   string             // complete | partial | skipped | denied | failed
    Reason   string
    Limits   map[string]string  // budgets that applied: files, depth, bytes, elapsed
    Unseen   []string           // named blind spots for this scope
}

type Host struct {
    Name, ID string   // ID = salted hash of the platform machine id (raw id never emitted)
    OSFamily, OSVersion, Arch string
    CollectorVersion  string
    PrivilegeTier     string   // highest tier used in this run
    CollectedAt       time.Time // once per run; NOT per observation (determinism)
}

type Batch struct {
    Host         Host
    Observations []Observation
    Coverage     []Coverage
}
```

## 4. The collector interface

```go
type Sensor interface {
    Info() SensorInfo                            // name, version, source type, methods it uses
    Detect(ctx context.Context) (bool, error)    // unchanged semantics
    Collect(ctx context.Context) (Batch, error)  // partial Batch + error is valid: partial beats none
}
```

Rules for every sensor (each is a review-checklist item and, where marked ★, an automated test):

1. **Read-only.** ★ (package-level test: no write syscalls in sensor packages)
2. **Emit `Batch` only.** No CBOM, no CycloneDX types. ★ (import test: `internal/sense/**` must not import `internal/cbom`, `cyclonedx-go`, or `internal/derive`)
3. **Host access only through injected interfaces** (`fs.FS`, and small OS interfaces such as `CertStore`,
   `Registry`, `ProviderProbe`, `ProcessLister`), so every sensor is unit-testable with fakes and the
   platform layer is the *only* place that touches the OS. `fs.FS` discipline (paths unrooted, confined) is kept.
4. **No subprocess.** ★ (lint/test: `os/exec` forbidden in `internal/sense/**`). PowerShell is a test oracle
   only (ADR-0004).
5. **No secret reads.** ★ (a forbidden-symbol test on the syscall layer: `NCryptExportKey`, key-open for
   export, `os.ReadFile` on paths classified as private-key locations; plus the canary corpus, ADR-0005).
6. **Attributes are allow-listed** per subject kind (§6). Anything else is dropped and counted.
7. **Bounded.** Every walk/parse takes budgets (files, depth, bytes, time); hitting one yields
   `Coverage{Status: partial, Reason: budget}` and `unknown(budget)` where relevant — never silent truncation.
8. **Sources that can fail silently must be wrapped** and converted to `unknown(stubbed-source)` (evidence
   model §3.4).
9. **Deterministic.** Sorted output, normalised paths (forward slash, host-relative), no timestamps or PIDs in
   observations, stable IDs.
10. **Honest privilege.** Record the tier actually used; never silently degrade (if an elevated call is denied,
    `unknown(permission)`).

## 5. Stages after collection (OS-agnostic)

| Stage | Package (proposed) | Input → Output | Notes |
|---|---|---|---|
| Normalise | `internal/evidence/normalize` | `[]Batch` → graph | canonical keys, merge same-key nodes across methods, keep all observations, validate contract (§7) |
| Knowledge | `internal/knowledge` | versioned tables | today's `apt/rules.go` capability mappings move here, keyed by **(family, version range)** independent of how the artefact was found (Agent 2 §1.3-3) |
| Derive | `internal/derive` | graph + knowledge → graph | `capable(mapped)`, path claims, policy effects, `incomplete` propagation; every output carries `BasedOn` |
| Project | `internal/cbom` (extended) | graph → CycloneDX 1.6 | fail-closed rules (§7); reuses the existing certificate/key/algorithm builders from the TLS work |

## 6. Allow-listed attributes (illustrative; extended per level)

| Kind | Allowed attributes |
|---|---|
| package | name, version, arch, distro, family |
| artefact | path (normalised), size, `fileVersion`, `productName`, `signatureStatus` |
| certificate | sha256, notBefore, notAfter, keyAlgorithm, keyBits, curve, signatureAlgorithm, isCA, selfSigned, store, `hasPrivateKeyRef` (bool) |
| privatekey-ref | path, mode, `protection` (`encrypted`/`unencrypted`/`unknown`, **only** if the optional armor-label read is enabled) |
| provider | name, kind |
| config | path, directive→value **only for allow-listed directives with allow-listed value shapes** |
| service | name, imagePath, startType |

**Free-form strings from the host (subjects, names, paths) are attacker-controlled** and are carried as data,
never interpreted (SR-6). Configuration values that could be secrets (passwords, PSKs, paths to key files
embedded in directives) are never copied; only *presence* and the directive name.

## 7. Contract validation (runs in the normalise stage; failures are build/test errors)

| Rule | Why |
|---|---|
| Every `Observation.Method` exists in the registry | quality and technique come from the method |
| `Origin == derived` ⇒ `BasedOn` non-empty and every ID resolves | the pipeline rule |
| `Claim` fields are consistent with `Rung` (e.g. `Direction` only on `policy`) | no ambiguous claims |
| `Outcome == unknown` ⇒ `Unknown` set; `confirmed-absent` ⇒ method is `authoritative` | absence is earned |
| A relation's class ≤ min class of its `BasedOn` closure | evidence-model §3.2 |
| `QualityOverride` only lowers quality | no upward inflation |
| No attribute outside the allow-list | SR-1/SR-6 |
| `Batch` and every ID are byte-identical across repeated runs on unchanged input | SR-8 (golden tests) |

## 8. Example (one Windows artefact, then its derived fact)

```json
{
  "id": "obs:3f9c…",
  "stream": "host",
  "origin": "observed",
  "subject": { "kind": "artefact", "key": "file:program files/git/mingw64/bin/libcrypto-3-x64.dll",
               "name": "libcrypto-3-x64.dll",
               "attrs": { "fileVersion": "3.5.7", "productName": "The OpenSSL Toolkit", "signatureStatus": "NotSigned" } },
  "claim": { "rung": "present" },
  "outcome": "observed",
  "method": "windows.fs.walk@1",
  "source": { "kind": "file", "location": "program files/git/mingw64/bin/libcrypto-3-x64.dll" },
  "privilege": "user"
}
```

```json
{
  "id": "obs:a71e…",
  "origin": "derived",
  "subject": { "kind": "algorithm", "key": "algo:ML-KEM-768" },
  "claim": { "rung": "capable", "capable": "mapped" },
  "relations": [ { "kind": "provided-by", "to": "file:program files/git/mingw64/bin/libcrypto-3-x64.dll",
                   "claim": { "rung": "capable", "capable": "mapped" } } ],
  "basedOn": [ "obs:3f9c…" ],
  "knowledge": { "id": "openssl.pqc@1", "version": "2026-09",
                 "citations": [ "OpenSSL 3.5.0 CHANGES.md: ML-KEM, ML-DSA, SLH-DSA added in 3.5" ] }
}
```

Note what is *not* here: no statement that anything **uses** ML-KEM; that requires `bound` and a class-E1 path,
and even then only "could use".

## 9. Compatibility with the current tool

- The apt plugin becomes a `Sensor`: it emits `present` observations for packages (`debian.dpkg.status@1`,
  authoritative) and **no** capability edges. The capability mapping moves to `knowledge` + `derive`.
- **Guardrail:** `testing/golden/*.cbom.json` must not change *silently*. The projection is expected to *add*
  claim/method properties; every golden diff is reviewed line by line, and a compatibility test asserts that
  the *set of components and `provides` edges* for the existing Debian/Ubuntu fixtures is unchanged.
- `cipherhorizon run` flags and exit codes are unchanged. New behaviour is additive and off by default at the
  elevated tiers.

## 10. Open items for Agent 4 (Implementation Architect)

1. Is a separate `Sensor` type worth it, or is evolving `collector.Collector` in place lower risk? (Agent 3
   prefers a new interface with an adapter for the old one, to keep the diff reviewable.)
2. How the OS interfaces are packaged so Windows syscalls compile only under `//go:build windows` while the
   fakes and all logic compile everywhere (Linux CI runs the contract tests).
3. The size of the first knowledge/derive implementation: do the minimum that reproduces today's capability output.
4. Whether `x/sys` should become a direct dependency (it is already in the module graph as an indirect one).
