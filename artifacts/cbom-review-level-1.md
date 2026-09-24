# CBOM / evidence review — Level 1

```
AGENT      8 — Evidence / CBOM Reviewer
DATE       2026-09-24
QUESTION   Does the CBOM faithfully represent what the collector actually knows?  Is
           installed != capable != configured != associated != running != used preserved?
INPUT      the real Windows CBOM produced on this machine (22 software components, 27 algorithm components),
           the Debian 13 / Ubuntu 24.04 goldens, artifacts/evidence-model.md
```

## 1. Schema

| Check | Result |
|---|---|
| Real Windows CBOM (default and `--redact-host`) against the vendored CycloneDX 1.6 JSON schema | **valid** |
| Goldens and every test CBOM | valid (`schematest.Validate` runs in the suite) |
| Deterministic bytes | two runs identical (test) |
| Vocabulary | unchanged closed sets; `related-crypto-material` support from the earlier TLS work is untouched |
| One schema constraint found while building | CycloneDX 1.6 **requires** a numeric `confidence` on every `evidence.identity` method. We have none we can honestly give except for authoritative methods, so the identity block is written for those only; the rest is in `cipherhorizon:method` / `method-quality`. Documented in ADR-0002. |

## 2. The evidence audit (programmatic, on the real CBOM)

| Property checked | Result |
|---|---|
| Every software component says `claim = present` | 22 / 22 |
| `dependsOn` ("uses") edges anywhere in the document | **0** (L1 has no `bound` evidence and emits none) |
| Every component with `provides` edges carries `provides-claim = capable-mapped` | yes, and no component carries the label without edges |
| Every capability is cited (`capability-basis`) | yes |
| Capability granted on `heuristic` evidence (a name match) | **0** (decoy control) |
| Component versions without a stated source | **0** (`version-source`) |
| Quality mix | 22 x `parsed` (all loose files); packages are `authoritative` in the Debian goldens |
| Document states privilege, coverage and blind spots | tier `user`, 1 coverage record (`partial`, `permission`, `denied=129`), 6 `not-seen` items, the coverage note |

**Words.** Nothing in the output says "uses", "supports" or "is using". The vocabulary is *present*, *can provide
(mapped)*, *not seen*. This matches the permitted wording for class E0 (`evidence-model` §3.2).

## 3. The chain, checked link by link

| Link | Preserved? | How |
|---|---|---|
| installed != capable | **yes** | presence and capability are different properties from different methods; capability lives only on `provides` edges and is labelled `capable-mapped` with citations |
| capable != configured | **yes (by absence)** | no policy is collected at L1, so nothing claims configuration; `not-seen` says configuration is not collected |
| configured != associated | n/a | not collected (L4/L5) |
| associated != running | n/a | not collected (L5/L6) |
| running != used | **yes** | the host collector never claims `exercised` (`Validate` rejects it); the CBOM says a present file "says nothing about use" |

## 4. Findings

### C1 — Family-level capability over-credits which file  (LOW) — accepted, documented
`libssl-3-x64.dll` is credited with OpenSSL's algorithms though the primitives are in `libcrypto`. It is a statement
about the family, applied per file, and matches the Debian output (`libssl3`). **Recommendation:** per-file mapping at
L2 (a knowledge entry saying which artefact implements which algorithm class).

### C2 — A version can mislead  (MEDIUM) — fixed (labelled)
`nss3.dll` shows version `156.0.1.575` (Firefox's), `product-name: Firefox`. Consumers might read it as NSS's version.
Now every version carries `version-source`. NSS has no capability mapping, so nothing was over-credited; for a
version-gated family (OpenSSL >= 3.5) the credit rests on the file's own claim, which the CBOM now says.

### C3 — The privilege note is a property, not a status  (LOW) — accepted
A consumer must read `cipherhorizon:coverage-note`/`coverage` to learn the run was partial; the CycloneDX document
has no native "incomplete" flag. It is present, stated in words, and mirrored in the CLI warning.

### C4 — `cipherhorizon:evidence = installed-package-capability` is a legacy name  (LOW) — kept for compatibility
The property predates the pipeline; it now appears only alongside `provides-claim`. Kept because the frozen legacy
output and the host page rely on it (compat test); new files use `file-capability`.

### C5 — Real gaps are invisible in the CBOM  (MEDIUM, honesty) — partly addressed
Five real crypto artefacts on the test machine are unrecognised (`legacy.dll`, `SSLeay.dll`, `cryptocme2.dll`,
`VBoxLibSsh.dll`, `msys-hcrypto-4.dll`). The CBOM's `not-seen` list says "libraries whose file name is not a
recognised crypto-library name (renamed or unrecognised)", so the limit is stated, but a reader cannot tell *which*
are missing. That is inherent to a name-recognition method; it is stated, not hidden.

## 5. What would make me fail it

Any of: a `dependsOn` edge without a claim; capability on `heuristic` evidence; a claim of use; a version without
provenance; an over-claiming derived edge accepted by the graph; a document that omits its coverage. None occurred;
each has an automated test (`TestGraphRejectsOverClaimingDerivedFact`, `TestDecoyIsInventoriedButNeverCapable`,
`TestCurrentOutputCarriesClaimsAndCoverage`, `TestLegacyOutputIsPreserved`).

## 6. Verdict

**The CBOM does not state more than the collector knows.** Level 1's claims are E0 (existence): present, and
capable-by-citation. Correct wording for any report built on it: *"OpenSSL 3.5.7 is present on this machine; a
library of that version can perform ML-KEM. Nothing here says anything on this machine uses it."*
