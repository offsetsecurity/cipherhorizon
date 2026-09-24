# Handoff 03 — Architecture → Implementation

```
FROM      Agent 3 (Security Architect)
TO        Agent 4 (Implementation Architect), then Agent 5 (Builder)
DATE      2026-09-24
FULL DOC  artifacts/agent-03-architecture.md, artifacts/evidence-model.md, artifacts/collector-contract.md,
          docs/decisions/ADR-0001 … ADR-0008
```

**Agent 4: before writing any code, challenge this. Look for unnecessary complexity, unsupported assumptions,
OS leakage, privilege problems, evidence inflation, false positives and poor CBOM modelling. If you change
something, send it back to Agent 3 conceptually and record the resolution in an ADR.**

## WHAT WE KNOW

- The regulatory object is *active* use; a host collector can produce **candidates and upper bounds**, and
  *loaded* evidence conditionally; **never** "used". (CISA/M-23-02.)
- Evidence must carry **claim** and **method quality** separately; a single confidence number cannot express
  "authoritative source, weak claim", and there is no data to calibrate one.
- CycloneDX `provides` means "does not imply in use"; `dependsOn` means "uses" — so our weaker claims must be
  labelled explicitly on the edge or a consumer will over-read them.
- On a real Windows machine (standard user): certificates, Schannel/GPO/FIPS policy, the CNG algorithm probe,
  loose-file crypto discovery, PE analysis and same-user module lists all work **without elevation**, and
  Windows has crypto that no package database lists.
- Two silent-failure traps exist and were measured: Windows `Process.Modules` **stubs** protected processes; Go's
  `debug/pe.ImportedLibraries()` **returns nothing** (use `ImportedSymbols()`).

## WHAT WE PROVED

- Windows: the items above, by test (Agent 2 §2, tagged `[T]`).
- The design's core rule (path claim = min of edge classes) is *stated and mechanically checkable*; it has **not**
  been implemented or exercised yet.
- **Nothing on Linux was run** by any agent.

## WHAT WE ASSUME

| # | Assumption | If wrong |
|---|---|---|
| B1 | A new `Sensor` interface with an adapter for the old one is safer than mutating `collector.Collector` | Adapter cost exceeds the benefit; evolve in place |
| B2 | Moving apt's capability rules into a knowledge base can reproduce today's `provides` edges exactly | Golden/compat test fails; the mapping needs the (family, version) key redesigned |
| B3 | The `x/sys` Windows wrappers plus a small `LazyDLL` layer are enough for L1 (registry read, file walk, PE, version info) | L1 needs fewer syscalls than L3; the risk grows at L3 (cert context properties, CNG) |
| B4 | Registry access can be done in pure Go via `golang.org/x/sys/windows/registry` | Otherwise a raw syscall wrapper |
| B5 | A bounded file walk with allow-listed roots is acceptable cost-wise | Budgets are configurable and reported |
| B6 | Fail-closed projection (error on over-claiming edge) will not block legitimate output | Reclassify the offending rule rather than downgrade the check |

## WHAT WE DON'T KNOW

- Performance of the file walk on large Windows estates.
- Whether golden CBOMs will need new properties beyond claim/method/coverage.
- How much of the `apt/rules.go` structure maps cleanly onto (family, version-range) knowledge entries.
- Any Linux behaviour on a live host.
- What customers want for redaction (SR-12).

## WHAT FAILED

Nothing in *this* stage failed, but it inherits: no Linux environment, Kali unreachable, Intune/SCCM details
not retrieved, `NCryptEnumKeys`/`Schannel via BCryptEnumContextFunctions` untested.

## WHAT NEEDS TO BE DONE

### Agent 4 (before code)

1. **Challenge** the contract and model (list above). Specifically test: is the partial-order + strength-class
   machinery justified for L1 which uses only `present` and `capable`? (My position: keep the *types*, use
   only what L1 needs.)
2. Decide `Sensor` vs evolving `Collector`; build-tag layout so all logic and fakes compile on every OS and only
   Windows syscalls are `//go:build windows`.
3. Decide the knowledge-base representation and how to prove **no change** to the existing Debian/Ubuntu
   components and `provides` edges (compat test).
4. Design the Windows L1 sensors: `windows.uninstall.registry@1`, `windows.fs.walk@1` (roots, depth, file
   budget, extension allow-list `.dll/.exe/.so`-style patterns for crypto families), `windows.pe.version@1`,
   authenticode status (API, not PowerShell).
5. Design the **method registry**, **contract validator**, **coverage** reporting and the fail-closed projection.
6. Write ADRs for anything changed.

### Agent 5 (Builder) — scope is L0 + L1 only

- L0: `internal/evidence` types, method registry, normaliser, validator, `Coverage`, host identity, fail-closed
  projection, canary-corpus harness, forbidden-import/symbol tests.
- L1: Debian/Ubuntu sensor refactor (dpkg → `present`, authoritative); Windows sensors above; knowledge/derive
  reproducing today's capability edges (L2-mapped).
- **Do not** implement: certificates (L3), policy (L4), bound (L5), runtime (L6), correlation (L7), Linux
  distros beyond Debian/Ubuntu, macOS (**not to be implemented**), persistent agent, installers.
- Keep `cipherhorizon run` flags/exit codes; new behaviour additive.

### Acceptance (what the Gatekeeper will test)

| Gate | Test |
|---|---|
| Existing output preserved | Components and `provides` edges for the Debian/Ubuntu fixtures unchanged; golden diffs reviewed |
| Claim discipline | No edge in the CBOM lacks a claim property; a deliberately over-claiming derived edge fails validation |
| Absence honesty | A stubbed source yields `unknown(stubbed-source)`, not a negative |
| Secrets | Canary corpus appears nowhere in outputs/logs |
| Determinism | Two runs, byte-identical |
| Windows ground truth | On the test machine, expected OpenSSL 3.5.7 / GnuTLS / NSS artefacts detected with PE version + signature status; **no false positive** from a decoy library-named file |
| Coverage | Budget-hit produces `partial` with reason |
| Wording | Release/README states Windows tested on one standard-user machine; Linux only as far as fixtures (or a provided host); macOS unsupported |

## WHY THE NEXT AGENT SHOULD CARE

The design rests on a few sharp rules that are cheap to get wrong in code and expensive to fix after users
depend on them: **claims may not exceed evidence**, **absence must be earned**, and **OS-specific code stops at
the observation**. Agent 4 is the last agent who can change those cheaply; after Agent 5 they become contract.

## CHALLENGES I EXPECT FROM AGENT 4 (welcome)

- "L0 is a lot of scaffolding before any user-visible change." — True; the alternative is repeating the
  current observation/derivation mixing in the first Windows collector, which is the defect this program
  exists to remove. Cut L0 to what L1 needs and *no more*.
- "Fail-closed will make real output flaky." — Then the rule is wrong or the input is; that is information,
  not a reason to downgrade the check.
- "Windows-first means Linux gets neglected." — The scope is deliberately limited to what has been *tested*;
  the design is platform-neutral and Linux distros are added as validated increments.

## OPEN DECISIONS ESCALATED TO THE USER

1. A reachable Linux/Kali test host.
2. Redaction policy for host/path data.
3. Confirmation of standard-user default.
4. Go-ahead to build L0 + L1.
