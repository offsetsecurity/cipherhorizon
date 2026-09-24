# Agent 5 — Builder: Level 0 + Level 1

```
AGENT      5 — Builder
DATE       2026-09-24
INPUT      artifacts/agent-04-implementation-design.md (which resolved handoff-03), ADR-0001..0010
SCOPE      L0 (foundation) + L1 (present), with today's capability mapping re-expressed as L2-mapped derivation.
           Debian/Ubuntu (refactor of the existing collector) and Windows (new). Nothing else.
NOT DONE   By decision: certificates (L3), policy (L4), bound (L5), runtime (L6), correlation (L7), other Linux
           distros, macOS, installers, a persistent agent, Authenticode.
```

## What was built

| Package | Role | Notes |
|---|---|---|
| `internal/evidence` | the contract: `Observation`, `Claim`, `Coverage`, method registry, validator, `Graph`, strength classes (E0-E3), `Clean`/`SafeText`, `RedactPath` | imports no OS package and no CycloneDX (enforced) |
| `internal/knowledge` | family recognition (package names, file names) + cited capability tables + version parsing | the apt rules moved here unchanged; Windows file patterns added |
| `internal/derive` | applies knowledge to present artefacts: `capable (mapped)` facts, each naming its input and citation | requires `parsed` or better `present` evidence: a name match never qualifies |
| `internal/sense` | `Sensor` interface, registry, runner (timeouts, panic containment, coverage) | replaces `collector.Collector`/`scan` (ADR-0010) |
| `internal/sense/debian` | dpkg sensor (name kept as `apt`) | packages -> `present`, authoritative |
| `internal/sense/pefiles` | Windows loose-library sensor + a hand-written, bounds-checked, fuzzed PE version-resource reader | **zero hand-written syscalls** |
| `internal/hostinfo` | host identity, privilege tier, OS version, machine-id label (build-tagged) | the only package that imports `x/sys` |
| `internal/discover` | orchestrates sensors -> graph -> derive; the privilege note | |
| `internal/cbom` (`hostbuild.go`) | fail-closed projection of the graph to CycloneDX 1.6 | reuses `Build`, sanitisation, PQC annotation |
| `internal/archtest` | import rules as tests | negative control verified |
| `internal/app`, `internal/config` | `run` rewired; `--redact-host`; privilege warning; Windows default root | flags and exit codes unchanged, additive |

Removed (replaced): `internal/scan`, `internal/plugins/*`, `collector.Collector`/registry/`PluginInfo`, `collectortest`.
`docs/writing-a-plugin.md` became `docs/writing-a-sensor.md`.

## Numbers

322 top-level Go tests pass, 0 fail, 0 skip; `golangci-lint` 0 issues; `go vet` clean on windows and linux; 44/44
browser-journey steps pass; PE parser fuzzed 2.8 M executions without a crash; ~4,700 lines of new production and
test code across the new packages.

## Where I deviated from the plan, and why

1. **CycloneDX 1.6 requires a numeric `confidence` on every identity method.** ADR-0002 said numeric confidence only
   for authoritative methods. The schema check failed the first Windows projection. Resolution: the identity block is
   written only for authoritative methods (packages); loose-file findings carry technique and quality in
   `cipherhorizon:method` / `method-quality`. ADR-0002 updated.
2. **Citation order.** My first projection sorted the citations; the frozen legacy output kept table order. The
   compat test caught it; fixed to preserve table order.
3. **Package names.** `Version` clashed twice (a constant and a type); renamed `KBVersion` and `VersionInfo`.
4. **Recognition patterns changed after ground truth** (Agent 7 backtrack): `openssl.exe` and MSYS-style
   `msys-gnutls/nettle/hogweed/gcrypt` names added; `libgnutls_plugin.dll` deliberately still excluded.
5. **`host-id` is emitted only with `--redact-host`** (Agent 6 finding), not by default.

## Traps hit while building (recorded for whoever builds L2+)

- Go's `debug/pe.File.ImportedLibraries()` returns nothing on PE; `ImportedSymbols()` works. (Not needed at L1;
  needed at L5.)
- `os.DirFS("/")` on Windows is the *current drive's* root, so the default root is now the system drive.
- `fs.WalkDir` does not follow symlinks; junctions must be treated as irregular entries; both are skipped.
- `fstest.MapFS` may not list a directory whose name is invalid UTF-8, so tests of hostile names cannot count on all
  of them being seen.
- The shell tool mangled several quoted heredocs; patches were written as files instead (tooling, not product).

## Known limitations of what was built

- The capability mapping is by **family**: every file of the OpenSSL family (including `libssl-3-x64.dll`, which
  does not itself implement the primitives) is credited with the family's capability. Per-file mapping is an L2
  refinement. This matches what the Debian output already did for `libssl3`.
- File versions are **what the file claims**. `nss3.dll` inside Firefox reports Firefox's version (156.0.1.575).
  The CBOM now says so (`cipherhorizon:version-source = file-version-resource`).
- Recognition is by name. Real crypto artefacts with unrecognised names are not found (see the test report).
- A run as Administrator was **not measured** (this session has no elevation).
- **Linux was not run on any Linux host.** Only fixtures.

## Handoff

To Agent 6 (security review): `internal/sense/pefiles/*`, `internal/evidence/validate.go`, `internal/hostinfo/*`,
`internal/discover`, `internal/cbom/hostbuild.go`. To Agent 7: `testing/hostdiscovery/*`. See the next artefacts.
