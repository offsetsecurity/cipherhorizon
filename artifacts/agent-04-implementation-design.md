# Agent 4 — Implementation Architect

```
AGENT      4 — Implementation Architect
DATE       2026-09-24
OBJECTIVE  Challenge the architecture before any code exists; resolve it against the real code base; design
           the smallest correct implementation of L0 + L1.
INPUT      handoff-03 + agent-03, evidence-model, collector-contract, ADR-0001..0008;
           the current code (internal/collector, scan, plugins/apt, app, config, cbom);
           the user's answers (§1).
OUTPUT     this document; ADR-0009 (privilege disclosure + redaction), ADR-0010 (Sensor replaces Collector);
           the build plan Agent 5 implements.
```

## 1. The user's four answers, and what each does to the plan

| # | User answer | Consequence |
|---|---|---|
| 1 | "Can you use WSL for Linux testing." | **WSL is not installed here** (`wsl --status`: not installed). This session is a **standard user, not in the Administrators group**; `wsl --install` enables Windows features and needs elevation and usually a reboot, i.e. a change to system settings that I will not attempt. **Action for the user:** run `wsl --install -d Debian` once in an *elevated* terminal and reboot (hypervisor is already present on this machine, so WSL 2 should work; virtualisation shows as active). Until then Linux stays **fixtures-only**. I prepare a ready-to-run lab script (`testing/hostdiscovery/lab-debian.sh`) so the first WSL session can validate immediately. |
| 2 | "Decide on best way" (redaction) | Decided: **ADR-0009** — minimise by default, no policy engine. |
| 3 | "Should give a warning for full result, elevated privileges might be needed." | Accepted as a **requirement**, ADR-0009: a visible warning whenever the run is below the highest privilege tier, plus a machine-readable record in the CBOM. It states *what* was unreadable when the run can tell. |
| 4 | "Go ahead … make it now." | Agent 4 (this document) → Agent 5 builds **L0 + L1** → review → tests → CBOM review → gate. |

## 2. Challenge to the architecture (Agent 3)

| Agent 3 position | Verdict | Reason / change |
|---|---|---|
| Keep the *types* for the whole claim model, use only `present` + `capable` in L1 | **Accept** | Cheap in a type system; the validator is the real content and it is small. |
| A new `Sensor` interface **with an adapter** for the old `collector.Collector` (Agent 3's preference) | **Reject the adapter; replace the interface** (ADR-0010) | The only production collector is apt. An adapter must convert `CryptoAsset` (a finished CycloneDX component with inference baked in) back into observations — lossy by construction and it would keep alive the very interface that fuses observation and derivation. Deleting `scan`, the registry and `plugins/apt` (≈1,500 lines incl. tests) is cheaper than maintaining two paths, and the compatibility test (§7) protects the output. |
| Windows L1 = uninstall registry + file walk + PE version + Authenticode | **Cut to file walk + a pure-Go PE version-resource parser** | (a) Uninstall registry: **0 of 31 entries were crypto-relevant** on the test machine; low signal, adds a registry dependency. (b) **Authenticode is cut on a security finding:** `WinVerifyTrust` performs certificate **revocation checks that can reach the network** by default — that violates SR-7 (no network during collection) and needs hand-written syscalls. It may return later as an offline-only method proven by test. (c) Everything else is doable with **no hand-written syscalls at all**: the PE resource parser is ordinary bounded Go over an `fs.FS`, so it is also **testable on Linux CI** with synthetic PE fixtures. Net: **L1 contains zero `LazyDLL` code**; the highest-risk layer Agent 3 flagged is deferred to L3 where it is needed. |
| Own PE resource parser | **Accept, with fuzzing** | New parser of hostile input is itself a risk (SR-5/SR-6): bounded reads, no allocation sized from the file, fuzz test. |
| Knowledge keyed by (family, version) | **Accept**; family *recognition by name* is also knowledge | Recognition is a **heuristic** (a filename or package name); therefore a file-found artefact is `present` at *heuristic* quality until a **parsed** method (PE version resource) corroborates it. |
| Capability derivation for any recognised artefact | **Change: derivation requires evidence of at least `parsed` quality** | Uses the method-quality axis as a real gate: a file named `libcrypto-3-x64.dll` that is not a valid PE (a decoy) is *listed as present (heuristic)* but is **never** claimed `capable`. This is the false-positive control the acceptance table demands. Package rows stay `authoritative`. |
| Fail-closed projection | **Accept** | Implemented as a validator over the graph before projection; a violation is an error, not a dropped edge. |
| Salted host ID from machine id | **Accept** | Linux `/etc/machine-id` via the FS; Windows `MachineGuid` via `x/sys/windows/registry` (a single read of a standard-user-readable value; a wrapper that already exists). |
| Coverage in CBOM `metadata.properties` | **Accept** | Plain namespaced properties; one summary property per collector run. |

### New findings from the code

1. `config.Host.Root` defaults to `"/"`. On Windows `os.DirFS("/")` is the **current drive root**, so a Windows run
   silently depends on the working directory's drive. Fix: default root by OS (`C:\` from `%SystemDrive%`).
2. `pluginsCmd` builds every plugin with `os.DirFS("/")` just to list metadata — replaced by static sensor info.
3. `scan.Run` already contains panic containment, per-plugin timeout and Partial/Failed/Skipped semantics; these are
   **kept** (moved into `sense.Run`) because they are exactly the honest-failure behaviour the model needs.
4. The apt collector's `provides` edges and the `evidence=installed-package-capability` property are consumed by the
   host page (`internal/server/ingest.go`) and documented; they must not disappear. Kept by the projection.
5. `internal/collector` also owns `CryptoAsset`, which `cbom.Build` and the TLS builder use: **it stays**; only the
   `Collector` interface, registry, `PluginInfo`/`SourceType` and `collectortest` go.

## 3. Package layout (all logic compiles and tests on every OS)

```
internal/evidence      types, method registry, contract validator, graph/normalise, strength classes, path composition
internal/knowledge     families: package/file recognition, versions, capability mappings with citations
internal/derive        capable(mapped) derivation over the graph
internal/hostinfo      Host identity + privilege tier (build-tagged: windows / other), path redaction
internal/sense         Sensor interface, registry, runner (timeout, panic containment, coverage)
internal/sense/debian  dpkg sensor (moved from plugins/apt): packages -> `present`, authoritative
internal/sense/pefiles bounded file-walk sensor + PE version-resource parser (pure Go)
internal/cbom          FromHostGraph: graph -> []collector.CryptoAsset (reuses Build, sanitize, PQC annotation)
internal/app           `run` rewired; warnings; `plugins` lists sensors
```

Import rules **enforced by test** (`internal/evidence/archtest`): `evidence`, `knowledge`, `derive` import no
platform package and no CycloneDX; `sense/**` imports neither `cbom` nor `derive` nor `os/exec` nor `net`;
only `hostinfo` (build-tagged) imports `golang.org/x/sys/windows`.

## 4. L0 scope (only what L1 needs)

- `evidence`: `Observation`, `Subject`, `Claim`, `Relation`, `Outcome`, `Coverage`, `Host`, `Batch`;
  method registry with `debian.dpkg.status@1`, `fs.walk.filename@1`, `pe.version-info@1`, `knowledge.mapping@1`;
  `Validate(batch)`; canonical IDs (content hash); `Graph` merge by subject key; `Class`/`MinClass`/`Wording`;
  `CheckDerived` (BasedOn resolves, class ≤ weakest input).
- `Coverage` and `UnknownReason` produced by sensors and runner; rendered into the CBOM.
- **Not in L0:** probed capability, policy modifier engine, path-composition beyond the check, redaction policy engine,
  assessment records, upload.

## 5. L1 scope

1. **Debian/Ubuntu sensor** (`apt`, name kept for config compatibility): read dpkg status → for recognised crypto
   packages emit `present` (authoritative) with allow-listed attributes (name, version, arch, distro, family, kind);
   `Coverage{complete|partial}`; `Unseen`: statically linked and language-runtime crypto, bundled libraries.
2. **Windows/PE sensor** (`pe-files`): allow-listed roots (`Program Files`, `Program Files (x86)`, `ProgramData`,
   `Users/*/AppData/Local/Programs`), depth ≤ 8, entries ≤ 500 000, time via ctx; **read a file only if its name
   matches a recognised family pattern** and size ≤ 256 MiB; emit `present` (heuristic, by name) and, if the PE
   version resource parses, a second `present` observation by `pe.version-info@1` (parsed) carrying `fileVersion`,
   `productName`. Permission-denied directories are counted into Coverage as `unknown(permission)`.
3. **Derivation** (`capable`, mapped): for each node with an *authoritative-or-parsed* `present` and a family with
   a mapping, emit one derived observation per algorithm: `BasedOn` = that present observation, `Knowledge`
   = {family mapping ID, citations}. Version-gated capabilities need a parseable version (else omitted, never assumed) —
   today's rule, kept.
4. **Projection**: package/artefact → `library`/`application` component; capable → `provides` + existing
   `capability-basis`/`evidence=installed-package-capability` properties + `cipherhorizon:claim`,
   `cipherhorizon:method`, `cipherhorizon:method-quality`; coverage and privilege in `metadata.properties`.
5. **Warnings** (ADR-0009): non-elevated run ⇒ stderr warning + `cipherhorizon:privilege-tier` + coverage note.
6. **Redaction** (ADR-0009): user-profile path tokenisation always on; `host.redact`/`--redact-host` for the name.

## 6. Security design decisions (delta over Agent 3)

| Item | Decision |
|---|---|
| SR-1 | The file walker reads **only** files whose *names* match recognised crypto-library patterns; never opens `*.pfx`, `*.pem`, `*.key`, or anything else; PE parsing reads only headers/resource directory bytes it needs. The canary corpus (keys/passwords named plausibly, e.g. `libcrypto.key`, `id_rsa`) must produce **no read**. Verified by a test using an `fs.FS` that fails the test if a non-allow-listed file is opened. |
| SR-4/7 | `os/exec` and `net` forbidden in `sense/**` (arch test). No Authenticode in L1 (revocation network I/O). |
| SR-5 | `fs.WalkDir` does not follow symlinks; junctions are not descended; budgets; per-file size cap; reads via `io.LimitedReader`. |
| PE parser | Bounds-checked offsets; recursion depth ≤ 3 (type/name/language); at most 4 KiB of version block strings copied; fuzz test. |
| Determinism | Sorted walk; no PIDs/timestamps in observations; collection time recorded once, in the CBOM timestamp as today. |

## 7. Acceptance for L0 + L1 (what Agents 6–9 will verify)

1. **Compatibility:** for the Debian 13 and Ubuntu 24.04 fixtures, the *set of components and `provides` edges* is
   identical to the pre-refactor golden; every other golden diff is additive and reviewed line by line.
2. **Claim discipline:** an over-claiming derived edge, or a derived fact without `BasedOn`, fails validation.
3. **No decoy false positive:** a non-PE file named `libcrypto-3-x64.dll` is `present (heuristic)` and never `capable`.
4. **No secret reads:** the allow-list FS test passes; canary names are never opened.
5. **Honest coverage:** budget hit ⇒ `partial` + reason; denied directory ⇒ `unknown(permission)` counted.
6. **Privilege warning** appears when not elevated and names the effect.
7. **Determinism:** byte-identical repeat runs.
8. **Ground truth on this machine (Windows, standard user):** expected artefacts (OpenSSL 3.5.7 under Git, NSS under
   Firefox) found with correct versions, cross-checked against an independent oracle (PowerShell `VersionInfo`).
9. **Linux:** only fixtures (and WSL Debian *if installed*); wording says so.

## 8. Risks I am accepting

| Risk | Note |
|---|---|
| Deleting the old collector path breaks something I did not read | Whole test suite + 44-step E2E + goldens run after; compat test is the guard |
| PE parser bugs on odd binaries (packed, .NET, ARM) | Treated as `present (heuristic)`, version unknown, no capability; fuzz; never panics (recover in runner) |
| Walk cost on a big `Program Files` | Budgets are reported as Coverage; measured in Agent 7's tests |
| L0 grows beyond L1's needs | Anything not listed in §4 is out of scope |

## 9. Handoff to Agent 5

Build §3–§5 in this order, running the full suite after each step: (1) `evidence` + validator + tests;
(2) `knowledge` (move rules + version) with the *existing apt rule tests ported*; (3) `sense` runner + `debian`
sensor + `derive` + `FromHostGraph`, rewire `run`, prove the compat test; (4) `hostinfo` + warnings +
redaction; (5) `pefiles` + PE parser + fuzz; (6) docs (`writing-a-plugin.md` → sensors), CHANGELOG, arch test.
