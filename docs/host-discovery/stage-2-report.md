# Windows collector, stage 2: native cryptography

**Scope (approved 2026-09-26):** ask Windows itself what cryptography it provides, instead of only reading files.
**Decision record:** [ADR-0013](../decisions/ADR-0013-native-windows-cryptography.md).
**Security review:** [stage-2-security-review.md](stage-2-security-review.md).

## What the collector now reports on a Windows host

| Layer | Source | Evidence |
|---|---|---|
| CNG algorithm registry | `BCryptEnumAlgorithms` (per operation class) | 51 identifiers on the development machine |
| CNG providers and who offers each algorithm | `BCryptEnumRegisteredProviders`, `BCryptEnumProviders` | 9 providers |
| Key storage providers | `NCryptEnumStorageProviders` (5 listed by name); the in-box software provider opened for its algorithms | 1 opened, 4 not |
| Legacy CSPs | `CryptEnumProvidersW` (name and type only) | 10 providers |
| Post-quantum parameter sets | `BCryptOpenAlgorithmProvider` and an ephemeral key handle | ML-KEM 512/768/1024 and ML-DSA 44/65/87 confirmed |

Every algorithm is attributed to the provider that offers it (`provides`, claim `capable-probed`), providers are
components with their kind, and the seven retired algorithms Windows still registers (MD2, MD4, MD5, SHA-1, RC4, DES,
3DES) carry a cited statement, separate from the quantum verdict. On this machine a run takes about 2.3 s in total.

## Evidence (this Windows 11 machine, standard user)

| Check | Result |
|---|---|
| Independent oracle for the native inventory (`compare-cng.ps1`: C# P/Invoke and `certutil -csplist`) | CNG/KSP names identical (9 = 9); legacy CSP names identical to certutil (10); every algorithm the oracle says a provider offers is named on it; **all 6 post-quantum parameter sets agree; 4 negative controls refused by Windows**; only the software key storage provider was opened; every legacy algorithm cites its source |
| File oracle (`compare-windows.ps1`) | unchanged: 22 agreed, 0 version mismatches, 0 false positives |
| Hash oracle (`compare-hashes.ps1`) | 22 of 22 agree |
| CycloneDX 1.6 schema validation of provider components | passes (pipeline tests with a fake live Windows) |
| Security tests | string reader, count cap, allow-list, PQC-only probing, hostile names, failure, stall, cancellation; **two mutation checks** each made two tests fail and were reverted |
| Whole suite, lint, vet | 430 tests pass (2 skipped, POSIX-only), 0 lint issues, vet clean on Windows and Linux; every release platform cross-compiles (the Windows layer is a stub elsewhere) |
| Browser journey and live security script | 60 of 60 and 33 of 33 |
| Release build | a GoReleaser snapshot of a tagged scratch copy builds all twelve archives; the collector archives are 1.7 to 1.9 MB; the **release-built** Windows collector lists all three sensors and produces the same 80 components as the development build |
| Architecture rules | stricter than before and passing (only two platform packages may touch Windows or `unsafe`) |

## Things found and fixed along the way

- The first design put the Windows calls in the sensor package; **the architecture test rejected it**. The code moved to
  its own platform package and the rule was extended, not weakened.
- A test asserting every catalogue algorithm has a post-quantum verdict failed on the new entries. The invariant stayed;
  an algorithm may now have no verdict only if the catalogue says why, and the test enforces that too.
- Probing a parameter set on an algorithm handle failed; the property can only be set on a key handle. That is why the
  probe generates an ephemeral key, which is documented, constrained and reviewed rather than hidden.
- Two citations were checked from primary sources before use (RFCs 6149, 6150, 6151, 6194, 7465, 3370; the NIST hash OID
  registry; FIPS 46-3; NIST's 2017 TDEA notice). Where NIST's SP 800-131A page did not state the 3DES position, it was not
  cited for it.

## Not validated

Windows Server, ARM64, Windows builds before 24H2 (no PQC, so probes answer "no"), an **elevated** run, and a machine with
third-party providers (HSM or smart-card middleware). Linux is unchanged and still unvalidated on a live host. The sensor
does not say what anything uses, what is enabled for TLS, or whether Windows is in a FIPS mode.
