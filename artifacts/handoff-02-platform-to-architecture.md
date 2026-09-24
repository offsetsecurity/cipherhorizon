# Handoff 02 — Platform Research → Security Architecture

```
FROM      Agent 2 (OS / Platform Researcher)
TO        Agent 3 (Security Architect)
DATE      2026-09-24
FULL DOC  artifacts/agent-02-platform-research.md   (inputs: agent-01 + handoff-01)
```

**Agent 3: you receive two packages — Agent 1's requirements and my platform findings — and I changed some of
Agent 1's premises. Read §1 of my document first. You are expected to challenge both.**

## WHAT WE KNOW

**Tested on one Windows 11 machine as a standard, non-elevated user** (all tagged `[T]` in the full document):

- **Certificates**: 6 stores enumerate unelevated; algorithm and key size are available; `HasPrivateKey` is a
  presence flag; no key was opened. The store holds **4 × RSA-1024 roots and 1 × RSA-512 intermediate** —
  directly useful evidence found without touching a key.
- **Policy**: Schannel effective cipher suites (28, all classical) and ECC curves (`curve25519, NistP256,
  NistP384`, no hybrid) are readable; the override key `Protocols` exists but is **empty** (defaults);
  FIPS = 0.
- **Capability, probed from the OS**: CNG opens `ML-KEM` and `ML-DSA` providers and enumerates 41 algorithms
  including legacy `RC4/MD2/DES`.
- **Bundled crypto is invisible to package databases**: 31 uninstall entries, none crypto; but a bounded file
  walk found **OpenSSL 3.5.7, GnuTLS, NSS** as loose DLLs; version read from PE resources without loading;
  `NotSigned`.
- **Static linkage**: readable in pure Go **only** through `debug/pe.File.ImportedSymbols()`;
  `ImportedLibraries()` returns 0 on PE.
- **Static linkage misses dynamic loading**: `firefox.exe` imports no crypto DLL yet `nss3.dll` is loaded in
  ≥7 Firefox processes.
- **Runtime trap**: `Process.Modules` returns a **1-entry stub, not an error** for protected processes
  (`System, lsass, csrss, services, svchost, MsMpEng`). Reading that as "no crypto loaded" would be a false
  negative.
- **Pure-Go reach** (verified in the module cache): `golang.org/x/sys/windows` wraps store open/enumerate but
  **not** `CertGetCertificateContextProperty` nor anything in `bcrypt`/`ncrypt`; those need our own
  `LazyDLL` bindings.

## WHAT WE PROVED (by test, not by reading)

1. The OS-capable ≠ TLS-stack-offered gap exists on a real machine: CNG supports ML-KEM/ML-DSA; Schannel offers
   only classical suites and curves.
2. The ImportedLibraries() vs ImportedSymbols() behaviour on PE.
3. The stub-module false-negative for protected processes.
4. Certificate metadata can be enumerated without opening any key.

## WHAT WE ASSUME

| # | Assumption | Consequence if wrong |
|---|---|---|
| P1 | The test machine is a fair *standard-user* Windows endpoint | Domain/GPO-managed and Server SKUs will show overrides, FIPS on, different providers |
| P2 | Linux mechanisms in the full document are correct as documented | **No Linux mechanism was executed.** Every Linux cell is `ʳ` (researched) or `ᶜ` (fixtures only) |
| P3 | A pure-Go RPM reader can cover RHEL-family and Amazon Linux | SUSE's NDB backend is unverified |
| P4 | CI containers can stand in for hosts for package/config evidence | Not for `/proc/sys/crypto/fips_enabled` or runtime evidence — kernel-shared |
| P5 | Windows probes done in PowerShell have in-process API equivalents | Untested for `BCryptEnumContextFunctions` (Schannel effective config) and CNG key properties |

## WHAT WE DON'T KNOW

- Anything about real Linux hosts from this session (Kali is not reachable; no WSL/Docker).
- `NCryptEnumKeys`/`NCryptGetProperty` behaviour for a standard user.
- Whether NDB (SUSE) is readable by an available pure-Go library.
- Windows Server, domain-joined, Core, ARM64 behaviour.
- Cost/stability at scale (only a rough single-host timing).
- macOS: everything (`?`), by design.

## WHAT FAILED

- No Linux environment available; the Linux half is unvalidated.
- `Get-Tpm` empty unelevated.
- My first PE probe used the wrong stdlib call and reported zero imports (corrected).
- Intune/SCCM packaging details were not retrieved.

## WHAT NEEDS TO BE DONE

1. Decide the **evidence model** (`artifacts/evidence-model.md`) incorporating: partial-order ladder; two kinds
   of `capable`; `policy` with direction and `unspecified`; `bound` as a typed-edge graph; `unknown(reason)` as
   a first-class outcome; method quality declared per collection method with per-fact override.
2. Decide the **collector contract** (`artifacts/collector-contract.md`): a normalized observation record;
   OS-specific collectors **must not** emit CBOM directly.
3. Decide **levels and order** (the brief's seven are a hypothesis): my evidence suggests **`provisioned`
   (certificates) is the cheapest high-value host evidence on Windows and is directly the CISA item-4 data**,
   while **Linux `policy` is strong only on RHEL-family/AL2023/SLE 15 SP4+**. The level cut should not assume
   one order for all platforms.
4. Decide **privilege tiers**: standard-user default and complete-in-itself; elevated evidence separately
   reported.
5. Rule on the **host vs network boundary** for local `exercised` evidence (Agent 1 left it open).
6. Decide the **distribution model**: my research points to *signed standalone collector + native packages*,
   persistent agent as a separate later decision. Authenticode/`.deb`/`.rpm`/repo signing are **not built**;
   cosign/SLSA/SBOM for archives **are**.
7. Tell Agent 4/7 what is **tested vs researched** so the Level 1 claim is worded correctly.

## WHY THE NEXT AGENT SHOULD CARE

The architecture's value is that each level *strengthens* the previous one. Three things I found would silently
break that if the schema ignored them:

- **Absence is not evidence** when the observer is blind (the module stub, static-import gaps): the model needs
  `unknown(reason)`, or the CBOM will assert negatives the collector never earned.
- **Capability is not exposure** (CNG vs Schannel): a single "capable" label would mark this Windows box as
  PQC-ready when its TLS stack is not.
- **Where evidence comes from changes what it means**: OpenSSL 3.5.7 found as a loose DLL is the same
  *capability* as a package, but a different *method* — the model must separate them.

## SECURITY POINTS FOR THE ARCHITECT (Agent 1's SR list, as they apply)

- The hand-written syscall layer is the one place a key-export call could be introduced; constrain by
  design (narrow wrapper set) **and** by test.
- Config parsing must be **allow-list based** on directive names and values; never echo raw config text.
- A **canary-secret corpus** should be a gate.
- Avoid PowerShell/subprocess at runtime; PowerShell is useful only as a **test oracle** for the Go collector.

## CHALLENGES I EXPECT FROM AGENT 3 (welcome)

- "Partial order is over-engineered; pick one order." — Counter: the same document shows `policy`-first on
  RHEL/AL2023 and `provisioned`-first on Windows. A single order forces a wrong claim somewhere.
- "Probed vs mapped capability is a distinction without a customer." — Counter: it is the difference between
  "this OS can" and "this OS's *documentation* says a library can"; different failure modes.
- "Give me one confidence number." — Counter: see A1; a number cannot carry the stub trap.
