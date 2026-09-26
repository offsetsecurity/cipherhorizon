# Stage 2 security review: `internal/winapi` and the `windows-cng` sensor

**Role:** security reviewer. **Scope:** the first hand-written Windows API layer in the collector
(`internal/winapi/api_windows.go`), the sensor above it, and what they may load or do. **Method:** read every function
against the rules of ADR-0004, ADR-0005 and ADR-0013; test the properties with hostile inputs and mutation checks; compare
against independent implementations. Written before the stage gate; findings are fixed or accepted below.

## The rules the layer must keep

1. No subprocess, no network. *(Enforced by `internal/archtest`: `winapi` may not import `os/exec`, `net`, `net/http`,
   `net/rpc` or any other package of this module.)*
2. Nothing opens a key, a certificate or a secret, and nothing enumerates key or certificate material.
3. A provider is loaded only when the caller asks for that one provider, and the sensor asks only for the allow-list.
4. Everything the OS returns is bounded and validated before use; a hostile or corrupt registration cannot enlarge,
   crash or poison a run.
5. A stalled provider cannot stall the run.

## Function by function

| Function | What it calls | Ownership and bounds | Loads code? | Verdict |
|---|---|---|---|---|
| `Algorithms` | `BCryptEnumAlgorithms` | OS-allocated list, freed with `BCryptFreeBuffer` on every path (deferred); count capped at `MaxEntries` **before** it sizes the slice; each name read by `readString` | no (registry) | ok |
| `AlgorithmProviders` | `BCryptEnumProviders` | same pattern | no | ok |
| `RegisteredProviders` | `BCryptEnumRegisteredProviders` | header struct then a capped slice of string pointers; freed once | no | ok |
| `StorageProviders` | `NCryptEnumStorageProviders` | freed with `NCryptFreeBuffer`; name and comment via `readString` (a bad comment is omitted, a bad name skips the entry) | no | ok |
| `StorageProviderAlgorithms` | `NCryptOpenStorageProvider`, `NCryptEnumAlgorithms`, `NCryptFreeObject` | handle released by defer; list freed | **yes, one provider** | ok, gated by the sensor's allow-list and a test |
| `CSPs` | `CryptEnumProvidersW` (size query, then bounded buffer) | buffer size checked against `MaxName*2+2`; loop capped at `MaxEntries` | no (registry) | ok |
| `Probe` | `BCryptOpenAlgorithmProvider`, `BCryptGenerateKeyPair`, `BCryptSetProperty`, `BCryptFinalizeKeyPair`, `BCryptDestroyKey`, `BCryptCloseAlgorithmProvider` | handles closed by defer, in the right order; parameter set digits-only and at most 8 characters | the in-box default primitive provider | ok, see finding S2-3 |
| `readString` | pointer arithmetic over a UTF-16 string | reads at most `MaxName` units; must terminate inside the cap; rejects control characters, DEL, empty and lone surrogates | n/a | ok, tested |
| `find` | `LazyProc.Find` | a missing export becomes `ErrUnsupported`, not a crash (older Windows) | n/a | ok |

The libraries are loaded with `NewLazySystemDLL` (System32 only), so a `bcrypt.dll` planted in the current directory or on
`PATH` is never loaded.

## Unsafe and pointer use

`unsafe` appears only in `internal/winapi` and only to (a) pass the address of out-parameters to the API,
(b) view an OS-allocated array as a slice after the count has been capped, and (c) read a string one unit at a time.
Out-parameters are Go variables, so the API's results arrive as `unsafe.Pointer` values directly, with no `uintptr`
round trip that the garbage collector could invalidate. `go vet` is clean.

## Findings

| ID | Sev | Finding | Disposition |
|---|---|---|---|
| S2-1 | Info | The first draft put the Windows calls in the sensor package; the architecture test failed. | **Fixed by moving them to `internal/winapi`** and extending the rule (not weakening it). |
| S2-2 | Low | A call that times out leaves its goroutine running. | **Accepted.** The process is short-lived; the call holds nothing the run needs; the timeout and the partial coverage are tested (`TestAStalledCallIsBoundedByTheTimeout`). |
| S2-3 | Low | Probing a parameter set generates an ephemeral key pair, the only cryptographic operation the collector performs. | **Accepted and constrained:** two families only, fixed digit-only parameter sets, key destroyed by defer, never exported or stored, method declared `adjacent`, decision recorded in ADR-0013. The independent oracle repeats the same operation. |
| S2-4 | Low | A provider registered by a local administrator can carry any name. | **Mitigated:** names are bounded and validated twice (the layer and the sensor's `SafeText`), lookalikes of the allow-listed name do not match (exact, case-sensitive), and the sensor never opens a name that is not on the list. |
| S2-5 | Info | The allow-list opens the in-box software provider, which talks to the local Key Isolation service. | **Accepted:** local IPC to an in-box service; no network. Pinned by test; changing it is a code change. |
| S2-6 | Info | Not validated: Windows Server, ARM64, builds before 24H2, an elevated run, a machine with third-party providers (HSM, smart-card middleware). | **Stated** in the stage report and the CBOM's blind spots. |

## Evidence

- Unit tests of the string reader with hostile input (unterminated, one over the cap, control character, DEL, lone
  surrogate, empty, nil) and of the count cap, class mapping, status mapping and the digits-only guard.
- **Mutation checks:** loosening the string cap makes two tests fail; making every key storage provider openable makes
  two tests fail (the allow-list test and the lookalike-name test). Both mutations were reverted.
- Sensor tests with a fake Windows: allow-list, PQC-only probing, hostile names, one failed call, everything failing,
  a stalled call, cancellation, bounded lists, determinism.
- **Independent oracle** (`testing/hostdiscovery/compare-cng.ps1`, C# P/Invoke and `certutil -csplist`): provider names
  identical, every algorithm the oracle says a provider offers is named on it, all six post-quantum parameter sets agree
  and four negative controls are refused, only the software key storage provider was opened.

## Verdict

**Pass, with S2-2 to S2-6 accepted as stated.** The layer keeps its rules; the residual risk is the ephemeral key probe
and the loading of one in-box provider, both deliberate and bounded.
