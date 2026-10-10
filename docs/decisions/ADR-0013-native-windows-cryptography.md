# ADR-0013 · Native Windows cryptography: ask the operating system (Windows collector, stage 2)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Context for:** the external review's main finding: the Windows collector reported third-party crypto files and
  nothing of the cryptography Windows itself provides (CNG, key storage providers, legacy CSPs).

## Context

On the development machine the file scan found OpenSSL, GnuTLS and NSS bundled with Git, VLC and Firefox. It said
nothing about Windows' own ML-KEM and ML-DSA, its 51 registered algorithm identifiers (including RC4, MD4, MD5, DES
and 3DES), its nine CNG providers or its ten legacy providers. Those are available from the operating system
directly, which is a stronger source than a file name and a version: the system can be **asked**.

## Decisions

1. **A new sensor, `windows-cng`, that asks Windows.** It reports two kinds of fact: a provider is *present*
   (method quality *authoritative*: the system was asked) and an algorithm is *capable, probed* through a provider.
   It does not replace the file sensor; both feed the same evidence graph. Capability is still never use (E0).
2. **All Windows calls live in one platform package, `internal/winapi`**, beside `internal/hostinfo`. The sensor
   itself imports no operating-system package. The architecture test now says: only `hostinfo` and `winapi` may
   import `x/sys/windows` or `unsafe`, `winapi` may import nothing else from this module, and neither may run
   subprocesses or use the network. (The first draft put the calls inside the sensor package and the test rejected
   it; the rule was kept and the code moved.)
3. **Loading policy: enumerate by name freely, load code only from a short allow-list.** Listing CNG providers,
   key storage providers and legacy CSPs reads registration data and loads nothing. *Opening* a provider runs its
   code, so the sensor opens exactly one key storage provider, the in-box **Microsoft Software Key Storage
   Provider**. The Platform (TPM), Smart Card, Passport and Pluton providers and every third-party or hardware
   provider are listed by name and never opened (their algorithms are a stated blind spot). Legacy CSPs are listed by
   name and type only, because asking one for its algorithms means loading it. The allow-list is pinned by a test.
4. **Post-quantum parameter sets are probed by generating an ephemeral key pair.** ML-KEM and ML-DSA appear in the
   registry only partly (ML-DSA is enumerated; ML-KEM is not, because key encapsulation is outside the enumeration
   filter), and a parameter set can only be set on a key handle. So, for the two post-quantum families and only for the
   fixed parameter sets FIPS 203 and 204 define, the layer opens the algorithm, generates a key pair in this process's
   memory, sets the parameter set, finalises it and destroys it. The key is never exported, never persisted, never read
   and never used. It is the one place the collector performs a cryptographic operation; the method is declared with
   `SecretProximity: adjacent` so it is visible as such; the parameter-set argument must be digits only. Negative
   controls (`999`, `1`) prove Windows refuses what it does not support.
5. **Live hosts only.** `sense.Env.Live` is true only when the run inspects the machine's own default root. The
   sensor is not detected for a `--root` override, a mounted disk, an image or a test fixture, where the operating
   system would describe the wrong machine.
6. **Identifiers map to the catalogue by a cited table** (`knowledge/cng.go`, citing Microsoft's CNG algorithm
   identifier list). Per-curve identifiers map to the family (`ECDSA_P256` → `ECDSA`) because the catalogue carries no
   curve and none is invented. An identifier with no catalogue entry (key derivation, random generation, MACs, XOFs,
   composite and pre-release algorithms) is still named on its provider (`cipherhorizon:native-algorithms`).
7. **The catalogue grows only with cited entries.** Added: SHA-1, MD5 (OIDs from RFC 3370), MD4, MD2, SHA3-256/384/512
   (OIDs from the NIST CSOR), RC4, RC2, DES, 3DES, and the ML-KEM and ML-DSA families. Every OID was read from its source
   on the day it was added; where no single authoritative OID exists it is left empty.
8. **Retired algorithms are flagged separately from the quantum verdict.** MD5 is not "quantum-vulnerable"; it is unsafe
   against today's computers. An algorithm may carry a `Legacy` statement (a citation and only what that source says,
   e.g. "RFC 6149: MD2 moved to Historic status"), and an algorithm with no post-quantum verdict must say why
   (`NoPQCVerdict`). The invariant test now checks both directions: forgetting a verdict fails, and declaring none
   requires that none exists.
9. **A stalled call cannot stall the run.** Each call into Windows has a deadline (15 s); a call that times out is
   abandoned and reported in the coverage as partial. Every string the OS returns is read with an explicit length cap
   and rejected unless valid, printable and terminated inside it; every count is capped before it sizes anything.

## Considered and not done

- **Opening every key storage provider to enumerate its algorithms.** Rejected: it loads third-party and hardware
  provider code and can stall or prompt. Listing by name is the safe default; an operator who wants more can add a
  provider to the allow-list by code change and review.
- **Legacy CSP algorithm lists.** Would need `CryptAcquireContext`, which loads the provider. Names and types only.
- **Probing every catalogue algorithm.** Only the post-quantum parameter sets need a key handle; everything else is
  read from the registry enumeration, which involves no cryptographic operation.
- **Certificates and key metadata, Schannel policy, application binding.** Later levels (L3 to L5); nothing here
  touches a certificate store or a key.

## Consequences

- On the development machine the document gains 19 providers (9 CNG, of which 5 are key storage providers, and 10
  legacy) and native algorithms, including six confirmed post-quantum parameter sets and seven retired algorithms
  with citations. The primitive provider offers 27 catalogue algorithms; the opened software key storage provider 9.
- A host with no PQC in Windows (an older build) simply has no probe successes: the negative case is an answer, not a
  failure. Windows Server, ARM64 and older builds are **not tested** (see the stage report).
- The UI names the sensor ("Windows cryptography (CNG)") and lists retired algorithms in their own card with the cited
  source; they are no longer lost in "Not classified".

## What this does not do

It does not say which provider or algorithm anything uses, which are enabled for TLS or any protocol, or whether
Windows is in a FIPS mode. That a provider offers an algorithm is not evidence that anything uses it.
