# ADR-0012 · File roles, static imports, hashes and file identifiers (Windows collector, stage 1)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Context for:** an external review of the Windows CBOM (see `docs/host-discovery/stage-1-report.md`)

## Context

The Windows collector reported every OpenSSL file (`libcrypto`, `libssl`, `openssl.exe`) as independently providing
the same 27 algorithms. Only `libcrypto` implements them: `libssl` and the command use it. A CBOM should say which
component **implements** cryptography and which **consumes** it (CycloneDX's own guide separates "provides" from use).
Components also carried no hash and no identifier beyond a path, so two builds of the same-named file were
indistinguishable.

## Decisions

1. **Provider and consumer roles are knowledge, per file, and only for loose files.**
   `knowledge.Family.FileConsumers` names the files of a family that use its implementation. The derive stage never
   credits a consumer with capabilities. Debian packages are unchanged: one package holds the whole library, and the
   frozen pre-refactor output (`testing/golden/legacy`) proves it. Knowledge revision `1` → `2`.
   *Citation:* OpenSSL's "introduction to the OpenSSL libraries" states that libcrypto provides general purpose
   cryptography and that libssl depends on and uses it. It does not describe the `openssl` command, so that file's
   consumer role is an inference and the component says so (`cipherhorizon:role-basis`).
2. **Dependencies are proven from the import table, not guessed.** A hand-written, bounds-checked, fuzzed reader
   returns the library names in a file's static import table. Only names that are themselves *recognised crypto
   libraries* are kept; every other import is discarded, not recorded. A link is written only when the sensor found
   that library in the **same directory**, because the import table proves a name and Windows resolves the name by a
   search order this sensor does not evaluate. The claim is `bound` (static-import), class E1: "could use", never
   "uses". The component states the basis in `cipherhorizon:dependency-basis`.
3. **A SHA-256 for every recognised, well-formed file.** It is computed from a file the sensor already opened
   because its *name* matched a recognised crypto library; it is never applied to a key or a secret (SR-1 forbids
   hashing key material, not libraries). Bounds: 128 MiB per file and 2 GiB per run; a file skipped for size or
   budget has no hash and the coverage says how many were hashed. The hash is a fact about the bytes: it identifies
   the exact file and does not say who made it.
4. **The identifier is a file identity, and says so.** `pkg:generic/<file>@<file version>?checksum=sha256:<digest>`,
   emitted only when the file version is known, with `cipherhorizon:identifier-basis` stating it is "not an upstream
   product identifier". OpenSSL's real version and a file's four-part version are not the same string, and a
   product identifier (CPE, `pkg:` for the upstream release) needs a cited per-family version rule; until that
   exists the collector does not offer one, so nobody can mistake the file identity for a vulnerability-database key.
5. **Attribute allow-list and format.** `sha256` must be 64 lower-case hex digits and `imports` library names
   only; `Validate` rejects anything else, so a hostile file cannot smuggle text through those fields.

## Considered and not done: algorithm variants

The review asked for algorithm variants ("AES-256-GCM", "RSA-2048") where the evidence supports them. **For a
host file it does not.** The evidence is "this library, this version, exists". The cited documentation says OpenSSL
supports AES and RSA; it does not tell us which key sizes or modes this installation offers or uses. Emitting
`AES-256-GCM` because it is common would be exactly the invention the evidence model forbids. Where the knowledge
table cites a specific variant it already emits it (ML-KEM-768, SHA-384, SLH-DSA-SHA2-128s and so on). Variants for
the classical families need per-mode citations in the knowledge table (a knowledge task, not an evidence one) and
belong with the level-2 native inventory, where the operating system can be *asked* which algorithms and key
lengths a provider supports (probed capability).

## Consequences

- `libssl` and `openssl.exe` no longer appear as providers of algorithms; the host page's "provided by" list
  shrinks accordingly. On this development machine `libcrypto` provides 27 algorithms and the consumers 0, and the
  documents now show `openssl.exe → libssl → libcrypto`, GnuTLS → Nettle/Hogweed and `gpg.exe → libgcrypt`, all
  proven from import tables.
- New method `pe.imports@1` (parsed). A `bound` observation is E1, so the derive-stage rule "no claim stronger than
  its weakest evidence" is unchanged and still enforced.
- The CBOM grows by a hash, an identifier and a few `cipherhorizon:*` properties per file; the run still takes about
  3 seconds.

## What this does not do

- It does not evaluate Windows' DLL search order, delay-loaded imports or `LoadLibrary` calls, so a missing edge
  proves nothing.
- It does not verify signatures (see `docs/host-discovery/authenticode-investigation.md`).
- It does not link a consumer to a provider in a different directory, even when the import names match.
