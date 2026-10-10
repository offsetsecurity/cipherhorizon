# Windows collector, stage 1: file-level evidence

**Scope (approved 2026-09-26):** close the cheap, high-value gaps in the file-level sensor before adding native
Windows discovery (stage 2). **Decision record:** [ADR-0012](../decisions/ADR-0012-file-roles-imports-hashes-identifiers.md).

## What changed

| Item | Result |
|---|---|
| OpenSSL relationships | Provider and consumer roles by file; consumers link to their provider by a proven static import. |
| SHA-256 | On every recognised, well-formed file (bounded). |
| Identifiers | A generic package URL that is honestly a *file identity*. |
| Algorithm variants | Considered and **not done**, with the reason (ADR-0012). |
| Authenticode | Investigated, **not shipped**: [investigation](authenticode-investigation.md). |
| Publisher | Unchanged: the PE resource's `CompanyName` is not collected, so nothing "claimed" is presented as verified. |

## Evidence (all on this Windows 11 machine, standard user)

| Check | Result |
|---|---|
| New CBOM, real files | 49 components; `libcrypto` provides 27 algorithms, `libssl` and `openssl.exe` provide 0; edges `openssl.exe → libssl, libcrypto`, `libssl → libcrypto`, `msys-gnutls → hogweed, nettle`, `gpg.exe → msys-gcrypt` |
| Oracle comparison (`compare-windows.ps1`) | **unchanged:** 22 agreed, 0 version mismatches, 0 false positives |
| Hash oracle (`compare-hashes.ps1`, `Get-FileHash`) | **22 of 22 agree** |
| Import-reader oracle (Go `debug/pe`, 400 genuine `System32` DLLs) | every import the standard library reports was found |
| Fuzzing the new reader | 3.9 million executions, no failure. **The first fuzz run found a real bug in the new code** (a header shorter than the directory count read past the buffer); fixed, and the failing input is kept as a regression seed |
| Frozen Debian output (`TestLegacyOutputIsPreserved`) | unchanged |
| Run time | about 3 s, as before |

## Corrections made along the way

- The knowledge table first cited an OpenSSL documentation URL from memory; it returned 404. The correct page
  (`ossl-guide-libraries-introduction`) was fetched and confirms libssl → libcrypto explicitly. It does not mention the
  `openssl` command, so that role is recorded as an inference.
- An earlier statement that hashes were "left out on purpose" was not supported by the design records; they were simply
  not built.
- An earlier note that Authenticode "needs hand-written syscalls" was wrong for embedded signatures.

## Known limits carried forward

Hashing reads file bytes, so it is the first thing in the collector whose cost grows with file size (bounded, and
reported in the coverage). Dependency edges are same-directory only. The other 47 candidates the oracle lists
(including five real recognition gaps) are unchanged and are not part of this stage.
