# WP-3 security review: Windows certificate store enumeration (`internal/winapi/certstore*.go`)

Reviewer role: Security Architect (performed by the assistant against SECARCH-001 and ADR-0016; not independent). Date 2026-09-26.
This is the written syscall review that PRD-003 REQ-CERT-1 and REQ-REVIEW-001 made a merge gate, in the form of the stage-2 review.

## What was reviewed

`internal/winapi/certstore.go` (interface, limits, allow-list), `certstore_windows.go` (the calls), `certstore_other.go` (stub), `internal/sense/wincerts/wincerts.go` (the sensor), and the tests that pin them.

## Calls made, and why each is safe

| Call | Where | Purpose | Safety argument |
|---|---|---|---|
| `CertOpenStore(CERT_STORE_PROV_SYSTEM, …, flags, name)` | `CertStore` | open one system store | flags are always `OPEN_EXISTING | READONLY` plus one of two location flags: it cannot create or modify a store. The name is a NUL-terminated UTF-16 string we allocate, taken from a fixed six-name list and re-checked in this function (`ValidStore`), so a caller cannot ask for another store. Pinned by `TestKeyAssociationQueryIsTheOnlyPropertyReadAndHasNoBuffer` and `TestStoresOutsideTheAllowListAreRefusedBeforeWindowsIsCalled`. |
| `CertEnumCertificatesInStore` | `CertStore` | walk the store | the standard enumeration; it frees the previous context on every call, including the final one that returns nil |
| `CertGetCertificateContextProperty(ctx, 2, NULL, &cb)` | `keyAssociation` | does a key association exist | property id **2** (`CERT_KEY_PROV_INFO_PROP_ID`) only; **no output buffer**, so it can report that the property exists and cannot return its contents (the container and provider names). It does not open the key or load its provider. There is exactly one call site (asserted by test). |
| `CertFreeCertificateContext` | early exit | release the context we hold when the per-store cap stops the loop | the only path that holds a context without handing it to the next enumeration call; freed once |
| `CertCloseStore` | deferred | close the store | read-only handle |

Not called anywhere in the package, asserted by `TestNoKeyMaterialFunctionIsCalled` scanning the non-comment source: `CryptAcquireCertificatePrivateKey`, `CryptAcquireContext`, `NCryptOpenKey`, `NCryptExportKey`, `NCryptImportKey`, `NCryptSignHash`, `NCryptDecrypt`, `NCryptEncrypt`, `CryptExportKey`, `CryptGetUserKey`, `CryptImportKey`, `CryptSignHash`, `CryptDecrypt`, `PFXExportCertStore(Ex)`, `CryptExportPKCS8`, `BCryptExportKey`, `CertGetPublicKeyLength`, `CertOpenSystemStore`, `CertFindCertificateInStore`, and every function that adds to, deletes from or changes a store or a certificate's properties.

## Checks

| # | Check | Result |
|---|---|---|
| 1 | Libraries load from System32 only | Pass: `NewLazySystemDLL("crypt32.dll")`, as the rest of the package. A Windows lacking the export reports unsupported through `find`, not a crash. |
| 2 | Every OS-supplied length is bounded before it sizes anything | Pass: `Length` is checked against `MaxCertDER` (64 KiB) before the copy; the count per store is capped at 20,000 (over-cap stops the loop and is counted); a zero length or nil pointer is skipped and counted. |
| 3 | Memory ownership | Pass: the certificate's bytes are copied out (`make` + `copy`) before the context is released; nothing retains an OS pointer after the loop moves on. |
| 4 | Handles and contexts on every path | Pass by inspection: normal end (enumeration frees), error return (enumeration frees the previous), cap exit (explicit free), store handle closed by `defer`. No path calls `CertFreeCertificateContext` on a context the enumeration already freed. |
| 5 | Error handling | Pass: a missing store is an empty answer; access denied and other failures are returned with the Windows code and become `unknown(permission)` / `unknown(error)` per store in coverage; one bad store never stops the run. |
| 6 | Stalls | Pass: the sensor gives each store 15 s and abandons a stalled one (the goroutine ends when Windows answers); tested with a fake that stalls. |
| 7 | Text from certificates | Pass: subject, issuer and names are attacker-controlled; the sensor cleans and length-caps them (`evidence.Clean`) and `evidence.Validate` now also rejects control characters as a second line of defence (**hardening made in WP-2**: it accepted them before). |
| 8 | The sensor cannot be pointed at the wrong machine | Pass: it runs only when `OS == windows && Live && Native()`; mutation check (drop `Live`) fails `TestDetectRunsOnlyForALiveWindowsHost`. |
| 9 | Network | No network call exists in the layer or the sensor (architecture test: the collector links `net` only through `crypto/x509`, ADR-0015). Runtime evidence, with the usual caveat that absence of observation is not proof: a full collector run left the CryptoAPI URL cache byte-identical (118 files before and after), which is where a fetched CRL or OCSP response would land. |
| 10 | Private-key handling end to end | Pass: the only key-related fact is the presence flag; `TestNothingButCertificatesComesOut` feeds a PKCS#8 key blob into a store and asserts none of its bytes appear; the real-machine test asserts no armored text in the output. |

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| W3-1 | Low | `privateKey=no` could be read as "no key exists". It means "no key is associated with the certificate in this store". A key can exist elsewhere. | Documented in ADR-0016 and the CBOM model; the UI (WP-8) must word it that way. |
| W3-2 | Low | Certificates Go's strict parser rejects (found: one, "Root Agency", a Microsoft test root, in the CA store) cannot be described. | Counted per store (`unparseableCertificates`), coverage becomes partial (reason unsupported), and the CBOM now carries the count (`cipherhorizon:coverage-limit`), so a reader sees how many were left out. The independent oracle found exactly these and no others. |
| W3-3 | Info | Reading the current user's stores reveals the user's certificates. | Metadata only, same class as the file inventory; the host name can be redacted (ADR-0009) and the user name is not emitted. |

## Mutation checks

| Guard | Mutation | Result |
|---|---|---|
| Store allow-list | accept any non-empty name and location | `TestStoresOutsideTheAllowListAreRefused…`, `TestOnlyAllowListedStoresAreRequested` fail |
| Property query has no buffer | pass an output buffer | `TestKeyAssociationQueryIsTheOnlyPropertyReadAndHasNoBuffer` fails |
| Read-only store open | drop the read-only flag | same test fails |
| No key functions | name `CryptAcquireCertificatePrivateKey` in the package | `TestNoKeyMaterialFunctionIsCalled` fails |
| Live-only | drop the `Live` requirement | `TestDetectRunsOnlyForALiveWindowsHost` fails |

## Independent oracle

`testing/hostdiscovery/compare-certs.ps1` re-derives the answer through the .NET `X509Store` classes and compares certificate by certificate, including key size (RSA, ECDSA and DSA by three separate extension routes) and the private-key association (`HasPrivateKey`).

Result on the development machine (Windows 11, standard user): **142 placements expected, 140 detected, 2 missing, both the certificate the sensor reported as unparseable; 0 extra; 0 key-size mismatches; 0 key-flag mismatches; no armored key text: AGREE.** Five negative controls (a certificate dropped, a certificate invented, a wrong key size, a flipped key flag, an armored key added to the document) were each caught (`DISAGREE`).

## Not validated

Windows Server, ARM64, builds before 24H2, an elevated run (the machine and user stores read here are those a standard user can enumerate; an elevated run may add nothing or may add stores this user cannot read), stores of other users, smart-card and Group-Policy stores, machines with third-party certificate providers.

## Verdict

**Pass.** The layer keeps ADR-0016's rules and the tests pin them. The residual risks are W3-1 (wording) and the unvalidated platforms above.
