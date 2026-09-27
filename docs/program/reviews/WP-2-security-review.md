# WP-2 security review (certificate entities, Linux certificate sensor, certificate rules and API)

Reviewer role: Security Architect (performed by the assistant against SECARCH-001; not independent). Date 2026-09-26.

## Scope reviewed

`internal/sense/certfiles` (sensor and PEM scanner), `internal/certinfo`, `internal/evidence` changes (certificate kind, `Source.Attrs`, attribute validation), `internal/cbom/{certificate,hostbuild}.go`, `internal/estate` (certificate projection), `internal/eval/certificate.go`, `internal/server/certificates.go`, `internal/store/certificates.go`, `internal/hostcmd` (`openHostFS`), the collector link rule.

## Checks and results

| # | Check | Result |
|---|---|---|
| 1 | No private key is opened by name, decoded, stored or reported (SR-06) | Pass. Key-named files and `private/` directories are never opened (`TestNoKeyMaterialIsReadOrReported` records every open). Inside an opened file the scanner decodes CERTIFICATE blocks only, and it is not `encoding/pem` (which decodes every block): `TestOnlyCertificateBlocksAreDecoded` uses key blocks that would decode cleanly. Canary keys appear in no batch, no CBOM, no API response. |
| 2 | The evidence layer offers no place for key material | Pass: attribute allow-lists; no attribute for a key, a password or a key path; `TestCertificateObservationsCarryOnlyAllowedMetadata` refuses each. |
| 3 | Symbolic links (SR-16) | Pass on fixtures: links followed once, inside the root, to a regular file, through real directories; escape, loop, chain, directory, dot-dot and empty targets refused and counted; refusal makes coverage partial, not silently complete. For an overridden root the filesystem is now `os.Root` (traversal-resistant), so a link inside a tree we do not control cannot lead out of it; that test **skips on the development machine** (no symlink privilege) and runs in Linux CI. |
| 4 | Hostile certificate text (SR-02, SR-17) | Pass: cleaned and length-capped by the sensor, refused by `evidence.Validate` as a second line. **Finding W2-1 (fixed):** `Validate` accepted control characters in attribute values. It now rejects them for every kind (`SafeText`). |
| 5 | Bounds (SR-01, SR-15) | Pass: file size 4 MiB, DER 64 KiB, 4,000 certificates per file, 20,000 per run, 200,000 directory entries, depth 6; each hit is counted and makes coverage partial (`TestBudgetsAreEnforcedAndReported`). |
| 6 | Parser robustness | Pass: two fuzz targets (PEM scan, first-element check) run for 60 s total, clean after **finding W2-2 (fixed):** the element check accepted a private-class tag; regression seed kept. |
| 7 | The collector must not gain a way to reach the network | Pass with a recorded change: `crypto/x509` links `net`. ADR-0015 tightens the rule to "only through `crypto/x509`, and no package of this module imports it", checked on Linux and Windows; mutation check (a module package importing `net`) fails it. |
| 8 | Method declared adjacent to secrets | Pass: `certs.file-parse@1` is `SecretProximity: adjacent` (asserted by test). |
| 9 | Certificate API exposes only public metadata, behind the token | Pass: `/api/v1/certificates*` are covered by the route-table token, forgery and Host tests; fingerprints are validated (64 hex) before use; the canary test covers 11 API paths. |
| 10 | The graph cannot be made to over-claim by an imported document | Pass so far: an imported observation cannot claim bound, loaded or exercised (validation); imports themselves land in WP-4. |

## Findings

| # | Sev | Finding | Disposition |
|---|---|---|---|
| W2-1 | Medium | `evidence.Validate` let control characters through attribute values. The sensors cleaned their input, so nothing exploited it, but the second line of defence was missing. | Fixed and tested for all kinds. |
| W2-2 | Low | ASN.1 element check accepted a non-universal tag class. | Found by fuzzing; fixed. |
| W2-3 | Info | `privateKey=unknown` is the honest answer for a bare certificate file on Linux: a key may exist elsewhere. `yes` is only "a key block is in this file". | Worded that way in the docs; the UI must too (WP-8). |
| W2-4 | Info | The overridden-root symlink test cannot run on the development machine. | Runs in CI; listed in the RTM notes and the not-validated list. |

## Mutation checks

| Guard | Mutation | Result |
|---|---|---|
| Key-named files are not opened | open them | `TestNoKeyMaterialIsReadOrReported` fails |
| Only CERTIFICATE blocks are decoded | decode key blocks too | **survived at first**; after strengthening, `TestNoKeyMaterialIsReadOrReported`, `TestOnlyCertificateBlocksAreDecoded`, `FuzzScanPEM` fail |
| Symlink rule | follow unconditionally | `TestSymbolicLinkRules` fails |
| File size cap | remove | `TestBudgetsAreEnforcedAndReported` fails |
| Collector `net` rule | a module package imports `net` | `TestCollectorLinksNoServerStoreOrScanner` fails |

Sign-off: approved for the WP-2 gate.
