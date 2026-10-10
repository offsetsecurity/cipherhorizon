# WP-4 security review (third-party CBOM ingest)

Reviewer role: Security Architect (performed by the assistant against SECARCH-001; not independent). Date 2026-09-26.

## Scope

`internal/importer`, `internal/cdxschema`, `internal/estate/imported.go`, `internal/store/{imports,graph}.go` (precedence), `internal/server/imports.go`, `internal/app/import.go`, migration 5, ADR-0017.

## Checks and results

| # | Check | Result |
|---|---|---|
| 1 | Hostile documents cannot exhaust memory or CPU (SR-01) | Pass. Order is fixed: size cap (32 MiB, also enforced by the HTTP reader), then a token-stream scan bounding nesting (64), nodes (1,000,000) and string length (1 MiB), then schema validation, then decode, then a component cap (200,000), then a per-document observation cap (50,000) with the excess counted. A depth bomb, a 20,000-value array, a 2,000-byte string and 51 components under a lowered limit are each refused with a specific reason and store nothing. `Parse` was fuzzed for 1.1 million executions (no panic; refusals are `*Error` and bounded; every observation from a valid document validates). |
| 2 | The document cannot choose where its data goes (SR-04) | Pass. The subject is a required query parameter, exactly one of `system` or `newSystem`; the document's own claim is stored and displayed only. A test gives a document the name of an existing system and checks that system receives nothing. |
| 3 | Trust follows the channel (SR-03) | Pass. The import path never assigns `collector` or `scanner`; a document that names this product as its producer is labelled so for the person and is still `imported` (mutation check: attributing imports to the collector fails three tests). |
| 4 | An import cannot overwrite or downgrade first-party facts (SR-18, T-05) | Pass. Imported sources may add entities and attributes but never replace an existing value or rename an entity; disagreements are recorded on the import ("conflict with first-party evidence ...") and both sightings are listed with their sources. Tested with a forged document that reuses a real certificate's fingerprint with a lie about its key size and subject; the mutation check (imports may overwrite) fails that test. |
| 5 | An import cannot claim use | Pass. The imported stream refuses bound, loaded and exercised (validation), mutation-checked. |
| 6 | No key material enters the graph | Pass. Related-crypto-material of any kind other than a public key (used only to read a certificate's size) is counted and not modelled: private keys, secret keys, passwords, tokens and credentials appear in the graph only as a count by reason. The real samples contained 1 private-key, 1 token, 1 password, 2 "other" and 33 secret-key assets; none is in the graph. |
| 7 | Stored text is inert (SR-02) | Pass. Cleaned and bounded in projection; validated; the API returns JSON behind the token and content-type guards; markup in a certificate issuer and in a system name comes back escaped. |
| 8 | Routes guarded (SR-12) | Pass: covered by the route-table tests, plus a dedicated test. |
| 9 | Provenance and audit (SR-11) | Pass: source class, claimed tool and version, SHA-256, size, time, submitting token label and assigned system are recorded; import, new-system creation and withdrawal are audited. |
| 10 | Idempotence and withdrawal | Pass: the same bytes for the same system change nothing; for another system they are refused (409); withdrawal removes observations and orphan entities, keeps the raw document and the record, and importing again reactivates. |
| 11 | Supply chain (SR-14) | Pass with a recorded change: the JSON-schema library that only tests used now ships in `cipherhorizon` (not the collector) and `golang.org/x/text` becomes a direct dependency (ADR-0017). The schemas are the specification's, unmodified, with SHA-256 and source in a manifest. |

## Findings

| # | Sev | Finding | Disposition |
|---|---|---|---|
| W4-1 | Medium | While building the tests, one run of an import test returned a 500 while another package's tests ran in parallel. It did not reproduce in 40 later runs. The likely cause is a deferred SQLite transaction that read before writing failing to take the write lock under WAL ("database is locked"). | **Fixed defensively:** every transaction is now opened IMMEDIATE (`_txlock=immediate`), so writers queue behind the busy timeout. The cause was not proven; the fix removes the class of failure. |
| W4-2 | Low | Real CBOMkit documents record no tool name (only `gitUrl`/`revision` properties); Theia's sample records no tool at all. | CBOMkit is detected by those properties after tool names; Theia is read as generic (the weakest reading, never an overclaim). |
| W4-3 | Info | The standard's schema has no field for a certificate's SHA-256; producers put it in `hashes` (CBOM-Lens) or in the bom-ref (Theia). A certificate with neither is counted, not guessed. | Documented. A wrong identity is harmless: an unmatched fingerprint is simply a new entity, and imports never auto-confirm a link. |
| W4-4 | Info | An oversized but valid document builds an in-memory JSON tree for schema validation (bounded by the node limit). | Accepted at the stated limits. |

## Mutation checks

| Guard | Mutation | Failed tests |
|---|---|---|
| Precedence | imports may overwrite attributes | `TestAnImportCannotOverwriteWhatAScanObserved` |
| Class | attribute an import to the collector | `TestThirdPartyDocumentsImportWithProvenance`, `TestAnImportCannotOverwriteWhatAScanObserved`, `TestAForgedCollectorDocumentIsStillImported` |
| Depth limit | remove | `TestRefusals`, `TestHostileDocumentsAreRefusedAndStoreNothing` |
| Imported stream may not claim use | remove | `TestValidateRefusals` |
| Schema validation | accept invalid documents | `TestRefusals`, `TestHostileDocumentsAreRefusedAndStoreNothing` |

Sign-off: approved for the WP-4 gate.
