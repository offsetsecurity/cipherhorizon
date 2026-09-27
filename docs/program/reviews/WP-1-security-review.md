# WP-1 security review (model, migration, systems metadata, audit)

Reviewer role: Security Architect (performed by the assistant against SECARCH-001; not independent). Date 2026-09-26.

## Scope reviewed

`internal/estate`, `internal/store/{graph,systems,findings,hosts,store}.go`, `internal/server/{systems,ingest,server}.go`, `internal/app/db.go`, migration 4.

## Checks and results

| # | Check | Result |
|---|---|---|
| 1 | Every SQL statement takes values as bound parameters | Pass. Two statements build the `SET` list from column names; those come only from the fixed `systemColumns` table, never from input (annotated for the linter, hostile-value test `TestHostileSystemTextIsData`). `VACUUM INTO` binds the path. |
| 2 | Attacker-controlled strings (certificate names, component names, properties) are cleaned and bounded before storage, and refused by `estate.Validate` if anything slips through | Pass (`TestHostileCertificateStringsAreCleaned`, `TestValidateRefusals`). Rendering is the UI's job (SR-02) and is checked in WP-8. |
| 3 | A hostile document cannot make the graph unbounded | **Finding, fixed:** a 32 MiB CBOM could carry about a million components and each would become a stored observation inside the upload request. Added `ObservationCap` (50,000 per document); the excess is counted in `sources.not_interpreted_json`, never silently dropped (`TestAnEnormousDocumentIsBoundedAndCounted`). Nesting depth is bounded by Go's JSON decoder (10,000). Full limit set for imports lands with WP-4 (SR-01). |
| 4 | Trust attaches to the channel, not the document | Pass with a stated weakness: host uploads are attributed to the collector when the route receives them and the document names this product as producer. Recorded in SECARCH-001 T-03 and pinned by test. Third-party documents will use the import flow, which never assigns `collector`. |
| 5 | The graph cannot be used to rewrite or hide first-party evidence | Pass so far: nothing in WP-1 lets a document delete or downgrade an observation (imports do not exist yet; the rule is enforced at validation: an imported observation cannot claim bound, loaded or exercised). Precedence rules are a WP-4 gate. |
| 6 | Migration cannot lose data | Pass: automatic backup before the first change (fails closed), one transaction, raw tables untouched, failure-injection test, frozen-migration hash test. **Real bug found by the retry test and fixed:** a second attempt within the same second could not create its backup and refused to migrate. |
| 7 | Audit log is append-only and written with the change | Pass: triggers reject UPDATE and DELETE; the write is in the same transaction as the change; a rejected patch writes nothing; mutation check (skip the write) makes three tests fail. Limit: one shared token, so the actor is `api-token`. |
| 8 | New mutating routes are guarded | Pass: tests walk the real route table; mutation check (guard narrowed to one prefix) fails the forgery test. The CSV route accepts `text/csv` and only there. |
| 9 | Estate data is not exposed without the token | Pass: every new route is covered by the token test; exports go through the same auth. |
| 10 | Secrets and key material | None enters the graph: certificate attributes are an allow-list of public metadata; there is no attribute that could carry key material; the decoy `server.key` test asserts a private-key file never becomes an entity. |
| 11 | File permissions of the new file (backup) | Pass: created 0600 before data is written; Unix mode test (skipped on Windows, where the ACL applies as for the database itself). |

## Residual risks accepted for WP-1

- One shared token means the audit actor is not a person.
- The producer name on a host upload is a claim (see 4).
- Rebuilding the graph on a very large database at start-up takes time proportional to the number of stored documents; it happens only when the projection version changes.

## Mutation checks performed

| Guard | Mutation | Tests that failed |
|---|---|---|
| Pre-migration backup (SR-10) | skip it | `TestLegacyDatabaseMigratesWithoutLosingAnything` |
| Audit write (SR-11) | skip it | `TestSystemChangesAreAudited`, `TestAuditLogIsAppendOnly`, `TestSystemsAreListedAndEdited`, `TestSystemRoutesAreGuarded` |
| Host cannot claim exercised (ADR-0006) | remove the rule | `TestValidateRefusals` |
| Import cannot claim bound/loaded/exercised (SR-18) | remove the rule | `TestValidateRefusals` |
| Forgery guard (SR-12) | apply it to one path prefix only | `TestEveryMutatingRouteIsGuardedAgainstForgery` |

Sign-off: approved for the WP-1 gate.
