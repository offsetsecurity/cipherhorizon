# ADR-0017: Validate imported CBOMs against embedded schemas (a test library becomes a shipped one)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Relates to:** PRD-003 REQ-ING-2, SECARCH-001 SR-01, SR-14, ADR-0014 (no new Go dependency without an ADR)

## Context

Third-party CBOMs are untrusted input (SECARCH-001 T-01, T-02). Requirement REQ-ING-2 says they are validated against the schema of the version they declare before anything is stored. The repository already validates its own output against the CycloneDX 1.6 schema in tests, using `github.com/santhosh-tekuri/jsonschema/v6`, which so far shipped in no binary.

## Decision

1. The server binary validates imports with the same library. It was already in `go.mod`; what changes is that it is linked into `cipherhorizon`. It is pure Go (no cgo), Apache-2.0, and `golang.org/x/text` (its message support) becomes a direct dependency. **The collector does not link either** (the architecture test bans it: the collector must stay small).
2. The schemas are embedded (`internal/cdxschema/schemas`, with a manifest of source and SHA-256), so validation needs no network and no files. Versions **1.6 and 1.7**; earlier versions have no cryptographic assets and are refused with a message saying so.
3. Validation runs **after** a limits layer that bounds size, nesting and node count, because validating builds an in-memory tree of the whole document. The order is fixed: limits, then schema, then decode.
4. Error reports are bounded (at most a few problems, each clipped) so a hostile document cannot make its own rejection large.

## Consequences

- The shipped binary grows by the library and the schemas (about 0.7 MB of schema text).
- One schema update procedure for tests and production (`MANIFEST.md`); `schematest` keeps its own copy of 1.6 for now and a test asserts the two are identical.
- 1.7's registry of algorithm families and curves is enforced on import: a document naming a family outside the registry is refused, which is the standard doing its job and also a place where a producer's bug will surface as a rejected upload rather than a silently odd one.
