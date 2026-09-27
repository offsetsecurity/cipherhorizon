# Embedded CycloneDX schemas

Provenance and checksums (SECARCH-001 SR-14). Nothing here is edited: to update, replace the
file, update this table, and run `go test ./internal/cdxschema ./internal/schematest`.

| File | Version | Source | Licence | SHA-256 |
|---|---|---|---|---|
| `bom-1.6.schema.json` | CycloneDX 1.6 | `schema/` of `github.com/CycloneDX/cyclonedx-go` v0.12.0 (the specification's schema); identical to `testing/schema/bom-1.6.schema.json` | Apache-2.0 | `3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93` |
| `bom-1.7.schema.json` | CycloneDX 1.7 | same module and version | Apache-2.0 | `6166dcd7ab0176139587650dee1427972122ac488b83c34f39933966b6146ffe` |
| `spdx.schema.json` | SPDX licence identifiers | same module and version; identical to `testing/schema/spdx.schema.json` | Apache-2.0 | `669315cee4265ad6d742e92d7afb062fb4847abe754d3ade544b7c40482d0a48` |
| `jsf-0.82.schema.json` | JSON Signature Format 0.82 | copy of `testing/schema/jsf-0.82.schemax.json` (the specification's, renamed to the file name its `$id` implies) | Apache-2.0 | `a517f9e483e2252debd23d5c62edb72805b6d3932935a6ebb8196745052d2dc3` |
| `cryptography-defs.schema.json` | 1.7 cryptography registry (algorithm families, elliptic curves; its `$comment` stamp is 2026-03-05) | `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/cryptography-defs.schema.json`, retrieved 2026-09-26 (the module above does not ship it) | Apache-2.0 | `027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44` |
