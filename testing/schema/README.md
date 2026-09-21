# Vendored CycloneDX schemas

These files are copied unmodified from the CycloneDX specification
(<https://github.com/CycloneDX/specification>, Apache-2.0), via the schema
directory of `github.com/CycloneDX/cyclonedx-go` v0.12.0. They let the test suite
validate every emitted CBOM offline, with no network access.

| File | `$id` |
|---|---|
| `bom-1.6.schema.json` | `http://cyclonedx.org/schema/bom-1.6.schema.json` |
| `spdx.schema.json` | `http://cyclonedx.org/schema/spdx.schema.json` |
| `jsf-0.82.schemax.json` | `http://cyclonedx.org/schema/jsf-0.82.schema.json` |

To update, replace the files and re-run `go test ./...`; `internal/cbom/vocab_test.go`
checks the closed vocabularies in code against the enumerations in `bom-1.6.schema.json`.
