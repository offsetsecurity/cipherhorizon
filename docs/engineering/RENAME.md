# Renaming the product

The name is not cleared as a trademark or domain (ADR-0014, owner decision OQ-1). If it changes, the change is mechanical and this is the procedure. It was rehearsed on a copy of the repository: after `scripts/rename.sh acme "Acme Crypto" --apply` the copy built, passed `go vet` and the whole test suite without any test being edited.

## Where the name lives

| Place | Example | Handled by the script |
|---|---|---|
| Go module path and every import | `github.com/<owner>/cipherhorizon` | yes (also `scripts/set-owner.sh` for the owner part) |
| Command directories and binary names | `cmd/cipherhorizon`, `cipherhorizon-collector` | yes (directories moved; release config rewritten) |
| CBOM property namespace | `cipherhorizon:classical-status` | text yes; **registration is a person's decision**, below |
| Environment variables | `CIPHERHORIZON_TOKEN` | yes |
| UI, documentation, release config | `CipherHorizon`, `cipherhorizon` | yes |
| History (CHANGELOG entries, ADR-0014) | | deliberately left alone |

## Steps

1. `scripts/rename.sh <identifier> "<Display Name>"` prints how many occurrences fall in each category and changes nothing.
2. Add `--apply`. Then `gofmt -l .`, `go build ./...`, `go vet ./...`, `go test ./...`.
3. Regenerate the golden CBOMs if a test asks (`go test ./internal/app -update`), review the diff, and run the end-to-end scripts in `testing/e2e`.
4. Do the parts a script cannot decide:
   - **Property namespace.** Stored documents and CBOMs already written carry the old prefix (`cipherhorizon:`). The readers (`internal/server/coverage.go`, `internal/estate/host.go`) accept only the prefix they define, so decide whether old documents must still be read. If they must, accept both prefixes for one release and say so in the CHANGELOG. Register the new namespace with the CycloneDX property taxonomy only after the name is cleared (RESEARCH-003 section 3.2).
   - **Database.** Nothing in the schema carries the name; the `.db` file keeps working.
   - **Existing installs.** The environment variable and the binary name change for users: say so under *Changed* in the CHANGELOG.
   - **Domain and repository** (`set-owner.sh`, DISTRIBUTION.md, the security contact).
5. Commit the rename on its own, so it can be reviewed as one mechanical diff.
