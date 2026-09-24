## What this changes and why

<!-- What problem does this solve? Link the issue it addresses, if any. -->

## How it was tested

<!-- go test ./...? A hermetic test server? The browser journey? Manual steps? -->

## Checklist

- [ ] `go build ./...`, `go vet ./...`, `gofmt -l .` (no output), and `go test ./...` are clean
- [ ] `golangci-lint run ./...` is clean
- [ ] Tests added or updated for the change (a hermetic `testserver`, not a real network target, for anything TLS)
- [ ] Docs updated if behaviour, a flag, or an API/CLI surface changed
- [ ] Golden CBOMs regenerated with `go test ./internal/app -update` if `run`'s output changed, and the diff reviewed
- [ ] **If this adds or changes a PQC verdict, TLS finding, or readiness/hygiene rule: its citation is stated
      in this description**, not only in the code (see CONTRIBUTING.md § Evidence and citations)
- [ ] Commits are signed off (DCO) — `git commit -s`

## Anything else the reviewer should know

<!-- Trade-offs, things deliberately left out, follow-up you're planning separately. -->
