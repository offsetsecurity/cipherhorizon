# Contributing to CipherHorizon

Thank you for considering a contribution. This project inventories and actively scans real cryptographic
configurations, so correctness and citing your sources matter more here than in most projects — see
"Evidence and citations" below before writing a rule.

## Before you start

For anything beyond a small fix (a new collector, a new finding/rule, a UI view, a CLI flag), please open an
issue first to agree on the approach. It saves you from a large PR built on an assumption that doesn't match
the project's direction.

## Development setup

```sh
git clone <this repository> && cd <it>
go build ./...
go test ./...
```

You need **Go 1.25+** and nothing else to build and run the unit/integration tests. Optional, for the full
suite:

- **golangci-lint** ([install](https://golangci-lint.run/welcome/install/)) — `golangci-lint run ./...`
- **Node 22+** — only to run the browser end-to-end journey (`node testing/e2e/journey.mjs`, see
  [testing/README.md](testing/README.md)); the UI itself has no build step and no npm dependency.
- A C toolchain — only to run `go test -race` locally; CI runs it on Linux regardless.

`make check` (build, vet, gofmt, tests, UI script syntax) runs everything a PR needs locally; `make help` lists the
rest. `go vet ./...` and `gofmt -l .` (expect no output) should be clean before you open a PR.

## Making a change

1. **Branch off `main`** with a short-lived branch (`feat/...`, `fix/...`, `docs/...`); see
   [docs/engineering/BRANCHING.md](docs/engineering/BRANCHING.md).
2. **Match the existing style.** Comments explain *why*, not *what* (`internal/server/guard.go` and
   `internal/eval/hygiene.go` are good examples); package doc comments open with `// Package x ...`; error
   strings are lowercase and unpunctuated per Go convention. `gofmt` and `golangci-lint` (see `.golangci.yml`)
   enforce most of the rest.
3. **Add tests.** Go code: table-driven unit tests plus, for anything touching the TLS scanner, a hermetic
   test server (`internal/tlsprobe/testserver`) rather than a real network target — **never point a test, an
   example, or CI at a host you don't own.** UI changes: if they're visible in the browser, consider extending
   `testing/e2e/journey.mjs`.
4. **Update the docs that describe what you changed** — most likely one of `docs/*.md`, `README.md`, or a
   package doc comment. Don't hand-edit `testing/golden/*.cbom.json`; regenerate them with
   `go test ./internal/app -update` and read the diff.
5. **Run the checks** in "Development setup" above.

## Evidence and citations

This is the one rule the codebase enforces in tests, not just in review: **every PQC verdict, every TLS
finding, and every readiness/hygiene claim must cite a primary source** (an RFC, a NIST FIPS/SP/IR, a CVE, an
IANA registry, or equivalent) — see `internal/pqc/rules.go`, `internal/eval/rules.go` and
`internal/eval/citations.go` for the existing pattern, and `TestEveryRuleIsCited` /
`TestEveryRuleFiresAndIsCited` for the tests that check it. If you can't cite a claim, it doesn't go in as a
rule; report the fact and leave the judgement to the reader. Don't guess at what an unrecognised algorithm,
cipher suite, or OID is — omit it rather than pattern-match a name (see `internal/algo`'s package doc comment).

If you're proposing a new algorithm classification or TLS finding, include the citation *in the PR
description* as well as the code, so it's easy to review.

## Commit messages and sign-off

- Write commit messages in the imperative ("Add X", not "Added X"), with a short summary line and, where it
  helps, a body explaining why.
- **Sign off your commits** (Developer Certificate of Origin, [developercertificate.org](https://developercertificate.org/)):
  add `-s` to `git commit`, or a trailing `Signed-off-by: Your Name <you@example.com>` line, confirming you
  have the right to submit the change under this project's license.

## Pull requests

- **Title the PR as a [Conventional Commit](https://www.conventionalcommits.org/)** (`fix(tlsprobe): ...`,
  `feat(web): ...`; a check enforces it). PRs are squash-merged, so the title is the commit on `main` and the
  changelog line. Add a line under `## [Unreleased]` in `CHANGELOG.md` for anything a user would notice.
- Keep PRs focused; a large PR that mixes an unrelated refactor with a feature is harder to review and to
  revert if something's wrong.
- CI runs build, tests (including `-race` on Linux), `golangci-lint`, a short fuzz smoke run, and the browser
  end-to-end journey (see `.github/workflows/ci.yml`); please make sure it's green before requesting review.
- Describe *what changed and why*, not just *what*. For a new rule or finding, restate its citation in the PR
  description.

## Reporting bugs and requesting features

Use the issue templates. For a **security vulnerability**, please follow [SECURITY.md](SECURITY.md) instead
of opening a public issue.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you're agreeing to abide by it.

## License

By contributing, you agree your contribution is licensed under this project's [Apache 2.0 license](LICENSE).
