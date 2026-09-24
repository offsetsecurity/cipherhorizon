# Where the code lives, and how a change gets in

This is the plan for the repository: what lives where on GitHub, how branches and commits work, and what
protects `main`. How a version is cut is in [RELEASING.md](RELEASING.md); how it reaches users is in
[DISTRIBUTION.md](DISTRIBUTION.md).

## Home

| | |
|---|---|
| Repository | `github.com/<owner>/cipherhorizon`, under a **personal account** to start (a transfer to an organisation later keeps stars, issues, links and the container image path redirects; see "Moving to an organisation" below). |
| Visibility | Public. CodeQL, dependency review and private vulnerability reporting are free on public repositories. |
| Licence | Apache-2.0 (`LICENSE`). Contributions are accepted under the same licence with a DCO sign-off (`CONTRIBUTING.md`). |
| Module path | `github.com/<owner>/cipherhorizon`. The tree ships with the placeholder owner `example`; run `scripts/set-owner.sh <owner>` once, before the first push (see "First push"). |
| Container images | `ghcr.io/<owner>/cipherhorizon` (GitHub Container Registry, published by the release workflow). |

One repository, one Go module, one binary. Do not split the scanner, the server and the UI into separate
repositories: they version together, the UI is embedded in the binary, and a cross-repo change would need
three coordinated releases.

## Layout

```
cmd/cipherhorizon/     the product binary (CLI + server)         -> shipped
cmd/demo-targets/      development-only servers of known posture -> never shipped
internal/              all library code; nothing here is a public Go API
  tlsprobe/            active TLS scanner, own wire protocol, generated IANA registries
  eval/  pqc/  algo/   findings, readiness and hygiene rules, algorithm verdicts (every rule is cited)
  cbom/  collector/    CycloneDX 1.6 builder, host inventory plugins
  server/  store/      HTTP API, scan runner, SQLite persistence
  version/             build identity, stamped at link time by the release build
web/static/            the UI: plain HTML/CSS/ES modules, embedded with go:embed (no npm, no build step)
testing/               golden files, vendored schemas, browser E2E journey, live security script
docs/                  user and design docs; docs/product = product/QA/release reports; docs/engineering = this
scripts/               release helpers (release-notes, prepare-release, set-owner)
.github/               CI, release, CodeQL workflows; issue/PR templates; Dependabot
```

`internal/` is deliberate: until 1.0 there is no supported Go library API, only the CLI, the JSON API and
the output schemas. Exposing packages would freeze them.

## Branching: trunk-based

- **`main` is always releasable.** It is the only long-lived branch and the only one tags are cut from.
- Work happens on short-lived branches named `<type>/<short-topic>` (`feat/hsts-check`, `fix/ssl2-timeout`,
  `docs/release-runbook`) and lands through a pull request. Aim for branches that live days, not weeks.
- **Squash-merge only.** One PR is one commit on `main`; the PR title becomes the commit message, which is why
  it is checked (below). No merge commits, no rebase-merge, so history stays linear and every commit on `main`
  is one reviewed, CI-passed unit.
- **No `develop` branch, no per-feature release branches.** Unfinished work that must merge early goes behind
  a flag or stays off by default (as `--http-checks` did).
- `release/X.Y` branches exist **only** to ship a patch to an older minor after `main` has moved on
  (`git switch -c release/0.1 v0.1.0`, cherry-pick the fix, tag `v0.1.1` from that branch). They do not exist
  otherwise. See [RELEASING.md](RELEASING.md#patching-an-older-release).
- Tags `vX.Y.Z` are the only release markers and are immutable: never move or delete a published tag; ship a
  new patch instead.

## Commits and pull requests

- **PR titles follow [Conventional Commits](https://www.conventionalcommits.org/)** and are enforced by
  `.github/workflows/pr-title.yml`: `type(scope): summary`, types `feat fix perf refactor docs test build ci
  chore revert security`, `!` before the colon for a breaking change. The type is what a maintainer uses to
  choose the next version (see the table in RELEASING.md); the summary is what goes in the changelog.
- Commits inside a PR can be anything, but must carry a DCO `Signed-off-by` line (`git commit -s`).
- The PR template asks for what changed, how it was tested and, for any rule or verdict, its citation.
- Anyone changing user-visible behaviour adds a line under `## [Unreleased]` in `CHANGELOG.md` in the same PR.

## What protects `main`

Configure once in **Settings → Rules → Rulesets → New branch ruleset** (target: default branch):

- [x] Require a pull request before merging (1 approval once there is a second maintainer; with a single
      maintainer set required approvals to 0 but keep the PR requirement so CI always runs first)
- [x] Require status checks to pass, branches up to date: `test (ubuntu-latest)`, `test (windows-latest)`,
      `test (macos-latest)`, `cross-build`, `lint`, `vuln`, `fuzz`, `e2e`, `release-dry-run`, `title`
- [x] Require conversation resolution; require linear history; block force pushes; block deletion
- [x] Require code-owner review for paths in `CODEOWNERS` (rules, verdicts, the SSRF guard, auth, wire parsers)
- [x] Restrict who can create tags matching `v*` (a second ruleset, target: tags) to maintainers, and block
      updating or deleting them

Repository settings: allow **squash merging only** (title = PR title, body = PR description); auto-delete head
branches; enable Dependabot alerts and security updates; enable **private vulnerability reporting**; enable
secret scanning and push protection; Actions → General → "Workflow permissions: read repository contents"
(each workflow requests what it needs) and "Require approval for first-time contributors".

## Automation that guards it

| Workflow | When | What it does |
|---|---|---|
| `ci.yml` | every PR, push to `main`, and before every release | build, vet, gofmt, `go mod tidy` check, tests (Linux with `-race`, Windows, macOS), cross-build of all six release targets, golangci-lint, govulncheck, fuzz smoke, browser E2E + live security checks, GoReleaser + container dry run |
| `codeql.yml` | PR, `main`, weekly | CodeQL for Go and the UI scripts (`security-extended`) |
| `dependency-review.yml` | PR | blocks new dependencies with high-severity advisories or copyleft licences |
| `pr-title.yml` | PR | Conventional Commits title check |
| `release.yml` | tag `v*` | the release; see RELEASING.md |
| Dependabot | weekly | Go modules, action pins, Docker base image |

Every third-party action is pinned to a full commit SHA (with the version in a comment); Dependabot moves the
pins. Workflows request the least token permission each job needs.

## First push

Nothing has been pushed yet. Do this once, in order:

1. **Create the empty repository** on GitHub (no README/licence/gitignore: they already exist). Name:
   `cipherhorizon`.
2. **Set the owner**: `scripts/set-owner.sh <github-username>`, then `go build ./... && go test ./...` and
   `git diff --stat`. This rewrites the module path, the release linker flags, doc links and `CODEOWNERS`.
   Set the security contact in `SECURITY.md` (it still has a placeholder).
3. **Commit the work in reviewable slices** rather than one dump (the working tree currently holds the
   rename from `cbom-scan`, the TLS scanner, evaluation, the server/UI and this release tooling on top of a
   single earlier commit). A sensible order, each slice building and passing tests on its own:
   1. `chore: rename cbom-scan to CipherHorizon` (module, binary, docs)
   2. `feat(tlsprobe): active TLS scanner with generated IANA registries`
   3. `feat(eval): cited findings, PQC readiness and TLS hygiene`
   4. `feat(server): scan runner, SQLite store, JSON API`
   5. `feat(web): posture workbench UI`
   6. `feat(cbom): TLS endpoint CBOM export, evidence tiers, mTLS and HSTS checks`
   7. `ci: release engineering (GoReleaser, signing, container image, Dependabot, CodeQL)`
   8. `docs: product, QA and engineering documentation`
   Commit with `-s` for the DCO. (If slicing is more effort than it is worth for an initial import, one
   `chore: initial public import` commit is acceptable; the history from then on is what matters.)
4. **Decide what not to publish.** `artifacts/` is a QA hand-off bundle (33 screenshots, logs, duplicated
   copies of `docs/product`); `docs/product` is the canonical copy. Prefer `git rm -r --cached artifacts`
   before the first push, since screenshots and logs re-generate from `testing/e2e` and duplicated docs rot.
5. `git remote add origin git@github.com:<owner>/cipherhorizon.git && git push -u origin main`.
6. **Apply the settings and rulesets above.** The required checks only become selectable after CI has run once,
   so push, let CI run, then turn the rules on.
7. Turn on GitHub Pages only if a docs site is wanted later (not needed for 0.1).
8. **Cut v0.1.0** by following [RELEASING.md](RELEASING.md).

## Moving to an organisation later

Transfer the repository (Settings → Danger zone). GitHub redirects the old web and git URLs, but Go module
paths and container image names do not redirect: run `scripts/set-owner.sh <org>` and ship the change as a
minor release (`0.x` permits it; after 1.0 it would be a `v2` module path decision). Keep the personal-account
image tags available for one release cycle.
