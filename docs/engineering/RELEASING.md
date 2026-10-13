# Releasing

How a version of CipherHorizon is numbered, cut, built, signed and published. The release is automated;
this page is what the maintainer does around the automation.

## Versioning policy

[Semantic Versioning 2.0.0](https://semver.org/), tags `vMAJOR.MINOR.PATCH`, with an optional pre-release
suffix (`v0.2.0-rc.1`).

What "the public interface" is, for this project (a change to any of these is what SemVer counts):

- the **CLI**: command names, flags, exit codes;
- the **JSON API** under `/api/v1` and the **report/CBOM/evaluation schema versions** it emits;
- the **database**: a migration that cannot run on the previous release's file is breaking;
- **scoring and classification** are *not* a stable interface: readiness levels, hygiene weights and finding
  sets change whenever the cited standards do (see `docs/methodology.md`). Such changes are always listed in
  the changelog under "Changed" so nobody is surprised by a score moving.

The Go packages are under `internal/` and are not a public API.

### The 0.x series (where this project starts)

`0.y.z` means *initial development*: anything may change at a minor release. First release: **`v0.1.0`, flagged
"Pre-release"** on GitHub. While in 0.x:

| Change | Bump |
|---|---|
| new feature, or a breaking change to CLI / API / schema / database | minor (`0.1.0` → `0.2.0`) |
| bug fix, security fix, docs, dependency updates | patch (`0.1.0` → `0.1.1`) |

Breaking changes in 0.x still get a `!` in the PR title and a **Breaking** note in the changelog.

### 1.0.0 criteria

Cut 1.0.0 (drop the pre-release flag, start honouring "minor = backwards compatible") when all hold:

1. the CLI flags, `/api/v1` and the schema versions have gone two minor releases without a breaking change;
2. the database migration path is tested from every released version;
3. an OpenAPI description of `/api/v1` exists and is tested against the server;
4. a written threat model for the server (SSRF guard, auth, CSRF, the wire parsers) exists and has been reviewed
   by someone other than its author;
5. at least one real-world validation against a non-hermetic TLS stack matrix (nginx, Apache, OpenSSL 3.5,
   Postfix) has been recorded in the QA report.

### After 1.0

| Change | Bump |
|---|---|
| breaking change to CLI / API / schema / database | major |
| new backwards-compatible feature | minor |
| fix | patch |

Pre-releases (`-rc.N`) are published from `main` before a major or a risky minor; they are marked pre-release
and do not move `latest`.

### Where the version lives

Only in the **git tag**. There is no version constant to edit: the release build stamps it into the binary
(`internal/version`, `-ldflags -X`), together with the commit and commit date. `cipherhorizon version` prints
them; the container image, the CBOM's `metadata.tools` entry, `/api/v1/about` and the UI sidebar all read it.
A build from a checkout without the stamp reports `0.0.0-dev`; `go install …@v0.1.0` reports the module version.

## Cadence and support

- No fixed schedule. Release when `## [Unreleased]` holds something a user would want, or a security fix.
- **Supported version: the latest release** (and, after 1.0, the latest minor of the previous major for
  security fixes only). Older ones get no fixes; upgrade.
- Security fixes are released as a patch as soon as they are ready, with an advisory (Security tab).

## Cutting a release

Prerequisites: you are a maintainer; `main` is green; Actions are enabled; you have run
`scripts/set-owner.sh` if this is the first release.

1. **Decide the version** from the changelog entries and the tables above.
2. **Prepare the changelog** on a branch:
   ```sh
   git switch main && git pull && git switch -c chore/release-0.1.0
   scripts/prepare-release.sh 0.1.0        # turns [Unreleased] into [0.1.0] - <today>, fixes compare links
   ```
   Read the section critically: users read it, and it becomes the release notes. Every user-visible change,
   every changed default, every new flag; **Security** and **Breaking** items first. Also confirm `SECURITY.md`
   "Supported versions" is right.
3. **Open a PR** titled `chore(release): 0.1.0`. CI runs (including the GoReleaser and container dry run).
   Merge (squash).
4. **Rehearse locally** (optional, needs `goreleaser`): `make snapshot` builds all six archives into `dist/`
   without publishing; run one: `dist/cipherhorizon_linux_amd64_v1/cipherhorizon version`.
5. **Tag the merged commit and push the tag:**
   ```sh
   git switch main && git pull
   git tag -s v0.1.0 -m "CipherHorizon 0.1.0"     # -s signs the tag; use -a if you have no signing key
   git push origin v0.1.0
   ```
   Tags are immutable once pushed: if step 5 is wrong, ship a new version, do not move the tag.
6. **Watch `release.yml`** (Actions tab). It runs, in order:
   1. `verify` — tag is SemVer, is on `main` (or `release/*`), and CHANGELOG has notes for it;
   2. `ci` — the full CI suite again on the tagged commit;
   3. `binaries` — GoReleaser builds six archives (linux/darwin/windows × amd64/arm64), `checksums.txt`,
      an SBOM per archive, a **keyless cosign signature** of the checksums and a **build-provenance
      attestation**; everything is uploaded to a **draft** release;
   4. `image` — multi-arch (amd64, arm64) container image to GHCR, signed by digest, with provenance and SBOM;
   5. `publish` — only when 3 and 4 succeeded: the draft is published. `0.x` and `-rc` versions are marked
      **Pre-release** and do not become "latest".
7. **Verify** the published release exactly as a user would (commands in [DISTRIBUTION.md](DISTRIBUTION.md#verifying-a-download)),
   and start the binary: `cipherhorizon version` shows the tag, the commit, and the build date.
8. **Announce**: nothing to do for 0.1.0 beyond the release page; for later releases, link the changelog.

### If the workflow fails

The release is a *draft* until the last job, so a failure leaves nothing public.

- Fix the cause on `main` (workflow bug, flaky test).
- **Re-run the failed jobs** from the Actions UI if the tag's commit is still what you want to release. A
  re-run of `binaries` replaces the existing draft (`replace_existing_draft`).
- If the tagged commit itself must change, the tag was never published: delete the tag (`git push --delete
  origin v0.1.0` + `git tag -d v0.1.0`) **only if no release was made public**, fix, and tag the new commit.
  If a release was public, publish `v0.1.1` instead.
- The image job is idempotent per tag; re-running it re-pushes the same tags.

### The container package on GHCR: do not delete untagged versions

One release puts about nine versions in the `cipherhorizon` package, and only the multi-arch index carries the
version tag (`0.1.0`, `latest`). The untagged ones are that image: the linux/amd64 and linux/arm64 images, the
SBOM and provenance attestation for each, the cosign signature and the GitHub provenance attestation (Sigstore
bundles), and the index of what is attached (tagged `sha256-<digest>`). Deleting untagged versions leaves a tag that
points at nothing (`manifest unknown` on pull) and an image that no longer verifies. That happened to v0.1.0
on 2026-10-13; re-running the release's image job re-pushed it. To remove an old image, delete its tagged index
only, and only for a version nobody should pull.

### Patching an older release

Only when `main` has moved on and the fix cannot ship with the next minor.

```sh
git switch -c release/0.1 v0.1.0
git cherry-pick -x <fix-commit-on-main>       # fix on main first, always
scripts/prepare-release.sh 0.1.1             # add the entry under [Unreleased] first
# PR into release/0.1 (same checks), merge, then:
git tag -s v0.1.1 -m "CipherHorizon 0.1.1" && git push origin v0.1.1
```
`release/*` branches get the same ruleset as `main`. Copy the changelog entry back to `main` so it lists the
patch too.

### Withdrawing a release

Never delete a published release or tag (it breaks people's pinned versions and `go` module proxy caches).
Mark it **Yanked** at the top of its release notes, add a `### Yanked` note in `CHANGELOG.md`, publish a fixed
patch, and if it is a vulnerability publish a GitHub Security Advisory.

## Checklist (paste into the release PR)

- [ ] `main` is green, no open PR I intend to include is waiting
- [ ] Version chosen by the rules above: `___`
- [ ] `scripts/prepare-release.sh` run; CHANGELOG section read and complete, Breaking/Security first
- [ ] `SECURITY.md` supported-versions text is current
- [ ] README install instructions match reality for this version
- [ ] Merged; tag created on the merge commit and pushed
- [ ] `release.yml` green through `publish`
- [ ] Downloaded an archive from the release page, verified checksum + signature + attestation, ran `version`
- [ ] Pulled the container image, verified the signature, ran it
- [ ] Any follow-up issues opened for things found while releasing

## What can go wrong here, and why the pipeline is shaped this way

| Risk | Control |
|---|---|
| Tagging something that never passed CI | `verify` requires the tag on `main`; `ci` re-runs on the tagged commit before anything is built |
| A half-published release | GoReleaser only creates a **draft**; `publish` runs last |
| Tampered or swapped artifacts | signed `checksums.txt` (Sigstore, tied to this repo's workflow identity, no long-lived key), provenance attestation, signed image digest |
| A secret leaking from CI | there are none: signing and registry login use the job's short-lived OIDC/`GITHUB_TOKEN` |
| Poisoned build tooling | actions pinned to commit SHAs (Dependabot updates them by PR), least-privilege `permissions:` per job |
| A version-number mistake in the binary | the version comes from the tag only, never from a file |
| Non-reproducible artifacts | `-trimpath`, `CGO_ENABLED=0`, commit-time timestamps, pinned Go from `go.mod` (latest patch of that minor) |
| Vulnerable dependency shipped | `govulncheck` gates CI, `dependency-review` gates PRs, Dependabot opens fixes |
