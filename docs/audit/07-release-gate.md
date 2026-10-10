# 07 · Release gate

**Role:** Release manager. **Decision: ready to commit as 0.1.0 (pre-release). Not ready to publish.**

## Version

- `CHANGELOG.md`: `[Unreleased]` was cut into **`[0.1.0] - 2026-09-24`** with `scripts/prepare-release.sh 0.1.0`; a fresh
  empty `[Unreleased]` follows it and the compare links were updated.
- The version number in a binary comes from the tag through the linker (`internal/version`), not from a file, so
  nothing else needs editing. A build from a checkout without a tag still reports `0.0.0-dev`.
- Policy: `0.x`, first release a pre-release ([RELEASING.md](../engineering/RELEASING.md)).

## What must be true before the tag is pushed (none of it is done here)

| Item | Status | Owner |
|---|---|---|
| Replace the placeholder owner: `scripts/set-owner.sh <github-username>` | **open** | repository owner |
| Set the security contact in `SECURITY.md` | **open** | repository owner |
| Create the repository, push, let CI run (Windows/macOS/Linux tests, POSIX file-mode tests, CodeQL, release dry run) | **open** | repository owner |
| Decide whether the tracked `artifacts/` bundle stays (33 screenshots regenerate on every E2E run) | **open** | repository owner |
| Tag `v0.1.0` from `main` after CI is green and push it | **open** | repository owner |
| Run the collector on a Linux host and from an elevated Windows shell (`testing/hostdiscovery`) | **open**, stated as *not validated* in the release notes | repository owner |

## Evidence

See [06-qa-report.md](06-qa-report.md). A GoReleaser snapshot of a tagged scratch copy built all twelve archives and
stamped the version.

## Known limitations carried into the notes

Linux and Administrator collector runs unvalidated; macOS unsupported; release pipeline never executed; module
owner and security contact are placeholders; single shared token; per-asset (not per-instance) storage bound.

## Commit

One commit on `main`: `feat: audit of security and usability, guided first run, inventory coverage, 0.1.0 changelog`,
with DCO sign-off. **Not pushed, not tagged**: tagging belongs after the repository exists and CI is green
(RELEASING.md), and a local tag would only invite publishing something that has not been through CI.
