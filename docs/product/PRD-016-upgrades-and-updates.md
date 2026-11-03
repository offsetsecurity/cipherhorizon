# PRD-016: Upgrades and updates

**Status:** Phase 0 built 2026-10-24 (branch `feat/upgrade-safety`, see §10 "As built"); Phases 1–3 and
decisions D1–D7 open
**Roles:** architect, product, build and release engineering
**Scope:** how a CipherHorizon install learns about, gets, and safely applies a new version, on every
channel (Docker/Podman, Linux packages, Windows service, macOS, bare binary) and from any older version.

---

## 1. The problem in one paragraph

We ship often (0.1.0 → 0.4.0 in nine days). Every install is self-hosted and holds an organisation's only
copy of its scan history in one SQLite file. Today an operator must notice a release on their own, upgrade
by hand with a different procedure per platform, and trust that the database migrates. Nothing tests that a
database made by a *released* version upgrades cleanly, nothing stops two versions touching one file, and
there is no tested way back. As the user base grows, people will skip versions, run old collectors against
new servers, and upgrade unattended. This PRD makes all of that boring and safe.

## 2. What already exists (audited 2026-10-24)

Good foundations; the plan builds on them rather than replacing them.

| Area | Today | Where |
|---|---|---|
| Schema migrations | Ordered list of SQL steps, one transaction each, optional Go back-fill in the same transaction; version recorded in `schema_migrations` | `internal/store/store.go` `migrations`, `postMigrations`, `migrate()` |
| Skipping versions | Already works in principle: the binary runs every missing step in order, so 0.1.0 → 0.4.0 runs step 15 only; an older file runs all it lacks | same |
| Newer database | Refused with a clear error ("schema version N is newer than this program understands") | `migrate()` |
| Pre-migration backup | `VACUUM INTO <db>.bak-v<schema>-<time>`, owner-only, newest 3 kept; if the backup fails nothing is changed | `internal/store/systems.go` `backup`, `pruneBackups` |
| Frozen migrations | A test pins the SHA-256 of migrations **1–3 only** | `internal/store/graph_test.go` `TestFrozenMigrationsAreUnchanged` |
| Legacy data tests | Hand-built legacy databases, failed migration leaves the file intact | `graph_test.go`, `migrate_test.go`, `bands_test.go` |
| Stored report formats | Versioned (`tls-report/1`, `tls-report/2`, `ssh-report/1`); old shapes are still read | `internal/tlsprobe/report.go`, `internal/server/ssh.go` |
| Release | Tag → GoReleaser archives, deb/rpm, SBOMs, cosign-signed checksums, provenance; GHCR image signed by digest | `.goreleaser.yaml`, `.github/workflows/release.yml` |
| Upgrade docs | One table per channel; "0.x releases do not promise a downgrade path" | `docs/engineering/INSTALL.md#upgrading` |
| Update awareness | Deliberately none: "No telemetry, no update check, no external requests at runtime" | `docs/engineering/DISTRIBUTION.md` |

Schema version shipped per release (counted from each tag):

| Release | Schema |
|---|---|
| v0.1.0, v0.1.1, v0.2.0, v0.3.0 | 14 |
| v0.4.0 | 15 |

### Gaps found

| # | Gap | Risk |
|---|---|---|
| G1 | Frozen-migration test pins 1–3, but 0.1.0 shipped 14 and 0.4.0 ships 15. Steps 4–15 can be edited silently. | An edited released step never re-runs on existing installs: fresh and upgraded databases drift apart. |
| G2 | No test opens a database **produced by a real released binary**. Legacy fixtures are hand-made. | A back-fill that works on synthetic data fails on real data at a customer. |
| G3 | No check that "fresh install at HEAD" and "upgraded from vX" give the same schema. | Silent drift (a missing index, a column default) shows up months later. |
| G4 | No guard against two processes on one database (old container still running, `serve` in a terminal while the service runs, two pods on one volume). | Two versions migrating or writing at once. |
| G5 | Backup does not check free disk space first; `VACUUM INTO` needs about the database's size again. | Upgrade fails at start on a full disk, service flaps. (The file is safe: nothing is changed.) |
| G6 | Restore is four manual steps (stop, copy, delete `-wal`/`-shm`, start). | The step people get wrong under pressure. |
| G7 | Windows `service install` refuses when the service exists; upgrade is "stop, copy exe, start", and the service's flags are only changed by uninstall/install. | Error-prone, not scriptable, flags lost. |
| G8 | Containers: only immutable `X.Y.Z` tags, no "latest" before 1.0, nothing wired for unattended updates. | Container users never upgrade, or use `:latest` from somewhere unofficial. |
| G9 | No APT/YUM repository, Homebrew tap, Scoop bucket or winget manifest: every platform upgrade is a manual download. | Low uptake of security fixes. |
| G10 | No way for a running server to tell the operator a newer or security release exists. | Old, vulnerable installs in the field. |
| G11 | Bundled reference data (root stores, CT logs, distrusted keys) only refreshes with a release; there is no scheduled refresh. | Results go stale even when nobody changes code. |
| G12 | No written skew policy between server and collector, or for `/api/v1` clients and CLI flags. | Fleets break silently when the server moves ahead of collectors. |
| G13 | UI assets are served at fixed URLs (`/style.css`, `/js/app.js`) with no versioned path or cache policy. | After an upgrade a browser can combine old JavaScript with the new API (to verify; low risk today). |

## 3. How mature open-source projects do it (what we take, what we skip)

| Project | Practice | Take for us? |
|---|---|---|
| **GitLab** | "Required upgrade stops": certain versions must be installed before later ones so background migrations finish; stops announced two milestones ahead; the project actively works to *avoid* adding stops ([upgrade docs](https://archives.docs.gitlab.com/17.2/ee/update/index.html), [avoiding required stops](https://docs.GitLab.com/ee/development/avoiding_required_stops.html)) | Take the *discipline* (stops are a cost; announce them early). We avoid stops entirely before 2.0 because our migrations are small and synchronous. |
| **Mattermost** | Migrations backwards-compatible only to the last ESR; skip-upgrades go ESR → ESR ([release policy](https://docs.mattermost.com/product-overview/release-policy.html), [common ESR upgrade](https://docs.mattermost.com/product-overview/common-esr-support-upgrade.html)) | Take "the tested path is what we promise", and test it in CI. No ESRs yet. |
| **Forgejo / Gitea** | Single binary migrates on start; `doctor check --all` after upgrade; backup first ([Forgejo upgrade guide](https://forgejo.org/docs/latest/admin/upgrade/)) | Take: a `db check` / doctor command, run automatically after migrating. |
| **Syncthing** | Opt-out auto-upgrade; each binary has a signature made with a release key whose public half is compiled in; mismatch aborts and deletes temp files; disabled in distro packages ([release signing](https://docs.syncthing.net/dev/release-signing.html)) | Take the model for self-update of bare/Windows/macOS installs, and "packages and containers never self-update". |
| **Grafana, Home Assistant** | SQLite + migration log table, automatic backup before upgrade, refuse newer schema | Already matched. |
| **Tailscale, Caddy** | `tailscale update` / `caddy upgrade` command that knows how it was installed and does the right thing per channel | Take: one `cipherhorizon upgrade` that dispatches by install channel. |
| **Podman Quadlet** | `AutoUpdate=registry` + `podman-auto-update.timer`; rolls the container back if the new one fails to start | Take: the most robust unattended path we can offer for free. |
| **Watchtower / Diun / Renovate** | Container users pick their own update agent, keyed on tags | Support by publishing sensible floating tags; document, don't build. |
| **Kubernetes** | Explicit version-skew policy (components N-1/N-2) | Take for server ↔ collector and for API clients. |
| **Rails / Django / expand-contract** | Additive change first, destructive change only after the code stopped using it | Take as the migration rule set (§5.2). |
| **SQLite itself** | File format carries a write-version / read-version so old readers know if they may write | Take for the downgrade window (§5.5). |

## 4. Principles

1. **Any released version upgrades straight to the latest, in one step, on every channel.** No required
   stops before 2.0. This is a promise, so it is tested in CI from every released version (§6).
2. **The binary is the migrator.** No separate migration tool, no SQL scripts for operators. Starting the new
   version is the upgrade; `db migrate` exists only for people who want the step explicit.
3. **Never lose data, never half-migrate.** Back up first, one transaction per step, verify afterwards, refuse
   to start rather than run on a doubtful file.
4. **The package manager or orchestrator owns the binary when there is one.** `apt`, `dnf`, `brew`, `scoop`,
   `winget`, the container runtime. CipherHorizon self-updates only where nothing else does (bare archive,
   Windows service from the zip, macOS launchd from the tarball).
5. **Notify by default, apply only when asked.** A scanner in a security team's estate must not change itself
   without consent. Unattended updates are opt-in per channel.
6. **Privacy stays.** Any update check is a single anonymous GET of a public signed file, can be turned off,
   and works offline by importing the file. No telemetry, no install ID.
7. **One procedure, one vocabulary, every platform.** The same five steps (§7) and the same commands; only the
   tool that swaps the binary differs.

## 5. Database: schema changes that cannot break an upgrade

### 5.1 Mechanics (mostly in place, tightened)

At start, `store.Open`:

1. Takes the **instance lock** (new, G4): an OS file lock on `<db>.lock` (`flock` on Unix, `LockFileEx` on
   Windows, both available without cgo). A second process gets "another CipherHorizon (pid N, version X) is
   using this database" and exits non-zero. This also covers a container recreated before the old one stopped.
2. Reads `schema_migrations`. Newer than known → refuse (exists). Equal → continue.
3. **Checks free space** (new, G5): needs at least `1.2 × database size` free in the backup folder, or refuses
   with the number of bytes needed. Nothing changed.
4. Backs up with `VACUUM INTO` (exists), records the backup in a new `upgrade_log` table row (from-version,
   to-version, from-schema, to-schema, backup path, started, finished, result).
5. Runs each missing step in its own transaction (exists).
6. **Verifies** (new): `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, and the schema fingerprint check
   (§5.4). Failure → restore the backup automatically, log why, refuse to start. The operator sees one
   message with the backup path and the command to report it.
7. Writes the finished row in `upgrade_log`; the About page shows "Upgraded from 0.3.0 to 0.5.0 on …".

### 5.2 Rules every migration follows (enforced in review and CI)

| Rule | Why | Enforced by |
|---|---|---|
| A released migration is never edited, reordered or removed. Fix forward with a new step. | Existing installs never re-run an edited step. | `migrations.lock` (§6.1) checked in CI |
| Additive changes only in a minor release: new table, new nullable column or column with a default, new index. | An older binary can still read the file (enables §5.5). | Review checklist; `compat` flag per step |
| Destructive changes (drop/rename column, change meaning) follow **expand → migrate → contract** across at least two releases: add the new column and write both; back-fill; stop reading the old one; drop it in a later release. | Rollback stays possible for one release. | Review; the step is marked `breaksOlder: true` |
| Go back-fills (`postMigrations`) use only code frozen with them: local SQL, local copies of any helper. Never call today's store or evaluation code. | Today's code changes; a back-fill must behave the same in 2028 as it did on release day. | Lint rule: a `postMigrations` func may not import `internal/eval`, `internal/server` etc. (archtest) |
| A back-fill that touches every row of a large table runs in batches inside its transaction and logs progress. | Big estates; visible progress instead of a "hung" start. | Review |
| Stored report JSON is never rewritten by a migration. New report shapes get a new `schemaVersion`; readers keep reading old ones (as `tls-report/1` today). | Evidence stays as observed; scoring changes are re-evaluation, not data rewrite. | Existing pattern, now written down |
| Every schema change adds an **Upgrade notes** entry to `CHANGELOG.md`. | Operators see what will happen before they upgrade. | CI: if `migrations` changed, `## [Unreleased]` must contain `### Upgrade notes` |
| SQLite feature use stays within the bundled `modernc.org/sqlite` version; bumping it is a release-notes item. | `RENAME COLUMN`, `DROP COLUMN` etc. depend on the engine version. | Dependency review |

### 5.3 Skipping versions

Because every step is ordered and self-contained, 0.1.0 → 1.4.0 simply runs every step between them in order,
with one backup at the start. We guarantee this until 2.0. If one day a migration genuinely needs an
intermediate release (for example a long background job), we follow GitLab's rule: announce the required stop
at least two minor releases ahead, and the newer binary refuses older schemas with "upgrade to 1.9 first" and a
link, never a cryptic SQL error. At 2.0 we may **squash** steps 1..N into one baseline; from then on 2.x opens
databases from the last 1.x and later only. That decision is recorded in the release manifest as
`minUpgradeFrom` (§8.2) so the update check can warn before anyone downloads.

### 5.4 Fresh equals upgraded

New test (G3): for every released schema `S`, open the fixture from §6.2, migrate to HEAD, dump
`sqlite_master` (tables, columns, indexes, triggers, normalised) and compare with a fresh HEAD database. Any
difference fails CI. The fingerprint of HEAD's schema is compiled into the binary and checked at step 6 of
§5.1, so a hand-edited database in the field is caught too.

### 5.5 Going back (downgrade window)

Today: restore the pre-migration backup. Plan:

- **`cipherhorizon db restore <backup>`** (G6): stops nothing on its own, refuses if the instance lock is held,
  checks the backup's integrity, moves the current file aside (`.replaced-<time>`), puts the backup in place and
  removes stale `-wal`/`-shm`. Works the same on every OS and inside a container (`docker run --rm -v
  data:/data image db restore …`).
- **Compatibility floor** (P2, before 1.0): the database records `compat_floor`, the oldest schema whose binary
  may still open it. Additive steps leave it alone; a `breaksOlder` step raises it. An older binary may open a
  newer file when its own schema ≥ `compat_floor`, ignoring tables and columns it does not know. Result: a patch
  or a purely additive minor can be rolled back by just running the old binary, no restore, no lost scans. This
  is SQLite's own read/write-version idea applied to our schema.
- After 1.0 the promise is: **rollback by binary to the previous minor works unless the release notes say
  otherwise; rollback by backup always works.**

### 5.6 Operator commands (all platforms, same words)

| Command | Does |
|---|---|
| `cipherhorizon db status` | Schema version, what this binary would run, compat floor, backups present, last upgrade |
| `cipherhorizon db migrate [--dry-run]` | Runs (or lists) pending steps explicitly, with the same backup and checks |
| `cipherhorizon db check` | Integrity, foreign keys, schema fingerprint (Forgejo `doctor` equivalent) |
| `cipherhorizon db backup <file>` | Exists |
| `cipherhorizon db restore <file>` | New, §5.5 |
| `serve --migrate=auto\|refuse` | `auto` (default) migrates at start; `refuse` exits with "run `db migrate`" for change-controlled shops |

## 6. Release engineering: proving every upgrade path before release

### 6.1 Lock the migrations (G1)

Replace the 1–3 hash map with `internal/store/migrations.lock`: one line per released step, `N sha256`.
`scripts/prepare-release.sh` appends the new steps when cutting a release. CI fails if a locked step's hash
changes or a locked step disappears. Unreleased steps (above the last release) may still be edited freely.

### 6.2 Golden databases from real releases (G2)

For each release, the release workflow runs the **released binary** against the hermetic demo targets
(`demo-targets`) and a scripted scenario — TLS and SSH scans, an imported inventory, a system, a triaged
finding, an account with sign-in on, settings changed — then `db backup`s the result into
`testdata/upgrade/v<version>.db` (small, synthetic, no secrets beyond test hashes). A bot PR commits it. Seed
the set now by running v0.1.0, v0.2.0, v0.3.0 and v0.4.0 from their published archives.

### 6.3 The upgrade matrix (release gate)

A CI job, required on `main` and on every release PR:

| Check | From | To |
|---|---|---|
| Direct upgrade opens, migrates, passes `db check`, row counts and key values preserved | every `testdata/upgrade/*.db` | HEAD |
| Fresh equals upgraded (§5.4) | every fixture | HEAD |
| Chained equals direct: v0.1 → v0.2 → … → HEAD gives the same schema and data as v0.1 → HEAD | oldest fixture | HEAD |
| Newer schema refused cleanly | HEAD-migrated file | previous release binary |
| Compat-floor rollback (once §5.5 lands) | HEAD-migrated file | previous release binary, opens and serves |
| Failed step leaves the file intact (exists) | fixture + injected failure | HEAD |
| Server UI and API smoke on the upgraded file (journey checks) | newest fixture | HEAD |

The last released binary for each OS is downloaded once per CI run from GitHub Releases and its checksum
verified, so the "old binary" rows run the real thing.

### 6.4 Per-channel upgrade smoke (nightly, and before each release)

| Channel | Test |
|---|---|
| deb | Debian container: install previous `.deb`, enable service, seed, `apt install ./new.deb`, assert service restarted, schema migrated, data present, `/etc/cipherhorizon/env` kept |
| rpm | Same on Rocky/Fedora with `dnf` |
| Container | `docker run` previous tag on a volume, seed, recreate with new tag, health check passes, data present; same with Podman Quadlet `AutoUpdate` |
| Windows service | `windows-latest` runner: `service install` previous zip, seed, `cipherhorizon upgrade --from-file new.zip` (§7.3), service running, data present, flags kept |
| macOS | `macos-latest` runner: launchd agent with previous tarball, upgrade, agent running, data present |
| Self-update | Each runner: point the update check at a local signed test manifest; corrupt signature → refused; broken new binary → rolled back |

### 6.5 Release artefacts added

- `releases.json` manifest (§8.2), signed like `checksums.txt`.
- `UPGRADING.md` section generated from the changelog's **Upgrade notes**, included in release notes.
- Floating container tags (§7.1).
- Brew formula, Scoop manifest, winget manifest, APT/YUM repository update (§7.2).

### 6.6 Scheduled data refresh (G11)

A monthly scheduled workflow regenerates `internal/refdata` from CCADB, the CT log list and the distrust
list, runs the tests, and opens a PR. Merging it is a patch release (`0.4.1`: "reference data refreshed"). This
turns stale-data risk into a routine, low-risk upgrade and keeps people in the habit of upgrading.

## 7. Per-platform: one procedure, each channel's own tool

Every channel follows the same five steps: **learn → fetch → verify → swap → check** (and roll back if the
check fails). The table says who does each step.

| Channel | Learn of a release | Upgrade (manual) | Unattended (opt-in) | Verify | Roll back |
|---|---|---|---|---|---|
| **Docker / Compose** | UI banner (§8); Diun/Renovate on tags | `docker compose pull && docker compose up -d` | Watchtower or Renovate on the `0.4` / `0` tag | `cosign verify` by digest (documented); image signed | Re-run the previous tag; DB rollback by compat floor or `db restore` |
| **Podman Quadlet** | UI banner | change tag, `systemctl restart` | `AutoUpdate=registry` + `podman-auto-update.timer` (ships commented in `deploy/cipherhorizon.container`) | registry signature policy (`policy.json` sigstore) documented | **Automatic**: Podman rolls back when the new unit fails health |
| **Debian / Ubuntu** | `apt list --upgradable`; UI banner | `sudo apt update && sudo apt upgrade` | `unattended-upgrades` with our origin allowed | repo signed (GPG key published; packages also listed in signed `checksums.txt`) | `apt install cipherhorizon=<old>`; DB as above |
| **RHEL / Fedora / SUSE** | `dnf check-update`; UI banner | `sudo dnf upgrade cipherhorizon` | `dnf-automatic` | repo `gpgcheck=1` | `dnf downgrade`; DB as above |
| **Windows (service)** | UI banner; `winget upgrade` list | `winget upgrade OffsetSecurity.CipherHorizon` / `scoop update cipherhorizon`, or `cipherhorizon upgrade` | `cipherhorizon upgrade --schedule` registers a weekly task, off by default | checksum + signature verified by the binary itself (§8.3); Authenticode signing later | automatic on failed health (§7.3); `cipherhorizon upgrade --rollback` |
| **macOS** | UI banner; `brew outdated` | `brew upgrade cipherhorizon` (tap), or `cipherhorizon upgrade` for the tarball install | `brew autoupdate` (user's choice) or `cipherhorizon upgrade --schedule` (launchd) | as Windows; notarisation later | as Windows |
| **Bare binary** (any OS) | UI banner; `cipherhorizon version --check` | `cipherhorizon upgrade` | none (it is someone's terminal) | as Windows | keeps `cipherhorizon.old` next to it |
| **Collector on endpoints** | server shows "N collectors older than the supported window" | fleet tooling (Intune, SCCM, Ansible, Jamf) using the server's own `/api/v1/collector/binaries` | fleet tooling | SHA-256 listed by the server and in `checksums.txt` | fleet tooling |

### 7.1 Containers

- Publish `X.Y.Z` (immutable, what docs pin), **`X.Y`** (patch releases, safe to follow) and, from 1.0, `X` and
  `latest`. Before 1.0 publish `0.4` style tags only; that keeps "no latest before 1.0" while letting
  Watchtower/Quadlet follow patch fixes.
- Never two containers on one volume: the instance lock (§5.1) makes this an error instead of corruption; the
  docs say `Recreate`, not rolling update, for any orchestrator (and a future Helm chart sets
  `strategy: Recreate`, one replica).
- Migration runs inside the container at start; the backup lands in the volume, so it survives the container.
- Pre-migration backups count against volume size; `db status` shows it.

### 7.2 Package channels to add (G9)

| Channel | How | Cost |
|---|---|---|
| Homebrew tap `offsetsecurity/homebrew-tap` | GoReleaser `brews` (or `homebrew_casks`) | one repo + token |
| Scoop bucket `offsetsecurity/scoop-bucket` | GoReleaser `scoops` | one repo + token |
| winget | GoReleaser `winget` (opens PR to `microsoft/winget-pkgs`) | review latency; fine before 1.0 if marked pre-release-free versions only — **owner decision** |
| APT + YUM repository | Option A: Cloudsmith OSS (free for open source, signed, hosted). Option B: self-host on GitHub Pages, signed by a repo key, built in `release.yml` with `aptly`/`createrepo_c`. | A: none; B: a GPG key to guard — **owner decision** |
| Chocolatey | later | moderation queue |

### 7.3 Windows service and the bare binary: `cipherhorizon upgrade` (G7)

- `service install` on an existing service becomes **upgrade in place**: stops it, replaces
  `C:\Program Files\CipherHorizon\cipherhorizon.exe`, keeps the recorded flags unless new ones are given, starts,
  health-checks. `service reconfigure <flags>` changes flags without reinstalling.
- `cipherhorizon upgrade [--to X.Y.Z] [--from-file archive]`:
  1. reads the install channel stamped at build time (`-X version.Channel=archive|deb|rpm|container|brew|scoop|winget`)
     and, for anything but `archive`, prints the right command for that channel and exits (Tailscale/Caddy model);
  2. fetches the manifest and the archive for this OS/arch, verifies (§8.3);
  3. `db backup` to the data folder;
  4. Windows: stops the service, renames the running exe to `cipherhorizon.old.exe` (a running exe can be renamed,
     not overwritten), puts the new one in place, starts; Unix: atomic rename, restart the launchd agent /
     systemd unit if it runs;
  5. waits up to 60 s for `/api/v1/health`; on failure puts the old binary back, restores the backup **only if a
     migration ran**, starts the old one, and reports what happened;
  6. records the result in `upgrade_log`.
- Requires administrator on Windows (service) and write access to the binary elsewhere; says so up front.

## 8. Knowing an update exists (G10)

### 8.1 Behaviour

- **Owner decision:** default **on with disclosure** (recommended; Syncthing, Grafana, Gitea do this) or **off**.
  Either way: Settings → Updates shows the state, a `--update-check=off` flag and `CIPHERHORIZON_UPDATE_CHECK=off`
  turn it off, and air-gapped sites can import a downloaded `releases.json`.
- Once a day the server GETs one static file (`https://offsetsecurity.github.io/cipherhorizon/releases.json`, or
  the release asset), with no cookies, no identifiers, a fixed `User-Agent: CipherHorizon` (no version, so the
  request carries nothing about the install).
- The UI shows a quiet banner to administrators: "0.5.0 is available" — and a red one for "security fix", with
  the one command for *this* install's channel (from §7.3 step 1) and a link to the upgrade notes.
- `cipherhorizon version --check` does the same from the command line, for scripts and monitoring (exit code 10
  when an update exists, 11 when a security update exists).

### 8.2 `releases.json` (signed)

```json
{
  "schema": "cipherhorizon-releases/1",
  "latest": "0.5.0",
  "releases": [
    {
      "version": "0.5.0",
      "date": "2026-11-05",
      "security": false,
      "dbSchema": 17,
      "minUpgradeFrom": "0.1.0",
      "compatFloor": 15,
      "collectorMin": "0.3.0",
      "notes": "https://github.com/offsetsecurity/cipherhorizon/releases/tag/v0.5.0",
      "upgradeNotes": ["Adds an index on scans(asset_id, started); first start takes a few seconds on large databases."]
    }
  ]
}
```

Generated by `release.yml` from the tag, the migration lock and the changelog, never by hand.

### 8.3 Verifying what we download

Two options, **owner decision**:

- **A. Sigstore keyless (recommended):** verify `checksums.txt.sigstore.json` with `sigstore-go`, pinned to the
  identity `https://github.com/offsetsecurity/cipherhorizon/.github/workflows/release.yml@refs/tags/v*` and the
  GitHub OIDC issuer. Same trust as today's manual verification; no key to keep. Cost: a sizeable dependency and
  a trusted-root file that must be refreshed (ship it in the binary, refresh in the monthly data PR).
- **B. Release key (Syncthing model):** an Ed25519 key held as a GitHub Actions secret signs `checksums.txt` and
  `releases.json`; its public half is compiled in. Small and offline-friendly. Cost: a long-lived secret and a
  rotation plan (ship next key's public half one release ahead).

Either way: verify the manifest signature, then the archive's SHA-256 from the signed checksums, then refuse a
version lower than the running one (downgrade attack) unless `--allow-downgrade`.

## 9. Everything else an upgrade touches

| Area | Policy |
|---|---|
| **Server ↔ collector skew** (G12) | Server accepts inventories from collectors up to **two minor releases older** and any newer patch; ADR-0017 schema validation already rejects unknown shapes clearly. The server lists collectors outside the window on the estate page and serves its own matching collector binaries. Collector never self-updates (fleet tooling owns it). |
| **`/api/v1` clients** | No breaking change within v1 after 1.0. Removals are announced with `Deprecation` and `Sunset` response headers (RFC 9745 / RFC 8594) for at least two minor releases; OpenAPI marks them `deprecated`. |
| **CLI flags and env** | A renamed flag keeps the old name as an alias for two minor releases, printing one warning line. Removed flags fail with "use --new-name". Same for `CIPHERHORIZON_*` variables. |
| **Config files** (`/etc/cipherhorizon/env`, `config.yaml`) | Package installs mark them `config|noreplace` (exists). Today `config.yaml` rejects unknown keys, which is right for typos but means a config written for a newer version stops an older one: keep the error for keys never known, and make keys from a *newer* release a warning (needs a small list of known-future keys in the manifest, or a `version:` key). A future breaking config change carries a `version:` key and an automatic in-memory translation for one major. |
| **Settings stored in the database** | Changed by migrations like any schema change; defaults for new settings come from code, so upgrades never need a settings step. |
| **Accounts and sessions** | Sessions survive an upgrade unless the release notes say otherwise. If the password hashing parameters change, a hash is upgraded at the user's next sign-in, never forced. |
| **Stored scan results vs. new scoring** | Results keep the version that evaluated them. After an upgrade that changes scoring, the UI says "evaluated by 0.4.0; re-evaluate with 0.5.0" (re-evaluation is from stored evidence, no rescan). Changelog lists scoring changes under "Changed" (exists). |
| **Report and CBOM formats** | `schemaVersion` on every stored and exported document (exists). Readers read every old version forever; exporters may emit only the newest. A CBOM consumer change is a release-notes item. |
| **Browser cache** (G13) | Serve UI assets under `/assets/<version>/…` with `Cache-Control: immutable` and `index.html` with `no-cache`, so a browser never mixes old JavaScript with a new API. |
| **Embedded inventory scripts** | Already versioned and hashed per release; the server marks inventories produced by an older script version. |
| **Reference data** | Monthly refresh release (§6.6). |
| **Go toolchain and dependencies** | Patch releases for Go security fixes and `govulncheck` findings; Dependabot already in place. |
| **Signing continuity** | Keyless identity stays the workflow path; renaming the repo or org (RENAME.md) changes it, so a rename ships a release that trusts both identities first. |
| **Data growth** | Backups count against disk: `keepBackups = 3` plus the live file. `db status` and the About page show the total. |
| **Very large or slow migrations** | Progress logged per step; a step expected to exceed a minute is listed in Upgrade notes with an estimate per 100k scans. |
| **Support window** | Before 1.0: latest release only. After 1.0: latest minor, plus security fixes for the previous minor for 6 months. Upgrade-from window: every release since 0.1.0 until 2.0. |

## 10. Phased plan

Each phase is shippable alone. Effort is rough engineering days.

### Phase 0 — make upgrades provably safe (next release; ~5 days)

| ID | Item | Gap |
|---|---|---|
| U-01 | `migrations.lock` for all released steps (1–15); CI check | G1 |
| U-02 | Golden databases from v0.1.0, v0.2.0, v0.3.0, v0.4.0 made by the real binaries; generator script | G2 |
| U-03 | Upgrade matrix job (§6.3) as a required check | G2, G3 |
| U-04 | Fresh-equals-upgraded schema test + compiled-in fingerprint check at start | G3 |
| U-05 | Instance lock on `<db>.lock` | G4 |
| U-06 | Free-space check before backup | G5 |
| U-07 | `db status`, `db check`, `db restore`, `db migrate --dry-run`; post-migration verify + automatic restore on failure; `upgrade_log` table | G6 |
| U-08 | CI rule: migration change requires `### Upgrade notes` in the changelog | — |
| U-09 | archtest: `postMigrations` may not import live evaluation/server code | — |
| U-10 | Write the migration rules (§5.2) into `CONTRIBUTING.md` | — |

**As built (2026-10-24).** All ten items, with these differences from the plan above:

- **Structure mismatch warns, does not refuse.** After an upgrade the schema fingerprint is compared with the
  compiled-in one; a difference is logged and shown by `db status` / `db check`, not refused. A database from a
  pre-0.1.0 build or a hand edit has worked with every release so far, and refusing would lock its owner out.
  Integrity and new foreign-key violations *do* refuse and restore. The CI matrix is the real gate for structure.
- **Foreign keys:** violations already in a file do not block its upgrade; only violations the upgrade adds do.
- **A failed upgrade restores the pre-upgrade backup** (not just "the last good step"), keeps one
  `<db>.failed-upgrade-<time>` copy, and prunes older ones so a service restart loop cannot fill the disk.
- **Locking needs the database lock only to change the file:** `serve` holds it for its life; other commands
  take it only when they would upgrade, so `db backup` still works while a server runs.
- **New platform layer `internal/osfile`** (flock / LockFileEx, free space): the architecture test allows only
  platform layers to import `x/sys/windows`, so `store` stays OS-free.
- **U-09 found a real case:** migration 6's back-fill called the live `recordManualLinkTx`, which uses
  `internal/estate` types. It now calls `recordConfirmedLinkV6`, a frozen copy that writes byte-identical rows
  (checked against the live helper before freezing). Migration 10's column list became `timestampColumnsV10`:
  adding a later table to the shared map would have broken upgrades from before step 10.
- **U-08 is a Go test**, not a workflow rule: `TestUnreleasedMigrationsHaveUpgradeNotes` fails while a step is
  missing from `migrations.lock` and `[Unreleased]` has no `### Upgrade notes`.
- **U-03:** `TestUpgradeFromEveryRelease` runs in the existing test job on Linux, Windows and macOS; a new
  `upgrade` CI job builds the latest release from its tag and checks it refuses, then (after `db restore`)
  reads, a database this commit upgraded.
- **Fixtures:** `testing/upgrade/make-fixture.sh vX.Y.Z` builds the tag, runs it against the demo targets
  (TLS, PQ certificate, SSH, STARTTLS, a dead port; two scans each), triages a finding, links two endpoints,
  uploads a host inventory and adds an admin account, all through that release's own API and CLI. About 0.7–0.9 MB
  per release.

### Phase 1 — every platform upgrades with its own tool (~6 days)

| ID | Item | Gap |
|---|---|---|
| U-11 | Floating `X.Y` container tags; Quadlet `AutoUpdate=registry` documented and shipped commented-in | G8 |
| U-12 | Homebrew tap, Scoop bucket (GoReleaser) | G9 |
| U-13 | APT/YUM repository (option per owner decision) | G9 |
| U-14 | Windows `service install` upgrades in place; `service reconfigure` | G7 |
| U-15 | Install channel stamped at build; `cipherhorizon upgrade` prints the right command per channel | — |
| U-16 | Per-channel upgrade smoke tests (§6.4), nightly + pre-release | — |
| U-17 | Versioned UI asset paths and cache headers | G13 |
| U-18 | Monthly reference-data refresh workflow | G11 |

### Phase 2 — the server tells you, and can do it for you (~7 days)

| ID | Item | Gap |
|---|---|---|
| U-19 | Signed `releases.json` generated in `release.yml` | G10 |
| U-20 | Update check (default per owner decision), Settings → Updates, offline import, banner, `version --check` | G10 |
| U-21 | Self-update for archive / Windows service / macOS launchd with verify, backup, health-gated rollback | G10 |
| U-22 | Collector skew window: shown on the estate page, enforced on import with a clear message | G12 |
| U-23 | winget manifest (owner decision on timing) | G9 |

### Phase 3 — 1.0 promises (~5 days, part of the 1.0 checklist)

| ID | Item |
|---|---|
| U-24 | Compatibility floor: rollback by running the previous minor's binary |
| U-25 | API deprecation headers + OpenAPI `deprecated`; flag aliases with warnings |
| U-26 | Re-evaluate stored results after a scoring change, from the UI |
| U-27 | Published support and upgrade policy page (UPGRADING.md), linked from every release |

`RELEASING.md` criterion 2 for 1.0 ("the database migration path is tested from every released version") is met
by U-02 and U-03.

## 11. Decisions for the owner

| # | Decision | Recommendation |
|---|---|---|
| D1 | Update check default: on with disclosure, or off | **On, with disclosure** and a one-switch off; offline import for air-gapped sites. Security-fix uptake matters more for a security tool. |
| D2 | Self-update signature: Sigstore keyless (A) or release Ed25519 key (B) | **A**, matching how users already verify; B if the binary-size cost is unacceptable. A needs a new dependency, so an ADR first (ADR-0014 rule). B needs none (`crypto/ed25519`). |
| D3 | APT/YUM hosting: Cloudsmith OSS or self-hosted on Pages | **Cloudsmith** (no key to guard); revisit if terms change. |
| D4 | Floating `0.Y` container tags before 1.0 | **Yes**, `0.Y` only; still no `latest` before 1.0. |
| D5 | winget/Chocolatey before 1.0 | winget **yes** (stable versions only), Chocolatey after 1.0. |
| D6 | Unattended self-update for Windows/macOS | **Offer, off by default** (`upgrade --schedule`). |
| D7 | Upgrade-from window guarantee | **Every release since 0.1.0 until 2.0**; no required stops before 2.0. |

## 12. Acceptance

- CI proves direct upgrade from every released version to HEAD, fresh-equals-upgraded, and clean refusal of a
  newer file, on every PR.
- On each channel, a scripted upgrade from the previous release keeps all data and settings and comes back
  healthy; a deliberately broken new version leaves the install running the old one with its data.
- Two processes on one database: the second refuses with a clear message on Linux, Windows and macOS, and in
  containers sharing a volume.
- An operator on any channel can answer "am I up to date, and how do I upgrade?" from the UI or one command,
  without reading docs.
- No request leaves an install when the update check is off; with it on, exactly one anonymous GET a day.
