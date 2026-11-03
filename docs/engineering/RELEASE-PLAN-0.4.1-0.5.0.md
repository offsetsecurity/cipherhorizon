# Release plan: 0.4.1 and 0.5.0

**Written:** 2026-11-03. **Owner decisions taken the same day:** ship 0.4.1 now and 0.5.0 next; the maintainer
session merges and tags once CI and QA are green; PRD-016 D1–D7 and CRYPTO-REVIEW-004 D2–D4 as recommended (below).

The release procedure itself is [RELEASING.md](RELEASING.md). This page says what goes into each version, in what
order, and what stays with the owner.

## 0.4.1: patch, now

A patch under the 0.x rules: security fixes, a safety feature for upgrades, refreshed data and dependency bumps.
No breaking change to the CLI, API or database (`migrations.lock` proves steps 1–15 are unchanged; step 16 only adds
the `upgrade_log` table).

| # | What | Where | State |
|---|---|---|---|
| 1 | Distrusted CA keys reported on any Go version; own path builder; `CERT.DISTRUSTED-KEY`; eval/13 | PR #28 | merged |
| 2 | Opt-in CRL revocation checks up the served chain (`--revocation`) | PR #28 | merged |
| 3 | Root stores refreshed after Chrome Root Store v43 (emSign ECC Root CA - G3 gone from both stores) | PR #28 | done 2026-11-03 |
| 4 | Safe database upgrades from any release: lock, free space, backup, verify, auto-restore, `db status/check/migrate/restore`, upgrade matrix in CI | PR #29 | merged |
| 5 | Dependencies: modernc.org/sqlite 1.61.0, golang image, GitHub Actions | #30–#32 | merged |
| 6 | README header, social preview image and its render script | PR #27 | merged |

Order: #27 and #28 → update #29 from `main` (only `CHANGELOG.md` conflicts) → #29 → `chore(release): 0.4.1`
with its changelog, `migrations.lock` entry and upgrade fixture (`testing/upgrade/make-fixture.sh v0.4.1 HEAD`) →
annotated tag `v0.4.1` → watch `release.yml` → verify the download as a user would.

Found while releasing: Phase 0 asked for the fixture *after* the tag, but its own CI check fails the release commit
without one, so `release.yml` could never pass. `make-fixture.sh` now builds the release commit before the tag
(`vX.Y.Z HEAD`), and RELEASING.md step 2 says so.

**Release note headline:** "If you scan servers whose chain runs through one of the eight eMudhra CAs, 0.4.0 said
only *no valid chains built*. 0.4.1 says which certificate's private key is public, and still evaluates the rest."

## 0.5.0: minor, next

Each line is a PR of its own, reviewed and QA'd before the next starts. Rough effort in engineering days.

| # | What | Source | Effort |
|---|---|---|---|
| 1 | **Weekly reference-data refresh** in CI: CCADB root stores, CT log list, Mozilla OneCRL and Go's distrusted SPKIs diffed into `distrust.json`; opens a PR when anything changes. Bundled-store age becomes a finding after 30 days. | CRYPTO-REVIEW-004 P3 (14, 15), PRD-016 U-18 | 2 |
| 2 | **Weak-key tests** on every key seen: EC small scalar (BSGS, \|k\| < 2^32), RSA ROCA, close primes (Fermat), small factors; self-test corpus | CRYPTO-REVIEW-004 P1 (6, 7, 9) | 4 |
| 3 | **Estate batch GCD and key reuse** as a background job | CRYPTO-REVIEW-004 P1 (8) | 2 |
| 4 | **Host exposure:** Windows Disallowed store, Linux/macOS trust-store files and `ca-certificates` versions, embedded bundles (Go buildinfo, certifi, Java cacerts), estate view "hosts exposed to a distrusted CA or key" | CRYPTO-REVIEW-004 P2 | 5 |
| 5 | **Every platform upgrades with its own tool:** floating `0.Y` image tags, Quadlet auto-update, Homebrew tap and Scoop bucket, APT/YUM on Cloudsmith, Windows `service install` upgrades in place, channel stamped at build, per-channel upgrade smoke, versioned UI assets | PRD-016 Phase 1 (U-11..U-17) | 6 |
| 6 | **Linux collector validation** on real Debian/Ubuntu/Fedora userlands (in the Podman machine), as user and root | host-discovery gate item 1 | 1 |

Not in 0.5.0: PRD-016 Phase 2 (update check, signed `releases.json`, self-update) and Phase 3 (1.0 promises); the
CryptoLyzer follow-ups (STRATEGY-002 §9) wait for their own decisions.

## Decisions recorded

PRD-016 §11: D1 update check **on, with disclosure** and one switch off, offline import for air-gapped sites;
D2 **Sigstore keyless** for self-update (ADR first); D3 **Cloudsmith** for APT/YUM; D4 floating **`0.Y`** tags, no
`latest` before 1.0; D5 **winget yes** (stable only), Chocolatey after 1.0; D6 unattended self-update **offered,
off by default**; D7 upgrades from **every release since 0.1.0 until 2.0**.

CRYPTO-REVIEW-004 §5: D1 0.4.1 **yes**; D2 distrust list **hand-curated plus OneCRL** through the weekly CI PR;
D3 badkeys data **only after a licence read**; D4 **no** CCA India store for now; D5 and D6 already built as
recommended.

## Left with the owner

These need a person with admin rights or a decision only the owner can make:

- **GitHub Pages** for the docs site: the repository is public now, so Pages is available (Settings → Pages →
  GitHub Actions).
- **Repository settings now that it is public:** branch protection on `main` (require CI), private vulnerability
  reporting, and setting the `CODE_SCANNING` variable if scheduled CodeQL runs are wanted.
- **Windows Administrator validation:** run `testing/hostdiscovery/compare-windows.ps1` from an elevated
  PowerShell once; the collector has only been validated as a standard user.
- **Name and security contact** for 1.0 ([RELEASE-CHECKLIST-1.0.md](RELEASE-CHECKLIST-1.0.md) §1).
- **CryptoLyzer follow-ups** (STRATEGY-002 §9): SSH is done; client simulation, RDP/MySQL STARTTLS and IKE are open.
