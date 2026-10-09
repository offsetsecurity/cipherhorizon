# QA report 007: Launch 1.0

Executes the checks named in [PRD-007](../product/PRD-007-launch-1-0.md) (requirements and measures). Run on
2026-10-09:

- Windows 11, Go 1.27, Edge headless.
- Podman 6.0.2 with its Fedora machine (WSL), for the container and Linux checks.
- Fresh databases, and the demo targets built from this tree.

Requirement status lives in the [RTM](RTM.md) (PRD-007 section). The research and decisions behind this program are in
[docs/launch](../launch/).

## 1. Verdict

**PRD-007 is met, with three things left to the owner.** All 46 requirements (33 P0, 12 P1, 1 P2) are `done`.

Not validated here, because they need a published repository or a download that was not approved:

- **The release itself.** The GoReleaser export of the inventory scripts and the signature over them. GitHub Pages.
  The CI example run end to end. All of these wait for the owner's organisation and module path (launch blockers B-01,
  B-02 in [01-security-audit.md](../launch/01-security-audit.md)). The [release checklist](../engineering/RELEASE-CHECKLIST-1.0.md)
  covers them.
- **`deploy/compose-caddy.yml`.** It was written and checked statically (`TestComposeFilesAreHardened`), but the Caddy
  image was not among the approved downloads, so it was not run.
- **Windows service.** Documented as a wrapper, not packaged.

## 2. Results

| Suite | Result |
|---|---|
| `gofmt`, `go vet ./...` | clean |
| `golangci-lint run ./...` | **0 issues** (11 found during this pass, all fixed) |
| `go test ./...` | pass |
| `govulncheck ./...` | **No vulnerabilities found** |
| Browser journey (`journey.mjs` with every phase, new `launch-phase.mjs`) | **182 / 182** |
| `testing/e2e/security.sh` | **122 / 122** |
| `testing/deploy/smoke.sh` (Podman, inside its machine) | **14 / 14** with a build; 13 / 13 on the built image in 16 seconds |
| `testing/deploy/linux-script.sh` | **26 / 26**: Debian 12, UBI 9.6, Alpine 3.20 |

### New and changed automated checks

- **Go:**
  - `TestPasswordChangeRotatesTheSession`, `TestSessionCookieUsesTheHostPrefixOverHTTPS`, `TestSetupCodeExpires`
  - `TestShellEngineIsHardened` (it runs the real PowerShell engine and reads its ACL back; on Linux it runs the shell engine)
  - `TestOldBackupsArePruned`, `FuzzParseFacts`, `FuzzImportSystemsCSV`, `TestScriptsCommandMatchesTheServer`, `TestDBBackup`
  - `TestTheServerPassesItsOwnScan`, `TestHSTSOnlyOverTLS`
  - `TestStyleTokensMatchDesign`, `TestTokenContrast`, `TestLogosAreFlat`, `TestNoDecorativeGradients`, `TestPDFCarriesTheLockup`
  - `TestUICopyRules`, `TestTheProductTellsItsStory`, `TestHelpCarriesTheOneLiner`
  - `TestTLSScanPrintsTheVerdict`, `TestTLSScanJSONHasTheEvaluation`, `TestFailOnConditions`, `TestTLSScanSaysWhenATargetCouldNotBeScanned`
  - `TestSTARTTLSMatchesDirectTLS` (7 protocols), `TestSTARTTLSChoice`, `TestSTARTTLSRefusalIsExplained` (7 protocols), `TestEndpointKeepsItsSTARTTLS`
  - `TestScanScopeRefusesAtAddAndConnect`, `TestScanScopeParsingAndMatching`, `TestEveryChangeIsAudited`, `TestAuditExportIsAdminOnly`, `TestScanRecordsWhoStartedIt`
  - `TestSystemdUnitIsSandboxed`, `TestComposeFilesAreHardened`, `TestReadmeLinksResolve`, `TestSiteMakesNoExternalRequests`
- **Journey:**
  - E2E-B.1 / B.1m: the sign-in value panel, and its phone layout.
  - E2E-B.2, B.3, B.4: the Overview story, About, the fonts loaded with nothing external.
  - NFR-a11y.contrast × 4: rendered text, light and dark.
  - E2E-14.5: RemoteSigned first, how to check a script.
  - E2E-X.1: an SMTP endpoint through STARTTLS.
  - E2E-A.11 to A.13: the Activity tab, its filter, who started each scan.
- **security.sh:**
  - the `__Host-` cookie and HSTS over HTTPS;
  - no HSTS on plain HTTP;
  - CBC and RSA key transport refused in TLS 1.2 (`openssl s_client`; curl on Windows ignores cipher names);
  - the scan scope at add time;
  - the activity log.

Several of these checks were tried against a deliberately broken input, to make sure each one can fail:

- **Style tokens:** a wrong `--primary` failed both token tests.
- **Links:** a missing file and a missing anchor failed the link test.
- **Shell engine:** with the `set -f` guard removed, the engine found 0 of 2 files, against 2 of 2 with it.
- **Windows command:** RemoteSigned refused a file carrying Mark-of-the-Web, and ran it after `Unblock-File`.

## 3. Measures

| ID | Measure | Target | Measured |
|---|---|---|---|
| L-M1 | Time from `docker run` to a first report | under 3 minutes | **16 s** on a built image, for both containers, setup, backup and a self-scan. A first build pulls the Go and distroless images and takes a few minutes. Not measured on a clean machine |
| L-M2 | Findings when the product scans its own HTTPS | 0 outside certificate trust | **0**: CERT.UNTRUSTED (self-signed), CERT.EXPIRING (the 2-day test certificate), and two inherent notes (PQC.CLASSICAL-AUTH: no CA issues post-quantum certificates yet; HTTP.HSTS-NO-SUBDOMAINS: deliberate). Readiness **L3** |
| L-M3 | Automated checks green | all | all (section 2) |
| L-M4 | Gradients in the UI | 0, skeleton and shimmer excepted | **0** (`TestNoDecorativeGradients`) |

<a id="tr9"></a>
## 4. Dependencies (REQ-TR-9)

`golang.org/x/text` was upgraded from v0.39.0 to v0.41.0 (GO-2026-6629). `govulncheck ./...` then reported no
vulnerabilities. SECURITY.md now describes:

- the `__Host-` cookie, and session rotation on a password change;
- the setup code's 24-hour life;
- the bounded password hashing;
- the sign-in log keeping its newest 5,000 entries;
- `db backup` and the pruned pre-migration copies;
- how to check an inventory script.

<a id="systemd"></a>
## 5. The systemd unit (REQ-DP-3)

The unit was checked in the Podman machine (Fedora, systemd), on a temporary copy pointing at a Linux build. Nothing
was installed.

- `systemd-analyze verify`: clean.
- `systemd-analyze security`: **1.5, OK**.
- The binary ran under every sandbox property of the unit, as a transient unit removed afterwards. `version` and a
  `tls scan` both worked, so the system-call filter and MemoryDenyWriteExecute do not break the Go runtime.
- The first draft also filtered `@resources`, which would have killed the process on the Go runtime's setrlimit. It was
  replaced by `SystemCallErrorNumber=EPERM`.

## 6. Defects found and fixed during QA

| Found by | Defect | Fix |
|---|---|---|
| systemd sandbox run | The CLI printed "Nothing to fix." for a target that answered nothing | It now says "Could not be scanned: <reason>"; `TestTLSScanSaysWhenATargetCouldNotBeScanned` |
| Screenshot review | A STARTTLS service reported its HTTP area as "Not checked", as if the scan had a gap | New section and check status `not-applicable`, in the UI, the PDF and the CLI |
| Screenshot review | Demo certificates lasted 24 hours, so demos read "0 days left" | `testserver.CertValidity`; the demo targets use 90 days, tests keep 24 hours |
| Smoke test | Podman drops HEALTHCHECK from OCI-format images | The smoke script builds with `--format docker` under Podman |
| Smoke test | Podman's WSL machine does not forward published ports to Windows | The deployment scripts run inside the machine, as on Linux and in CI |
| Journey | A renamed menu item ("Edit name, tags, notes and STARTTLS") | Journey updated |
| Lint | Eleven findings: unchecked `Index()` results in tests, De Morgan simplifications, an unused return value, missing doc comments, an unused nolint | Fixed |

## 7. Deviations from PRD-007

- **REQ-TR-4.** "Noclobber" became `mktemp` plus a trap: `mktemp` already creates the file exclusively and owner-only,
  and the trap removes it on exit. The PRD wording was updated.
- **REQ-SX-1.** XMPP covers client-to-server STARTTLS (port 5222) only. Server-to-server XMPP (5269) is not mapped by
  `auto`.
- **About.** It links to the API description on the server itself rather than to the documentation site, because the
  site's address depends on the owner's repository.
- **Breaking change.** `tls scan --json` now emits `{target, report, evaluation}` per target, and the text output leads
  with the verdict (`--details` restores the raw tables). Both are recorded in the CHANGELOG.

<a id="review-008"></a>
## 8. Owner review round: UX-REVIEW-008 (2026-10-09)

The owner rejected three things after PRD-007: the logo, sign-in forced on everyone, and About mixed with help. The
owner also pointed out that the finished screens had never been reviewed. [UX-REVIEW-008](../product/UX-REVIEW-008-screen-by-screen.md)
walks every screen as a product manager and a design lead and records 15 findings with a decision for each.
Every decision is built.

| Decision | Built | Checked by |
|---|---|---|
| S1, S2: a plain flat icon (padlock on a blue tile); the tagline instead of "by Offset Security" | `img/mark*.svg`, `brandMark()`, the PDF cover, the site | `TestLogosAreFlat`, `TestPDFCarriesTheLockup` |
| S3: sign-in off by default; Settings turns it on and creates the administrator; `--sign-in auto\|on\|off`; a network server needs sign-in or `--open-network`; existing accounts keep sign-in on (migration 12) | `internal/server/settings.go`, `internal/store/settings.go`, `serve` flags, Dockerfile, compose files | `TestSignInIsOffByDefault`, `TestSignInCanBeTurnedOnFromSettings`, `TestSignInLocks`, `TestExistingAccountsKeepSignInOn`, `TestServeOnTheNetworkNeedsSignInOrOpenNetwork`, security.sh, smoke.sh, E2E-S.2 |
| D1 to D6 (addendum): turning sign-in off needs the administrator's password, ends every session and ignores leftover cookies, keeps and freezes accounts (409 on changes), records anonymous actions with their address, and turning it on again restores roles | `settings.go`, `accounts.go`, `store.EndAllSessions`, `RecordAction` client, `settings.js` dialog, `users.js` frozen view | `TestTurningSignInOffKeepsAccountsAndHistory`, screenshot review of the dialog, the frozen Users page and Activity |
| S4: About is the product's identity, credits and data; Help is the how-to with a contents list; Settings is new | `about.js`, `help.js`, `settings.js` | `TestTheProductTellsItsStory`, E2E-B.3, E2E-S.0, E2E-S.1 |
| O1: the readiness scale counts your endpoints | `overview.js` | E2E-O.1 |
| E1 to E3: one way into a row, one findings badge, the STARTTLS protocol under the address | `assets.js` | E2E-R.4, E2E-R.5 |
| R1, R2: the summary leads with readiness on its scale; certificate colour follows time, trust in words; Not checked only when something was not checked | `report.js` | T1-E2E.4 |
| F1: the badge no longer overflows its column | `findings.js`, CSS | screenshot review |
| M1, M2: quantum-vulnerable algorithms first, the safe ones folded, the reason opening from the verdict | `host.js` | E2E-14.3, screenshot review |
| I1, I2: counts fit their card; each figure says what it counts | `inventory.js`, CSS | screenshot review |
| P1: one system picker for the OMB export | `reports.js` | screenshot review |

R3 (the verdict box's red edge) was re-examined and left as it is: the edge already follows the worst finding, and
that finding was high.

**Results after the round:**
- `go test ./...` passes; `golangci-lint` reports 0 issues.
- Journey 190 / 190; security.sh 124 / 124; smoke.sh 16 / 16.
- The screens were captured again and reviewed against the findings. The README and site screenshots were
  regenerated from demo data.
