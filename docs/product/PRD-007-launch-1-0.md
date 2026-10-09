# PRD-007 · Release 1.0, the public launch

Status: agreed 2026-10-08 (decisions in [06-launch-plan.md §5](../launch/06-launch-plan.md)). Research:
[docs/launch](../launch/). Design source of truth after WP-3: [DESIGN.md](../../DESIGN.md) v2.

**Goal.** A first-time visitor understands in one screen that CipherHorizon is a post-quantum readiness workbench
and a TLS scanner that shows its work. They can run it in one command, trust what they downloaded, use it in CI,
scan mail and directory servers, and hand an auditor a report. The product carries the Offset Security identity
and passes its own scan.

**Out of scope (1.1):** MFA, single sign-on, notifications, discovery, fleet trend, config snippets, report
branding, standards views, the public demo. **Deferred by the owner:** the GitHub organisation, module path and
security contact (the rename is the last step before release).

Each requirement below has acceptance criteria and the automated check that proves it. "Journey" is
`testing/e2e/journey.mjs` and its phases; "security.sh" is `testing/e2e/security.sh`.

## WP-1 · Trust and hardening (REQ-TR)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-TR-1** | A password change (own or forced) issues a new session token for the browser that made it; the old token stops working (L-07) | After the change, the previous cookie gets 401; the new one 200 | `TestPasswordChangeRotatesTheSession` | P0 |
| **REQ-TR-2** | Over HTTPS the session cookie is `__Host-ch_session` (Secure, Path=/, no Domain); over plain loopback it stays `ch_session` (L-08) | Cookie name and flags per scheme | `TestSessionCookieUsesTheHostPrefixOverHTTPS`; security.sh HTTPS section | P0 |
| **REQ-TR-3** | The first-run setup code expires 24 hours after the server starts; the log line says so; an expired code is refused with a message saying to restart (L-09) | Setup with an expired code → 403 with "expired" | `TestSetupCodeExpires` | P0 |
| **REQ-TR-4** | The Linux engine refuses to run without `mktemp`, creates its temp file exclusively and owner-only (mktemp) and removes it on exit, writes the facts file with `umask 077`, and never lets the shell expand signature patterns against the working directory; the Windows engine writes the facts file readable only by its owner and Administrators (L-10..L-12) | A test with a matching file in the working directory finds no false path; output file mode 0600 on Linux | `TestShellEngineIsHardened`; Linux run in three distributions (WP-7) | P0 |
| **REQ-TR-5** | Pre-migration backups beyond the newest three are deleted, and the log says which (L-14) | Five old backups present → three remain after a migration | `TestOldBackupsArePruned` | P1 |
| **REQ-TR-6** | Fuzz targets for the facts parser and the systems CSV import; CI runs fuzzing on Linux (L-15) | Targets exist and seed corpora pass | `FuzzParseFacts`, `FuzzImportSystemsCSV` | P0 |
| **REQ-TR-7** | Script integrity can be checked independently of the server: `cipherhorizon scripts list` prints each served script's SHA-256 from the binary; `cipherhorizon scripts export DIR` writes them; releases ship `inventory-scripts.sha256`, covered by the signed checksums; the UI says how to verify (L-04) | The CLI hashes equal the server's hashes and the served bytes | `TestScriptsCommandMatchesTheServer`; journey checks the UI hint | P0 |
| **REQ-TR-8** | Windows instructions offer `Unblock-File` with the `RemoteSigned` policy first, Bypass as the fallback (L-16) | Text present in the guide | journey E2E-14.x | P1 |
| **REQ-TR-9** | `golang.org/x/text` ≥ v0.41.0; SECURITY.md describes the hash-slot limit and the sign-in log retention (I-01, I-03, L-17) | govulncheck shows no required-module vulnerability | `make vuln` | P1 |

## WP-2 · Passes its own scan (REQ-SS)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SS-1** | The HTTPS listener offers only AEAD suites with ECDHE in TLS 1.2 (TLS 1.3 unchanged; hybrid ML-KEM first) | No CBC suite accepted | `TestTheServerPassesItsOwnScan` | P0 |
| **REQ-SS-2** | HTTPS responses carry `Strict-Transport-Security: max-age=31536000` | Header present on TLS responses, absent on plain loopback | `TestHSTSOnlyOverTLS`; security.sh | P0 |
| **REQ-SS-3** | Scanned and evaluated with itself, the HTTPS listener has no protocol, cipher, key-exchange, feature or HTTP finding, and readiness L3 or higher. Expected and listed: certificate-trust findings from the test's own self-signed certificate, and two informational notes inherent to any server today (no post-quantum certificates exist yet; HSTS omits `includeSubDomains` on purpose, since the server usually lives on a subdomain whose siblings it must not force onto HTTPS) | Test passes | `TestTheServerPassesItsOwnScan` | P0 |

## WP-3 · The Offset theme and flat logos (REQ-BR)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-BR-1** | DESIGN.md v2 adopts the Offset design system: canvas, line, ink, body, muted, blue, blue-ink, blue-wash, navy and on-navy tokens; Geist (UI), Geist Mono (machine values, one eyebrow per screen), Newsreader (page titles and the hero only); 4px radius; the −27.6° skew as a sparing accent; dark mode derived from the navy scale | Document updated; `style.css` tokens match it | Review; `TestStyleTokensMatchDesign` | P0 |
| **REQ-BR-2** | Geist, Geist Mono and Newsreader (SIL OFL) are bundled as `.woff2` with their licences; no external request; CSP unchanged | Fonts load from the same origin | journey checks `document.fonts` | P0 |
| **REQ-BR-3** | The CipherHorizon mark is concept B (three −27.6° parallelograms), flat, in three versions: colour, on-navy, one colour; used in the rail, sign-in, About, favicon and PDF; the Offset credit is flat | No gradient, filter or glow in any logo SVG | `TestLogosAreFlat` | P0 |
| **REQ-BR-4** | No gradient anywhere in the UI CSS, except the loading skeleton and the running-scan shimmer (functional) | CSS check | `TestNoDecorativeGradients` | P0 |
| **REQ-BR-5** | Text and UI colours meet WCAG AA in light and dark | Contrast computed on rendered pages | journey `NFR-a11y.contrast` | P0 |
| **REQ-BR-6** | PDF reports use the flat lockup and *by Offset Security*, and the cover names the standards (NIST IR 8547, FIPS 203/204/205, CycloneDX) | Text in the PDF | `TestPDFCarriesTheLockup` | P1 |

## WP-4 · The product tells its story (REQ-ST)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-ST-1** | The sign-in and setup screens have a navy value panel: *Quantum-safe before it's urgent.*, the three pillars (post-quantum readiness; a TLS scanner that shows its work; an inventory you can hand over), and *by Offset Security* linking to the PQC Readiness page | Text present; panel stacks above the form on a phone | journey E2E-B.1 | P0 |
| **REQ-ST-2** | The Overview hero has one Geist Mono eyebrow (*Post-quantum readiness · TLS scanner · CBOM*), a Newsreader headline and the scan form; the L0–L4 scale stays | Elements present | journey E2E-B.2 | P0 |
| **REQ-ST-3** | About is a product page: the pillars, the standards, what it does and does not do, the Offset credit, links to the docs, the source and the Offset PQC Readiness service, then the reference tables | Sections present | journey E2E-B.3 | P1 |
| **REQ-ST-4** | `cipherhorizon --help` and `version` carry the one-liner; the image label too | Text present | `TestHelpCarriesTheOneLiner` | P1 |
| **REQ-ST-5** | No em-dash or en-dash and none of the banned words in UI strings | Check over `web/static` | `TestUICopyRules` | P0 |

## WP-5 · CLI verdict and CI (REQ-CL)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-CL-1** | `tls scan` prints the evaluation first: readiness level and name, TLS hygiene score, checks run and found, then the action items (severity, title, what to do); `--details` adds the raw probe sections shown today | Golden output for the demo targets | `TestTLSScanPrintsTheVerdict` | P0 |
| **REQ-CL-2** | `--json` emits `{report, evaluation}` for each target | Schema stable; documented | `TestTLSScanJSONHasTheEvaluation` | P0 |
| **REQ-CL-3** | `--fail-on` with one or more conditions (`level<L3`, `score<70`, `severity>=high`, `finding=PROTO.TLS10`); exit code 3 when any target meets one; exit codes documented (0 pass, 1 fatal, 2 incomplete, 3 policy failed) | Each condition tested against demo targets | `TestFailOnConditions` | P0 |
| **REQ-CL-4** | A CI page with a GitHub Actions example (download the release, verify the signature, run `tls scan --fail-on`) | Docs present; the example's commands run | docs review | P1 |

## WP-6 · STARTTLS (REQ-SX)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-SX-1** | Every probe connection can negotiate STARTTLS before the handshake for SMTP (incl. submission), IMAP, POP3, FTP, XMPP, LDAP and PostgreSQL; the SSRF guard applies unchanged | A scan through each protocol finds the same protocols and suites as a direct scan of the same TLS configuration | `TestSTARTTLSMatchesDirectTLS` (per protocol) | P0 |
| **REQ-SX-2** | The protocol is chosen by `--starttls auto|none|<protocol>` or a scheme (`smtp://host`); `auto` maps well-known ports (25, 587, 143, 110, 21, 5222, 389, 5432) | Table test | `TestSTARTTLSChoice` | P0 |
| **REQ-SX-3** | The server stores the protocol per endpoint; the add dialog offers it (Automatic by port by default); the report header says "via STARTTLS (SMTP)"; the HTTP/HSTS check is skipped for non-HTTP services, with that reason | API and UI | `TestEndpointKeepsItsSTARTTLS`; journey E2E-X.1 | P0 |
| **REQ-SX-4** | A server that refuses STARTTLS or is not the protocol gives a clear failure, not a hang | Error message names the protocol and the reply | `TestSTARTTLSRefusalIsExplained` | P0 |
| **REQ-SX-5** | `demo-targets` serves a STARTTLS endpoint per protocol for testing and demos | Ports documented | used by the tests above | P1 |

## WP-7 · Deployment (REQ-DP)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-DP-1** | The container image builds and runs: start, health, first-run setup from the log, an HTTPS listener with a mounted certificate, a scan of itself, a backup | `testing/deploy/smoke.sh` passes with Podman or Docker | smoke script (here and CI) | P0 |
| **REQ-DP-2** | `docker-compose.yml` is hardened (read-only root, all capabilities dropped, no-new-privileges, tmpfs `/tmp`) and still works; `deploy/compose-caddy.yml` adds Caddy with automatic HTTPS for a real host name (L-13) | The smoke script runs the hardened container | smoke script | P0 |
| **REQ-DP-3** | `deploy/cipherhorizon.service` (systemd, with sandboxing) and a Windows service note | Present; unit keys checked | `TestSystemdUnitIsSandboxed` | P1 |
| **REQ-DP-4** | `cipherhorizon db backup FILE` makes a consistent online copy (`0600`); restore is documented | The backup opens and holds the data | `TestDBBackup` | P0 |
| **REQ-DP-5** | The Linux inventory script runs on Debian, UBI (RHEL) and Alpine, and its facts file uploads and converts | `testing/deploy/linux-script.sh` passes in all three | script (here and CI) | P0 |
| **REQ-DP-6** | A release checklist for the owner: the rename, a pre-release on a fork, and verifying signatures, SBOMs and provenance from a clean machine | Checklist present | review | P0 |

## WP-8 · Launch materials (REQ-LM)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-LM-1** | README rewritten: one-liner, screenshot, quick start (container and binary), the three pillars, how it compares (testssl.sh, SSL Labs, PQC CLIs), standards, security and trust, the Offset credit | Links resolve; the quick start runs | `TestReadmeLinksResolve`; smoke script | P0 |
| **REQ-LM-2** | A docs site (`site/`, static, Offset theme, no external requests) with Home, Getting started, Deploy, CLI and CI, Methodology, Security, FAQ; a GitHub Pages workflow | Pages render; links checked | `TestSiteLinksResolve` | P1 |
| **REQ-LM-3** | Fresh screenshots of the main pages (light and dark) for the README and site, taken by a script | Script produces them | `testing/e2e/screenshots.mjs` | P1 |
| **REQ-LM-4** | Drafts of the launch posts (Show HN, r/netsec, r/selfhosted, LinkedIn) in `docs/launch/posts/` | Present | review | P2 |

## WP-9 · Scope and accountability (REQ-AC)

| ID | Requirement | Acceptance | Verified by | Pri |
|---|---|---|---|---|
| **REQ-AC-1** | `serve --scan-allow` (repeatable: a CIDR, an IP or a domain suffix such as `.example.com`) limits what can be scanned; adding an endpoint outside it is refused with the reason; a name that resolves outside it is refused at connect time; with no flag everything routable is allowed, and the server says so at start and on About (L-01) | Refusals at both points | `TestScanScopeRefusesAtAddAndConnect`; security.sh | P0 |
| **REQ-AC-2** | Every state-changing API call writes one row to the append-only audit log: when, who, what kind of object, which, the action, and a short detail (never a secret) (L-02) | A table-driven test over every mutating route checks one new row each | `TestEveryChangeIsAudited` | P0 |
| **REQ-AC-3** | Administrators see an **Activity** tab on Users: sign-ins and changes in one list, filterable by person and kind, exportable as CSV (`GET /api/v1/audit.csv`, formula-safe) | View and export | `TestAuditExportIsAdminOnly`; journey E2E-A.11 | P0 |
| **REQ-AC-4** | A scan records who started it (a person, the automation token, or the schedule); the report's history shows it | Field present | `TestScanRecordsWhoStartedIt` | P1 |

## Measures

| ID | Measure | Target |
|---|---|---|
| L-M1 | Time from `docker run` to a first report on a clean machine | Under 3 minutes |
| L-M2 | Findings when the product scans its own HTTPS | 0 outside the certificate-trust group |
| L-M3 | Automated checks green | Go tests, lint, govulncheck, journey, security.sh, smoke, Linux script |
| L-M4 | Gradients in the UI | 0 (skeleton and shimmer excepted) |
