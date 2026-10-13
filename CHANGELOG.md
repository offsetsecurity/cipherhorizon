# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project intends to
follow [Semantic Versioning](https://semver.org/). Until 1.0 (`0.x`) the interfaces (CLI flags, the JSON API,
the CBOM/report/eval schema versions, the database) can change in a minor release; see
[docs/engineering/RELEASING.md](docs/engineering/RELEASING.md#versioning-policy). The first tagged release is
`0.1.0`, a pre-release.

## [Unreleased]

## [0.1.0] - 2026-10-13

### Fixed

- **Post-quantum certificates are seen.** The scanner's own TLS 1.3 hellos offered no ML-DSA signature scheme, so a
  server whose only certificate is ML-DSA, and which picks its certificate before answering (as OpenSSL does),
  refused them: TLS 1.3 looked unsupported and the endpoint was rated L0. Every TLS 1.3 hello now offers
  ML-DSA-44/65/87.

### Added

- **SSH servers.** CipherHorizon now audits SSH servers as well as TLS endpoints, with its own SSH implementation
  (standard library only). It reads what a server offers, negotiates as OpenSSH 10.6 would (the ML-KEM hybrid
  included), fetches and verifies every host key (Ed25519, ECDSA, RSA, ML-DSA, the composite
  `ssh-mldsa44-ed25519`), and never logs in. At most 24 connections a scan; the address guard applies.
  - **A page of its own**, *SSH servers*, beside *TLS endpoints* in the menu, each with its own columns.
  - **Readiness L0 to L4** by SSH's own rules: hybrid key exchange for L3, a post-quantum host key for L4.
  - **Judged against the CipherHorizon SSH baseline 2026**, a cited list of what an SSH server may and must offer.
    The report says whether the server meets it and gives the `sshd_config` lines that would make it. Checked
    against real OpenSSH 9.2 and 10.0: `sshd -t` accepts the lines, and the rescan meets the baseline.
  - **18 cited checks**, an SSH CBOM, an SSH PDF, history with diffs, and `cipherhorizon ssh scan` with
    `--baseline` and `--fail-on baseline`. `cipherhorizon ssh baselines` lists the baseline with its sources;
    `GET /api/v1/ssh/baselines` returns it.
  - **`demo-targets`** serves seven SSH servers (base+20 to base+27), from an SSH-1 banner to an ML-DSA host key,
    one of them hardened to meet the baseline.
- **Signature schemes (TLS 1.3).** A new scan stage tests, one scheme per hello, which signature schemes the
  server holds keys for, with a control that catches servers answering regardless. An accepted ML-DSA scheme lifts
  L3 to L4 even when the default certificate is classical. Shown in the report, the PDF and the endpoint CBOM.
- `demo-targets` serves an ML-DSA-only and an ECDSA + ML-DSA TLS server (both L4).
- **Linux packages.** `.deb` and `.rpm` (amd64, arm64) install the binary, the hardened systemd unit and
  `/etc/cipherhorizon/env` for its options (kept on upgrade). The service is installed but not started.
  Upgrades restart a running service; removal stops it and keeps the database. CI installs both packages on
  every change.
- **Windows service.** `cipherhorizon service install|status|start|stop|uninstall`. Install copies the program
  to Program Files and keeps its data and log in `C:\ProgramData\CipherHorizon` (readable by SYSTEM,
  Administrators and the service only). The service starts at boot, runs as `LocalService` and restarts after
  a failure.
- **Podman Quadlet unit and macOS launchd agent** in `deploy/`, and
  [docs/engineering/INSTALL.md](docs/engineering/INSTALL.md): each OS, where the data lives, backup, restore,
  upgrade and removal.

### Changed

- **The product is multi-protocol.** It introduces itself as post-quantum readiness for the protocols your
  organisation runs on: TLS, SSH and, next, VPN. This applies to the CLI, the container label, the packages, the
  README, the site, the sign-in panel, About, Help, the sidebar and the PDFs.
  - **The Overview** has a card per protocol, each with its own measure, and the readiness scale states its rules
    for TLS and for SSH.
  - **The scan box** says *Scan as TLS* or *Scan as SSH* before it scans.
  - **Findings** filters by protocol.
  - **Reports** groups documents by protocol.
  - **No list, total or sort ever adds an SSH result to a TLS hygiene score.**
- **The endpoints CSV** gains `ssh_baseline`, `ssh_baseline_meets` and `ssh_baseline_changes` columns.
  `GET /api/v1/scans` takes `kind=`.
- Evaluations are `eval/8`; each endpoint's latest result is re-evaluated on start. Migration 14 stores each SSH scan's baseline
  verdict.
- Go 1.27 or newer is required to build (`crypto/mldsa`).
- **The database has a home.** Without `--db`, the database now goes in the per-user data folder
  (`%LOCALAPPDATA%\CipherHorizon`, `~/Library/Application Support/CipherHorizon`,
  `~/.local/share/cipherhorizon`) instead of whatever folder the server was started from. `CIPHERHORIZON_DB`
  overrides it. A `cipherhorizon.db` already in the current folder is still used, with a notice, so no history
  goes missing.
- `docker-compose.yml` and the Quadlet unit declare the health check themselves (exec form, no shell). An image
  built by Podman (OCI format) drops the Dockerfile `HEALTHCHECK`, so the container showed no health status.


### Changed (breaking, for scripts that read the CLI)

- `tls scan` now prints the verdict first: readiness level, TLS hygiene score, checks run, then what to do, worst
  first. `--details` adds the raw protocol, suite, group and certificate tables that used to be the whole output.
- `tls scan --json` emits one `{target, report, evaluation}` object per target instead of an array of bare reports.

### Changed (owner review, [UX-REVIEW-008](docs/product/UX-REVIEW-008-screen-by-screen.md))

- **Sign-in is off by default:**
  - **Turning it on:** in the new **Settings** page, which creates the first administrator in the same step.
  - **Server flags:** `serve --sign-in auto|on|off` (`--login` and `--no-login` remain as aliases).
  - **Existing accounts:** a database that already has accounts keeps sign-in on.
  - **On the network:** a server listening beyond loopback refuses to start open unless given `--open-network`. The container image passes it and is published on host loopback only; the Caddy compose file forces sign-in on.
  - **Turning it off** asks for the administrator's password and says what will happen: every session ends, accounts are kept but frozen until sign-in is on again, history keeps its names, and actions while it is off are recorded as *Anyone (sign-in off)* with the address they came from. Turning it on again restores everyone's roles.
- **The product icon** is a plain flat padlock on a blue tile, with the tagline *TLS and post-quantum scanner*.
- **About, Help and Settings are separate pages:**
  - **About:** the product, its version, standards, credits, licences and reference data.
  - **Help:** how to use it and how it judges, with a contents list.
  - **Settings:** sign-in and the server's configuration.
- **Overview:** the readiness scale counts your endpoints at each level.
- **The navigation rail holds places only:**
  - **Scan a URL** moved from the rail to the Overview's scan box and the Endpoints page.
  - **The foot is compact:** Settings, Help, About, the account, then one line for the credit and the version.
  - **No scroll pane:** the rail fits a laptop screen without a scroll pane of its own.
- **Endpoints:** one way into a row, one findings badge per row, and the STARTTLS protocol under the address.
- **The endpoint summary** leads with post-quantum readiness on its L0 to L4 scale. The certificate's colour follows its
  expiry, with trust said in words.
- **The machine page** lists quantum-vulnerable algorithms first.
- **Fixed:** a badge overflowing in Findings; Inventory counts spilling out of their card, and two figures that
  disagreed because one counted keys.
- **Reports:** the OMB M-23-02 export uses one system picker.

### Added (launch 1.0, [PRD-007](docs/product/PRD-007-launch-1-0.md); results in [QA-REPORT-007](docs/program/QA-REPORT-007.md))

- **Windows version information and icon.** `cipherhorizon.exe` and `cipherhorizon-collector.exe` now show their version (file version `MAJOR.MINOR.PATCH.0`, product version in full), product name, publisher, description and the padlock icon under Properties > Details, instead of a blank version (0.0.0.0). Release builds take them from the tag (`scripts/winres.sh`, run by GoReleaser).
- **STARTTLS** for SMTP (and submission), IMAP, POP3, FTP, XMPP, LDAP and PostgreSQL.
  - **Choosing it:** automatic by well-known port, by scheme (`smtp://host`), with `tls scan --starttls`, or per endpoint in the UI.
  - **Reports** say "via STARTTLS (SMTP)", and the HTTP area is reported as not applicable.
  - **Refusals:** a service that refuses STARTTLS fails at once, naming the protocol and its reply.
  - **Demo targets** add one STARTTLS service per protocol.
- **CI gate:** `tls scan --fail-on 'level<L3,score<70,severity>=high,finding=ID'` exits 3 when a target meets a
  condition or cannot be scanned. A GitHub Actions example is in [docs/CI.md](docs/CI.md).
- **Scan scope:** `serve --scan-allow` (networks, addresses, domains), checked when an endpoint is added and on the
  real address of every connection. About and the start-up log state the scope.
- **Audit trail:**
  - Every state-changing API call is recorded.
  - Administrators get an **Activity** tab on Users (sign-ins and changes, filters, CSV export) and `GET /api/v1/audit(.csv)`.
  - Scans record who started them.
- **Session hardening:**
  - A password change rotates the session.
  - Over HTTPS the cookie is `__Host-ch_session`.
  - The first-run setup code expires after 24 hours.
- **HTTPS that passes its own scan:** TLS 1.2 limited to ECDHE with AEAD, TLS 1.3 with X25519MLKEM768, and HSTS on
  HTTPS responses. Expected TLS handshake errors are kept out of the log.
- **Inventory scripts** (engine 2.0.1):
  - **Linux engine:** facts file is owner-only (`umask 077`); refuses to run without `mktemp`; no shell expansion of signature patterns.
  - **Windows engine:** facts file readable by its owner, Administrators and SYSTEM only.
  - **Windows run command:** `Unblock-File` with `RemoteSigned` first; Bypass only as a fallback.
  - **Checking a script:** `cipherhorizon scripts list|export DIR` prints and writes the scripts and their SHA-256s
    from the binary; releases attach them under the signed checksums.
- **Operations:**
  - `cipherhorizon db backup FILE` makes an online, owner-only copy.
  - Only the newest three pre-migration backups are kept.
  - A hardened `docker-compose.yml`, `deploy/compose-caddy.yml` (automatic HTTPS) and a sandboxed `deploy/cipherhorizon.service`.
  - [docs/deploy.md](docs/deploy.md) and a [release checklist](docs/engineering/RELEASE-CHECKLIST-1.0.md).
- **The Offset theme** ([DESIGN.md](DESIGN.md) v2):
  - **Look:** Offset's paper, navy and blue; 4px shape; Geist, Geist Mono and Newsreader bundled under the SIL OFL.
  - **Logos:** a flat logo (three bars at Offset's -27.6 degree angle, a keyhole) in colour, on-navy and one colour, also on the PDF cover with the standards it rests on.
  - **The story:** told on the sign-in screen, the Overview and About.
- **Launch materials:**
  - the README, rewritten;
  - a static documentation site (`site/`, GitHub Pages workflow);
  - screenshots made from demo data (`testing/e2e/screenshots.mjs`);
  - launch post drafts.
- **Tests:**
  - fuzzing for uploaded facts files and systems CSV;
  - container and three-distribution deployment scripts (`testing/deploy`);
  - design, contrast, copy and link checks;
  - all wired into CI.

### Security

- `golang.org/x/text` v0.41.0 (GO-2026-6629).
- [SECURITY.md](SECURITY.md) describes the new cookie, setup-code expiry, the bounded password hashing, the sign-in log
  retention, backups and script verification.

### Added (earlier in this cycle)

- **Sign-in and accounts** ([ADR-0018](docs/decisions/ADR-0018-accounts-and-sign-in.md)).
  - **Accounts** with administrator, analyst and viewer roles, enforced on every API route.
  - **Passwords** are salted PBKDF2-SHA256 hashes (600,000 iterations, Go standard library).
  - **Sessions** are server-side, in an HttpOnly, SameSite=Strict cookie (Secure over HTTPS) that is stored only
    as its hash. They end after 30 minutes idle or 12 hours, at sign-out, and on a password change (other
    sessions).
  - **Against guessing:** lockout after five wrong passwords, a per-address rate limit, and one generic error.
  - **First run:** the administrator is created with a one-time setup code printed in the server log.
  - **Administrator-made accounts** get a temporary password that must be replaced first.
  - **Pages and log:** Account (password, active sessions) and Users (accounts, sign-in log), plus a sign-in log
    that never holds a password.
  - **Console recovery:** `cipherhorizon user list|add|reset-password|unlock`.
  - **HTTPS:** served directly with `--tls-cert/--tls-key` (TLS 1.2+); plain HTTP is refused beyond loopback
    unless `--plain-http` (TLS proxy in front).
  - **Defaults:** sign-in is on; `--no-login` keeps the single-user loopback mode. `--token` remains an
    automation token for scripts and CI.
- **Visual redesign** to a written design system, [DESIGN.md](DESIGN.md) (audit:
  [UX-AUDIT-006](docs/product/UX-AUDIT-006-visual-redesign.md)).
  - One flat accent taken from the logo, cool graphite neutrals, and hairlines instead of shadows.
  - One radius system (6/8/12, 4 for badges).
  - Sentence-case labels; mono for machine values.
  - A left-aligned Overview hero with the post-quantum readiness scale as its legend.
  - Status bands instead of grids of identical cards.
  - Report action items grouped so each reason is said once.
  - Calmer motion (one page fade, colour-only hover, loops only while a scan runs).
  - No em-dashes in the interface. Light and dark tuned for WCAG AA.

- **Reports show everything that was evaluated** (PRD-006). An endpoint report has five tabs: **Summary** (the
  verdict, "N checks run: F found a problem, P found none", and action items in plain words: why it matters, how
  urgent, what to do), **Configuration** (a matrix of every TLS version, SSLv2 to TLS 1.3, with the suites each one
  ran by strength, forward secrecy and key-exchange groups; open a version to see its suites; then the certificate,
  key exchange, features and HTTP), **Weaknesses** (every check run, found or not, with evidence, sources and triage;
  the published attacks; how the score was worked out), **CBOM** (the endpoint's CycloneDX CBOM as a table, with
  1.7/1.6 downloads) and **History**. The evaluation records every check it considered (`checks`, rules `eval/5`);
  the PDF adds the version table and the full check list.
- **Machine inventory is signature-driven.** The PowerShell and shell scripts are now small engines with a fixed set
  of read-only capabilities (registry values, certificate stores, files by name, installed programs, matching config
  lines, packages, certificate files; none runs a command). What they collect is a **signature database**
  (`internal/signatures/signatures.json`): 16 signatures, among them Windows Schannel protocols, ciphers and suite
  order, .NET TLS settings, crypto libraries shipped with applications, OpenSSH server algorithms and host key types,
  OpenSSL defaults and the system crypto policy. The server embeds the current signatures in each script it hands
  out, publishes the database (`GET /api/v1/collector/signatures`) and lists every item (what, from where, how, why)
  next to the downloads. Facts carry their signature; library files go through the collector's knowledge base (an
  application's OpenSSL 3.5 shows as able to do ML-KEM), configuration becomes CBOM components, and a signature
  without its own interpreter is still recorded. The machine page shows the configuration found and the software and
  libraries with versions and paths.

- **Inventory a machine with a script, not a program.** Two short, readable scripts replace the collector download:
  `cipherhorizon-inventory.ps1` (Windows PowerShell 5.1+) and `cipherhorizon-inventory.sh` (POSIX shell: Debian,
  Ubuntu, RHEL, Fedora, SUSE, Alpine). The UI shows each one's text and SHA-256 before you download it
  (`GET /api/v1/collector/scripts`, `/api/v1/collector/scripts/{name}`). They are read-only, install nothing, make no
  network connection and never read a private key; they write a plain-text facts file (host, OS, crypto-relevant
  packages, public certificates; certificate files contribute their CERTIFICATE blocks only). Uploading it
  (`POST /api/v1/hosts/ingest`, now also `text/plain`) runs the collector's own sensors and knowledge base on those
  facts, so the result is the same CBOM. The knowledge base now also recognises RPM and Alpine package names
  (`openssl-libs`, `gnutls`, `nss`, `krb5-libs`, …). The Go collector stays buildable from source; it is no longer
  offered as an unsigned download.

- **Real PDF reports.** *Download → PDF* on a report now saves a formatted A4 document made by the server
  (`GET /api/v1/scans/{id}/report.pdf?kind=full|tls|cert`) instead of opening the browser's print dialog: a cover with
  the endpoint and scan, summary figures, Fix first, a section-by-section table, every section with its facts and
  tables (chain as served, trust per store, suites, groups, features, attacks), every finding with its fix, evidence
  and linked sources, how the TLS hygiene score was worked out and how the scan was done; page numbers and a PDF
  outline. The certificate report adds every field of every certificate. **Inventory → Download → PDF** gives the
  inventory report (`GET /api/v1/inventory/report.pdf`). Written by a small PDF writer in the module (standard fonts,
  no new dependency).
- **The Inventory is a dashboard.** It opens on figures, not tables: post-quantum status (a ring), what to replace
  first (quantum-vulnerable algorithms and keys, most used first), algorithms by purpose, protocol versions,
  certificate expiry and the most recent sources (`GET /api/v1/inventory/dashboard`). Each list is a page of its own,
  one click deeper (`#/inventory/algorithms`, `/keys`, `/certificates`, `/protocols`, `/software`, `/sources`);
  certificate keys are named by their common name. The lists now include imported CBOMs, marked as such.

- **A focused product: scan, reports, inventory** (PRD-005, ENG-HANDOFF-004). The interface is reorganised around
  the two jobs the product does. The menu has four entries: **Scan** (the home page: type an address, press Enter, get
  the report), **Reports** (every endpoint with its latest report, a fleet summary, and the fleet's findings and scan
  activity as tabs), **Inventory** and **Systems**. Old addresses redirect to their new place.
  - **Inventory**: every algorithm, key, certificate, protocol and software component seen by your scans, your
    machines and (optionally) imported CBOMs, with its post-quantum status, where it was seen and when; filters by
    name, quantum-vulnerable and source; **Download CBOM** exports the whole inventory as one CycloneDX 1.7 (or 1.6)
    document, each component carrying `cipherhorizon:seen-in`. New read-only routes `GET /api/v1/inventory`,
    `/api/v1/inventory/summary` and `/api/v1/inventory/cbom` (behind the usual token and Origin checks).
  - **Add data**: one dialog for the three ways in (scan an endpoint, inventory a machine, import a CBOM); machine
    uploads and imports are listed under Inventory → Sources.
  - **Reports read in seconds**: the summary and *Fix first* on the first screen, then one line per section (name,
    status, one sentence); sections with a problem are open, the rest closed; evidence and citations behind *Why and
    sources*; *How we tested* in one *About this report* at the end. A report shows about 40 % of the words it did,
    and nothing is lost when everything is expanded. **Download** and **Copy link** sit at the top.
  - The fleet **Findings** list is one line per problem with how many endpoints and machines have it (3,302 words
    before, about 300 now).
  - **Systems** (formerly the Estate home page) keeps the ranked order and the match **Decisions** as a tab; "based
    on evidence only" reads "no owner details yet".
  - A test keeps internal words (estate, asset, service, host, ...) off the primary pages.

- **TLS scanner, phase T1: PKI depth and a self-explaining endpoint page** (PRD-004, ENG-HANDOFF-003). Scans now
  produce `tls-report/2` (a superset of `/1`): each part of the scan is a named **stage** that records whether it
  ran, why not, what it sent and how many connections it made; each served chain is kept **as served** (raw
  certificates in order), with the **stapled OCSP response**, the **SCTs** from the TLS extension, a **no-SNI**
  handshake for named targets, and the **parsed HSTS header**. Evaluation `eval/3` judges them:
  - **trust per root store**: bundled, dated **Mozilla** and **Chrome** root stores from the CCADB (CDLA-Permissive-2.0,
    attributed on the About page), with Mozilla's distrust-after dates and Chrome's `sct_not_after` applied; the
    machine's own store is no longer consulted unless `tls scan --os-trust` is given;
  - a **private CA bundle**: server-wide `serve --ca-bundle FILE`, and per system on the system page
    (`/api/v1/systems/{id}/trust-anchors`; certificates only, an upload containing a private-key block is refused
    unread, every change audited); adding or removing one re-evaluates that system's results at once;
  - **served-chain problems** (missing intermediate, order, extra certificates, an intermediate expiring first, size),
    **lifetime** against the CA/B Forum SC-081v3 schedule (public chains only), **EKU** checks, a weak RSA exponent;
  - the **OCSP staple** (revoked, for another certificate, bad signature, stale, unknown, Must-Staple missing; stapling
    not used only when the certificate names a responder) and **Certificate Transparency** (SCTs from all three
    sources, logs named from the bundled CT log list);
  - **DH groups** matched against the RFC 2409/3526/5114/7919 primes (a shared ≤ 1024-bit group is Logjam);
  - **HSTS** syntax, max-age 0, under a year, duplicates, no includeSubDomains;
  - the certificate served **without SNI** is shown in its own tab and noted (`CERT.NO-SNI-DIFFERENT`, info), but never
    scored as the endpoint's certificate: large sites deliberately serve a placeholder there;
  - **attack names as labels** on the finding that enables them (FREAK, Logjam, DROWN, POODLE, BEAST, SWEET32,
    CRIME, LUCKY13, RC4), never counted twice; a key served on an **SSLv2 endpoint anywhere in the estate** is
    reported on every endpoint that serves it; active-only attacks are listed as *not tested by design*.
  Every new rule is cited; see `docs/methodology.md`. Reference lists, their sources, dates and licences:
  `docs/reference-data.md` (`internal/refdata`, generated by `internal/refdata/gen`).
- **The endpoint page is one sectioned report**: a summary strip (readiness, TLS hygiene, certificate days left and
  stores trusting it, sections not checked), **Fix first** (the three most important findings, ordered by severity and
  then by whether they stop clients connecting), a sticky **section index** whose status is always a word and a symbol,
  and eight sections that each state their purpose, their status, the key facts in sentences, their own findings, all
  the data, and *How we tested*. Certificates & trust shows the chain as served, a validity bar with the lifetime limit,
  a trust row per store and the names checked, with one tab per chain (default, ECDSA, RSA, without SNI).
- **Re-evaluation** without a rescan: `POST /api/v1/scans/{id}/reevaluate` and a *Re-evaluate* button; results
  evaluated by an earlier version show their old layout with that button.
- `GET /api/v1/reference-data` and `GET /api/v1/trust-anchors`, and both on the About page.
- **CycloneDX 1.7 CBOMs** carry `certificateExtensions` (basicConstraints, keyUsage, extendedKeyUsage,
  certificatePolicies) for certificates from `tls-report/2` scans; 1.6 documents, which have no such field, omit them.
- `demo-targets` gains a private-CA target, a broken-chain target and a hostile-certificate target (ports 9448–9450).
- **A new mark**: a gradient shield (the "horizon", violet into amber) with a keyhole cut from it (the "cipher")
  in place of the flat nested-hexagon icon, in the sidebar and on the About page (`web/static/js/dom.js`'s
  `brandMark`). The README leads with an active-TLS-scanner-and-posture-score framing and a six-frame demo GIF
  (ranked Estate → cited reasons → PQC readiness and TLS hygiene on a scanned endpoint → the fleet-wide TLS
  overview → certificates → getting the collector), generated from the running app.
- **`cipherhorizon healthcheck [--addr HOST:PORT]`**: a hidden CLI subcommand that asks a running server's own
  `/api/v1/health`, without a token, and exits 0 or 1. It exists for the container image's `HEALTHCHECK`: the
  distroless base has no shell, curl or wget, so the binary checks itself.
- **`docker-compose.yml`** at the repository root: `docker compose up -d` builds the image locally and starts it
  with a persisted volume; a `.env` file (gitignored) supplies `CIPHERHORIZON_TOKEN`. See
  [docs/engineering/DISTRIBUTION.md](docs/engineering/DISTRIBUTION.md#install).
- **`.dockerignore`**: the build context no longer includes `.git`, local databases, prior builds or docs, which
  were previously sent to the Docker daemon on every build.
- **Estate model, WP-1** (PRD-003, ENG-HANDOFF-002; the first package of the 0.2.0 program). The database gains a
  **system** (the owned unit an owner answers for) above the assets, and an **estate graph**: certificates, algorithms,
  software, providers, protocols, suites and groups as entities, each with observations that say who saw them, how, how
  strongly and when. The graph is a *projection* of the stored scan reports and host uploads, which are never rewritten; it can
  be dropped and rebuilt (`cipherhorizon db rebuild-graph`, `db stats`). The same certificate seen by a scan, a host or
  two endpoints is one entity. Host and network evidence stay separate (ADR-0006); a host observation is never at the
  exercised rung, and a third-party document cannot establish bound, loaded or exercised.
- **System metadata**: owner, environment, criticality, exposure, data lifetime, and the M-23-02 manual items (FISMA
  id, FIPS 199 category, HVA id, hosting). All optional; empty means "not provided". `GET/PATCH /api/v1/systems`,
  CSV export/import (all-or-nothing, every problem named by line), and an append-only **audit log** of every change
  (`GET /api/v1/systems/{id}/audit`; the log cannot be edited or emptied, enforced by database triggers).
- Every asset now belongs to a system. Linking a TLS endpoint to a host merges their systems (refused, naming the fields,
  if both hold different operator-set values); unlinking splits them again.
- Every observation records its **source class** (scanner, collector, imported, operator). A host upload is attributed to the
  collector only when it names this product as its producer; anything else is imported.
- New API routes: `/api/v1/systems*`, `/api/v1/entities`, `/api/v1/graph/stats`. Tests now walk the real route table to
  check that every route needs the token and every mutating route refuses forged, cross-origin and wrongly typed requests.
- **Certificates, WP-2 and WP-3** (PRD-003 REQ-CERT; ADR-0015, ADR-0016; `docs/host-discovery/stage-3-certificates-report.md`). Two new sensors describe the X.509
  certificates a host holds, **public metadata only, never a key**: `cert-files` (Linux trust stores and service
  directories) and `windows-certs` (the MY, Root, CA, TrustedPeople, TrustedPublisher and AuthRoot system stores, for the machine
  and the current user, through a new bounded, read-only, reviewed layer in `internal/winapi`). Each certificate carries its **key
  size and curve**, validity, signature algorithm, names, and whether a private key is associated at each place it was found. Key
  files are never opened and key blocks are never decoded; a test plants decoy keys and asserts no byte of them travels.
  A certificate a server presents and the same certificate a host holds are **one entity** with several places (shared
  `internal/certinfo`, one CBOM builder for both, in the standard's shape: the certificate points at a public-key component with its
  `size`).
- `GET /api/v1/certificates`, `/api/v1/certificates/{fingerprint}`, `/api/v1/systems/{id}/certificates`: end-entity certificates itemised with cited findings
  (expired, expiring, not yet valid, weak key, broken signature hash, and a quantum-vulnerable key in a certificate that outlives 2030 or 2035 per
  NIST IR 8547); roots and intermediates **summarised**, with any change to a host's set of roots reported. Key size is `null` with a note when no source
  recorded one; it is never guessed.
- Every sensor's counted limits (files not opened, certificates that could not be parsed, budgets hit) are now written into the CBOM as
  `cipherhorizon:coverage-limit` properties, so a reader sees how much was left out, not only that something was.
- Independent oracles: `compare-certs.ps1` (Windows, .NET `X509Store`; agrees on this machine, five negative controls caught) and `compare-certs.sh`
  (OpenSSL; agrees on a real Linux-style tree of Mozilla CA bundles; not yet run on a live Linux host).
- **Third-party CBOM import, WP-4** (PRD-003 REQ-ING; ADR-0017; `docs/importing.md`). `cipherhorizon import` and `POST /api/v1/imports` accept CycloneDX 1.6 and 1.7 CBOMs from CBOMkit, CBOM-Lens, cdxgen, Theia and others,
  validated against the specification's schema (embedded), after limits on size, depth, values and strings. **You name the system**; the document's own claim about its subject is only recorded. Imports are read as
  capability from source, or presence from a host or network scan, never as use, and **never as first-party**: an import can add to the estate graph but not overwrite what a scan or collector observed, and any
  disagreement is recorded and shown. Everything not modelled is counted by reason; keys and secrets found by other tools are counted and not stored. Provenance is recorded and audited; imports can be withdrawn.
  Checked on real CBOMkit, CBOM-Lens 1.6/1.7 and Theia documents (all validate; every component accounted for).
- **Correlation, WP-5** (PRD-003 REQ-COR). The product now proposes which TLS endpoint belongs to which machine, from exactly three deterministic rules: the endpoint's leaf certificate is held on a host (SHA-256), the endpoint's host name is the
  machine's name, the certificate names the machine. Each proposal is a reviewable **link** with the values that matched, a strength from a fixed table (never a score), and a state. Only a strong, unambiguous match made
  entirely of the product's own scanner and collector data joins on its own; everything else, and everything involving an imported document, is a proposal for a person (`GET /api/v1/links`, `POST /api/v1/links/{id}/confirm|reject`). A
  certificate on several hosts is shown as ambiguous and joins none; one on more than 25 systems is treated as shared infrastructure and joins nothing; chain and CA certificates never join; a rejected link is never proposed again; a confirmed join that
  loses its evidence is flagged for review, not undone; a join that would overwrite different values a person entered is refused with the fields named. The manual links of 0.1.0 are now confirmed links. Every decision is audited.
- **Prioritisation, WP-6** (PRD-003 REQ-PRI). `GET /api/v1/estate` ranks systems for post-quantum migration by four ordered, cited rules: recorded traffic exposed to
  harvest-now-decrypt-later against how long the data must stay secret, how exposed the system is, certificate and TLS defects, and how strong the evidence is. There is no composite
  score. Every row lists the rules and citations behind its place and says when it rests on evidence alone because nothing was entered; a system with no scan is not reported as safe, and a system known only from an
  imported document is ranked after what was observed and labelled a lead. The rules are published with the ranking and in `docs/methodology.md`.
- **CycloneDX 1.7, WP-7** (PRD-003 REQ-EXP-1, 2). CBOMs are written as **1.7 by default**; `--spec 1.6` (or `output.spec`) writes 1.6 for consumers that have not moved, and the scan CBOM route takes `?spec=`.
  Deprecated constructs are replaced, not doubled (`relatedCryptographicAssets`, `ellipticCurve`); `algorithmFamily` is set only where the registry has one, and the five catalogue entries without one are
  listed in `docs/exporting.md`. Both versions are validated against their vendored schemas. The importer reads 1.7's `relatedCryptographicAssets`, so a 1.7 document from another tool keeps its key sizes.
- **M-23-02 structure** (REQ-EXP-3): `GET /api/v1/systems/{id}/m2302.json` and `.csv` give the nine items for a system, each marked provided or not provided and by whom. It supports the structure; it does not claim compliance.
  Not yet covered: the supplier of software (item 5). The operating system (item 6) comes from the machine's own collector upload.
- **OpenAPI 3.1** (REQ-EXP-5): `GET /api/v1/openapi.json`, written by hand, with tests that fail when it and the route table disagree or a GET route answers a status it does not list.
- **The estate UI, WP-8** (PRD-003 REQ-UI; `docs/product/UX-DESIGN-002-estate-ui.md`). The home page is now the **Estate**: systems in the order to
  look at them, each row expandable to its four cited rules and marked when it rests on evidence alone. New pages: a **system** (why it is
  ranked there, a details editor with an audit trail, services and machines with per-endpoint CBOM download, certificates with key sizes, matches with undo,
  imported sources, coverage, M-23-02 export, history), **Certificates** (filter by expiry, key, signature, origin; trust anchors summarised; changes to a machine's roots),
  **Review** (proposed joins with the matching rule and values; confirm or reject with a reason; a count in the menu) and **Imports** (choose a file, name the system,
  see the detected producer and what was not interpreted). The first run offers three doors: scan a service, inventory a machine, import a CBOM. `GET /api/v1/estate`
  rows now say how a system is known (`evidence`), and certificates say which kinds of source observe them (`origins`).
- **Menu, download and visual pass** (direct feedback on WP-8: the menu was hard to follow, there was no way to get the collector
  from the browser, About read as a wall of reference text, and the interface looked generic). The menu is now two labelled
  groups (Manage: Certificates, Review, Imports; Monitor: Endpoints, Hosts, Findings, TLS overview) under the single Estate
  home link, with About and a new **Get the collector** action moved to the sidebar footer, off the data menu. `GET
  /api/v1/collector/binaries` and `GET /api/v1/collector/binaries/{name}` let the running server hand out a collector binary
  placed beside its own executable (or in a `collectors/` folder there, one per platform) directly from the browser — the "How
  do I collect?" dialog and the About page both offer it, with its checksum, and say plainly when none is on disk. About now
  opens with a proper header instead of starting straight into reference tables. A colour identity (an indigo–violet primary,
  a warm accent used sparingly for the estate's top ranks and the first-run doors) replaces the generic interface blue.
- Every database transaction is now opened IMMEDIATE, so concurrent writers queue instead of one failing with "database is locked".
- Documents: RESEARCH-003, PRD-003, SECARCH-001, REQ-REVIEW-001, ENG-HANDOFF-002, QA-PLAN-002, ADR-0014 and a program
  tracker with a requirements traceability matrix that a test keeps consistent (`docs/program/`).

### Changed

- **Navigation rebuilt around one place per kind of thing** ([UX-DESIGN-005](docs/product/UX-DESIGN-005-navigation.md)).
  A **Scan a URL** button tops the sidebar on every page. The menu is **Overview**; *Results*: **Endpoints**,
  **Machines**, **Findings**, **Inventory**; *Plan & share*: **Systems**, **Reports**. Overview keeps the scan box on
  top and adds six tiles (endpoints, machines, findings, post-quantum, inventory, next certificate expiry), the latest
  results and what to fix first. **Reports** is now the documents page: the inventory PDF and CBOM, the security, TLS
  and certificate PDFs and the CBOM of every endpoint, each machine's CBOM, the endpoint and system CSVs and the OMB
  M-23-02 files, each one click away. Machines and Findings have their own pages (they were under Inventory › Sources
  and a Reports tab); scan activity is a tab of Endpoints. Detail pages start with a breadcrumb and light up their home
  in the menu. Old addresses (`#/reports/N`, `#/hosts/N`, `#/reports?tab=findings`, …) still land.
- **Results say what happened, not only what was looked for.** A check that passed states what it confirmed ("The
  certificate has not expired", "TLS 1.0 is switched off") instead of "Certificate has expired: not found" (rules
  `eval/6`, `Check.pass`); Weaknesses groups each area into Found, Passed and Not run, with a filter for each and a
  visible Details toggle on every finding. In Configuration each TLS version says its state and whether that is right
  ("Enabled · should be off", "Disabled · good", "Disabled · should be on"), under a one-line summary of what is
  enabled; each enabled version has a "Show suites" toggle. The PDF uses the same words.
- **Reports list.** Five tiles answer the first questions (endpoints, post-quantum, TLS hygiene, findings, the next
  certificate expiry); the add, scan and export actions sit with the filter; a whole row opens its report, and each
  row has an "Open report" button; certificate expiry reads "44 days left".

- **The endpoint report is reorganised** (UX-DESIGN-004). Three tabs: **Summary** says whether the endpoint is OK and
  what to fix (a headline such as "7 things to fix", the four figures, then every finding to act on once, worst first,
  each opening to its fix, what was seen, its sources and triage; informational notes in a closed list; then one
  checklist row per area); **Details** shows what the server accepts, one card of facts and tables per area, never a
  finding card (a card names its issues and links back to them); **History**. The Findings tab is gone (its address
  opens the Summary's fix list). The header keeps *Scan again* and *Download*; copy link, rescan schedule, edit, link
  to a machine and delete are in one *More* menu. The Vulnerabilities card is one table (attack, possible here or
  not, why), without internal rule IDs.

- **The HTTP check (HSTS) is on by default**, on `serve` and on `tls scan`; `--http-checks=false` turns it off. It
  still sends one `GET /`, reads at most 8 KiB and follows no redirect; a skipped HTTP section says why.
- `CERT.UNTRUSTED` fires only when no bundled store and no private anchor trusts the chain; when stores disagree,
  `CERT.PARTIAL-TRUST` names them. `CERT.EXPIRING` scales with the certificate's lifetime (min(30 days, ⅓) medium,
  min(7 days, ⅒) high). `CERT.EXPIRED`, `CERT.UNTRUSTED` and `CERT.NAME-MISMATCH` are marked as stopping clients.
- A scan contacts only the target (asserted by test): the OS certificate verifier, which on some systems fetches
  missing intermediates, is no longer run by default.
- Database migration 7 adds the `trust_anchors` table.
- The collector may now link `crypto/x509` (and through it `net`); the rule that the collector links no network package is tightened to "only through `crypto/x509`, and no
  package of this module imports it", checked on both platforms (ADR-0015). For an overridden `--root` the host filesystem is now a traversal-resistant view, so a
  symbolic link in a tree we do not control cannot lead a sensor out of it.
- `evidence.Validate` now rejects control characters in attribute values for every kind (it accepted them before; the sensors cleaned their input, so nothing exploited it).
- A scan's final event is recorded in the same transaction as its result, so a finished scan can never be seen without its summary line.
- The old Dashboard is now **TLS overview** under Sources, and the CBOM page is no longer in the menu (its address still works). Endpoints and Hosts are views of a system.
- The default CBOM version is now 1.7 (was 1.6). Pass `--spec 1.6` to keep the old output.
- The database migrates to schema version 4 on first start. **An automatic, owner-only copy of the previous database is
  written next to it first** (`<db>.bak-v3-<time>`); if the copy cannot be made, nothing is changed.
- The `artifacts/` directory (QA/release evidence from the first milestone, under the project's pre-rename name)
  is no longer tracked in git; `.gitignore` now excludes it wholesale, matching how `testing/e2e` and the
  Makefile already treat it as regenerable, not shipped. The durable write-up of that evidence lives in
  `docs/product/` and `docs/program/` instead.
- The sidebar no longer names Offset Security under the CipherHorizon wordmark; the credit stays once, in the
  sidebar footer, where it already was.

### Removed

- The browser no longer asks for, or keeps, the API token (it was readable by scripts in session storage); browsers
  sign in instead.
- Gradient buttons, glows, the radial page wash, hover lifts and the bobbing empty-state icon.

- The TLS overview dashboard page and the old stand-alone CBOM page (PRD-005). Their addresses redirect to Reports
  and Inventory; their counts live in the Reports fleet summary and the Inventory summary.

### Fixed

- **Sign-in lockout (security).** A locked account no longer checks the password: the right password and a
  wrong one get the same generic answer, so a guesser cannot learn during the lock which guess was right, and
  guesses during a lock no longer extend it. The refusal message now covers the locked case too.
- **Sign-in rate limits behind a proxy.** Limits are counted per client address (50 failures) and per client
  and account (10), so one person's mistakes behind a shared address no longer lock everyone out. New
  `serve --trusted-proxy ADDR|CIDR` (repeatable) reads the real client from `X-Forwarded-For` for limits and
  the sign-in log; from any other peer the header is ignored. The limiter no longer empties itself when full.
- **A bug in the scanner fails one scan, not the server.** Panics in the prober (including its goroutines),
  in evaluation and in start-up re-evaluation are recovered, logged with their stack, and the scan is marked
  failed with "internal error".
- **Nothing the runner or the graph fails to do is silent any more:** store errors are logged; a projection or
  correlation that fails marks the graph stale, and it is now repaired every five minutes rather than at the
  next start.
- **Host uploads** get the import limits (nesting depth, value count, string length) before they are decoded,
  at most two large uploads are parsed at once, and stored uploads are bounded by bytes: 256 MiB per host
  (oldest dropped first) and 8 GiB in total (an upload past it is refused with 507).
- **Scale:** retention removes the graph rows of the scans and uploads it deletes instead of sweeping every
  table after each scan; correlation runs triggered at the same time are coalesced; the DROWN shared-key check
  reads an index from the graph instead of decoding every stored report on every evaluation.
- **Times sort as times.** Stored times are now always written with nine fractional digits (migration 10
  rewrites existing rows; a backup is kept), so comparisons in SQL are right within a second.
- **Queued scans survive a restart**; only scans that were running are marked failed.
- Large downloads (collector binaries, CBOMs) are no longer cut off after 60 seconds, and collector binaries
  are hashed once rather than on every request.
- `cipherhorizon import` refuses to send the token over plain `http://` to another machine
  (`--allow-plain-http` overrides). `cipherhorizon healthcheck --tls` probes an HTTPS server.
- The About page and `serve --help` described the access model from before sign-in; both now say how it works.
- `golang.org/x/text` updated to v0.39.0 (GO-2026-5970, not reachable from this code); the container's base
  images are pinned by digest.
- The Reports list showed "none" under Findings for an endpoint whose findings were all medium or low (Google: 4
  medium and 3 low). It now counts every severity, and says "No problems" only when there are none. The database
  gains low and informational counts (migration 8, filled from stored evaluations; a backup is kept as for every
  migration).

- A Vulnerabilities section showed a green "Good" while listing an attack as exposed (LUCKY13 on CBC suites, whose
  finding is informational). Such a section is now "Needs attention", and each attack line states its result
  ("Possible: the server accepts CBC suites…" / "Needs TLS 1.0 with CBC suites; not seen on this server.") instead
  of only its condition, which read like a finding ("BEAST — TLS 1.0 with CBC suites"). Rules are `eval/4`; on
  start the server re-evaluates each endpoint's latest result made by older rules, so existing reports change
  without a rescan.
- Finding details named the same cipher suite once per protocol version ("3DES, 3DES, 3DES"); they now name each
  suite once and say which versions accept it.
- A failed scan with no earlier result showed an empty chart around the error. It now shows one card: why the scan
  failed in plain words (nothing listening, name does not resolve, no answer, not TLS), the technical message, and
  *Scan again*.

- A scan could be seen as finished a moment before its certificates and proposed joins were derived from it; they are now derived in the same transaction as the result.
- The About page's brand mark was invisible (built with the HTML-element builder instead of the SVG one, so
  nothing rendered inside its gradient tile); fixed as part of the new mark.


### Added (to 2026-09-26)

- **Windows collector, stage 2: native cryptography** (`docs/host-discovery/stage-2-report.md`, ADR-0013): a new
  `windows-cng` sensor **asks Windows** what it provides: the CNG algorithm registry and providers, key storage
  providers and legacy CSPs, with each algorithm attributed to the provider that offers it (`capable`, `probed`).
  Post-quantum parameter sets (ML-KEM 512/768/1024, ML-DSA 44/65/87) are confirmed by asking Windows to accept them,
  which generates an ephemeral in-memory key pair per parameter set (never exported or stored), limited to those two
  families. Only the in-box software key storage provider is ever opened; Platform/TPM, Smart Card, Passport, Pluton and
  third-party providers are listed by name and never loaded. The sensor runs only for a live Windows host, never for a
  `--root` override or an image.
- A new platform package, `internal/winapi`, holds every Windows cryptography call (hand-written, bounded, reviewed:
  `docs/host-discovery/stage-2-security-review.md`); the architecture test now allows only it and `hostinfo` to use
  `unsafe` or `x/sys/windows`.
- Catalogue: SHA-1, MD5, MD4, MD2, SHA3-256/384/512, RC4, RC2, DES, 3DES and the ML-KEM and ML-DSA families, with OIDs
  read from their sources. Retired algorithms carry a **cited classical status** (RFCs 6149, 6150, 6151, 6194, 7465, FIPS
  46-3 withdrawal, NIST's 2017 TDEA notice), kept apart from the post-quantum verdict; an algorithm with no verdict must
  say why, and a test enforces it.
- UI: a "Retired or broken algorithms" card on the host page, and the sensor named "Windows cryptography (CNG)".
- `testing/hostdiscovery/compare-cng.ps1`: an independent oracle for the native inventory (C# P/Invoke, `certutil`).

- Host inventory: plugin registry and collector interface, an `apt` collector, a CycloneDX 1.6 CBOM builder
  with closed-vocabulary enforcement, cited post-quantum algorithm verdicts (`internal/pqc`), a one-shot CLI
  (`cipherhorizon run`).
- Active TLS/SSL scanner (`cipherhorizon tls scan`): an own TLS/SSLv2 wire-protocol implementation
  (`internal/tlsprobe/wire`), so it can probe what a linked TLS library cannot (SSLv2/3, export/NULL/anonymous
  suites, arbitrary key-exchange groups); protocol version detection, full cipher-suite and group enumeration
  including post-quantum hybrids (`X25519MLKEM768` and others), certificate retrieval and trust/name checks,
  IANA registries generated from the official CSVs.
- Evaluation (`internal/eval`): cited findings, a PQC readiness level (L0-L4) with harvest-now-decrypt-later
  exposure, a TLS hygiene score (0-100, five bands) derived only from the findings on a result, scan-to-scan
  diff. Both scales are this project's own and share no terminology or tables with another scanner's rating.
- **CBOM export for TLS endpoints** (`cipherhorizon tls scan --cbom`): turns an active scan into a CycloneDX
  1.6 CBOM (protocols, cipher suites, key-exchange groups including hybrid post-quantum combiners,
  certificates), PQC-annotated the same way a host inventory's CBOM is.
- Web server and UI (`cipherhorizon serve`): a JSON API, a scan runner and scheduler, SQLite storage,
  loopback-by-default with token auth and CSRF/SSRF protections, and a dependency-free web UI (dashboard,
  endpoints, scans, hosts, about) embedded in the binary.
- `cmd/demo-targets`: development-only servers of known TLS posture, for trying the product and for QA without
  scanning a third party.
- A browser end-to-end test (`testing/e2e/journey.mjs`) and a live security check script
  (`testing/e2e/security.sh`), both run in CI.

- Release engineering: tag-triggered release workflow (GoReleaser archives for Linux/macOS/Windows on
  amd64/arm64, SHA-256 checksums, SBOMs, keyless cosign signature, build-provenance attestation, multi-arch
  distroless container image on GHCR), CI expanded (Windows/macOS tests, govulncheck, release dry run), CodeQL,
  dependency review, Dependabot, `Makefile`, `cipherhorizon version` reporting commit and build date, and the
  branching/release/distribution documentation under `docs/engineering`.
- UI polish: a restrained motion system (one-shot page and tab entrance, chart draw-in, count-up figures,
  animated dialogs and toasts, live-state indicators) that honours `prefers-reduced-motion` and never replays on
  the timed refreshes, a copy-to-clipboard control on certificate serials and fingerprints, and the running
  version in the sidebar.

- Endpoint CBOM model, reworked after review (see `docs/cbom-model.md`): bulk ciphers are key-size-and-mode
  variants with NIST OIDs (`AES-128-GCM`, `AES-256-CBC`, ...) instead of one `AES`; a certificate's
  `subjectPublicKeyRef` now points at a `related-crypto-material` public key with its size and algorithm
  (`RSA-2048`, `ECDSA-P256`) rather than at an algorithm; the endpoint depends on its protocols and certificates;
  certificates carry their chain role; the negotiated flag now covers the negotiated suite's cipher, key exchange
  and authentication; and the document states what its edges mean.

- Host discovery rebuilt as an **evidence pipeline** (`docs/host-discovery-program.md`, ADR-0001 to ADR-0010):
  sensors observe and never infer; capability is applied afterwards from cited knowledge; no claim is stronger than
  the weakest evidence it rests on; the document states its coverage, blind spots and privilege. `cipherhorizon run`
  now also works on **Windows** (`pe-files` sensor: loose crypto libraries such as a bundled OpenSSL, read from
  their version resource by a hand-written, fuzzed PE reader; no key or credential file is ever opened), warns when
  it runs without Administrator/root (results may be incomplete), and has `--redact-host`. Debian/Ubuntu output is
  unchanged (proven against the frozen pre-refactor output).
- `docs/decisions` (architecture decision records), `testing/hostdiscovery` (ground-truth scripts) and
  `artifacts/agent-*`, `gate-decision-level-1.md` (the research, review and test record).

- **`cipherhorizon-collector`**: a separate ~4 MB program for endpoints (`run`, `plugins`, `version` only) that links no
  web server, database, TLS scanner or HTTP/TLS client, enforced by a test (ADR-0011). Published for the same six
  platforms next to the full product. The TLS CBOM builder moved to `internal/tlscbom` and the UUID library was
  replaced by `crypto/rand`, which removed the scanner and the network package from the collector's dependency set.

- **A guided first run.** The empty dashboard now offers two clear ways to begin (check a server's TLS, inventory
  a machine); the Hosts page teaches the three-step collector loop with copyable Linux and Windows commands and an
  upload command for automation; the dashboard states one **next step** chosen from the data; the servers' and the
  collector's command-line output ends by saying what to do next.
- **Inventory coverage on the host page.** The privilege tier, operating system, per-sensor result, unreadable
  locations and blind spots the collector records are now shown (and on the Hosts list as *Full access* / *Limited
  access* / *Not recorded*), with a plain route to re-run with full rights. A CBOM that records none of this is
  shown as *Not recorded*, never as complete.
- A design refinement in the spirit of calm, clear interfaces: softer surfaces and shadows, larger radii, quieter
  navigation, six KPI cards as three by two (two per row on a phone), disclosure for long rationale, and
  jargon explained where it first appears. Tokens and new components only; the strict CSP and every route are
  unchanged, and `#/endpoints` now also opens the endpoints page.
- The audit record: `docs/audit` (security audit, usability audit, gap analysis, UI direction, PM decision,
  QA report, release gate).

### Security (to 2026-09-26)

- The SQLite database (and its `-wal`/`-shm` files) is created owner-only (`0600`) and an existing one is
  tightened on start; the collector's CBOM file is written `0600` (POSIX).
- Access tokens shorter than 16 characters are refused at start; failed authentication is logged (method, path,
  remote address, never the value) and delayed 250 ms.
- The SSRF guard also refuses `0.0.0.0/8` and NAT64 (`64:ff9b::/96`) spellings of blocked IPv4 addresses.
- Host names on upload must be printable UTF-8 without control or bidirectional-override characters.
- `Permissions-Policy` is sent on every response; workflow checkouts no longer persist the job token.

### Changed (to 2026-09-26)

- Host components now include providers (`library`, `cipherhorizon:provider-kind`); "software components" on a Windows
  host therefore counts them.

- Knowledge table revision 2: a file that only uses a family's implementation is no longer credited with the
  family's algorithms (Windows loose files only; Debian output is unchanged and tested against the frozen goldens).
- Project renamed from the working name `cbom-scan` to **CipherHorizon**, to avoid any confusion with a
  specific document type ("a CBOM") and to give the whole platform (inventory, TLS scanning, readiness,
  posture) one name.
- The TLS rating was redesigned from an SSL-Labs-style A-F letter grade to **TLS hygiene**, a 0-100 score
  derived only from a result's own cited findings, with its own bands (Strong/Sound/Fair/Weak/Broken) and no
  shared terminology or scoring tables with any other scanner's rating.

### Known limitations

- **Machines:** the host collector has run on Windows (standard user) and in fixture and shim tests for Linux; it has
  not run on a live Linux host or with Administrator/root rights. macOS machines are not inventoried. The native
  Windows inventory (`windows-cng`) has run on one Windows 11 machine only, and states what Windows offers, not what is
  enabled or used.
- **TLS:** validated against hermetic test servers and, for trust, against OpenSSL; a matrix of real TLS stacks
  (nginx, Apache, Postfix) is not yet recorded. No active vulnerability probes (Heartbleed, ROBOT), by design.
- **SSH:** checked against real OpenSSH 9.2 and 10.0. Servers that offer only `diffie-hellman-group18-sha512`,
  group exchange or sntrup761 are judged on their algorithm lists; their host keys are not fetched. One SSH
  baseline ships; BSI TR-02102-4 is planned. SSH clients are not audited.
- **Storage:** SQLite only. Up to 50 snapshots of up to 32 MiB are kept per machine; there is no overall storage
  budget yet.

[Unreleased]: https://github.com/offsetsecurity/cipherhorizon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/offsetsecurity/cipherhorizon/releases/tag/v0.1.0
