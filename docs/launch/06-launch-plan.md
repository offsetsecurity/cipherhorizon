# 06 · Launch plan: what is missing, what to build, how it will be tested

2026-10-08. Built on [01 security audit](01-security-audit.md), [02 market research](02-market-research.md),
[03 UX review](03-ux-review.md), [04 deployment](04-deployment.md) and [05 brand and messaging](05-brand-and-messaging.md).
**Nothing in this plan is coded until it is agreed.**

## Workflow

1. **Research** (this folder): done.
2. **Agreement:** the owner decides the questions in §4 and approves the scope in §2.
3. **Specification:**
   - PRD-007 (requirements and acceptance criteria per feature);
   - DESIGN.md v2 (the Offset theme);
   - the engineering hand-off;
   - QA-PLAN-007 (a test for every acceptance criterion).
4. **Build:** in the work packages below; each ends with its tests green.
5. **QA:** the full automated suite, plus a visual review in light, dark, tablet and phone, plus the launch checks
   in §3; results in QA-REPORT-007.
6. **Release candidate:**
   - a release dry run on a fork;
   - the launch materials;
   - the owner's go/no-go.

## 1. What is missing for a launch (from the research)

| # | Gap | Source |
|---|---|---|
| 1 | Nothing is published (release, image, docs site); the README and GIF are out of date | 03, 04 |
| 2 | Repository placeholders (module path, security contact) | Audit B-01, B-02 |
| 3 | Supply chain: script hashes only from the server; release pipeline never run | Audit L-04, L-05 |
| 4 | The product's own HTTPS fails its own checks (CBC suites, no HSTS) | Audit L-06 |
| 5 | The CLI gives no verdict or CI exit code | 02, 03 |
| 6 | No STARTTLS (mail, LDAP, etc.) | 02, 03 |
| 7 | The product does not advertise its USPs; the brand is not Offset's; the logo has gradients | 05 |
| 8 | No scan scope, no action audit trail, no MFA | Audit L-01..L-03 |
| 9 | No notifications, no discovery, no fleet trend, no config snippets, no report branding | 03 |

## 2. Proposed scope

### Release 1.0, the public launch: work packages

| WP | Content | Acceptance (summary) | Size |
|---|---|---|---|
| **WP-1 Identity and trust** | Rename to the chosen GitHub organisation; real security contact; script hashes in signed release notes and pointed to from the UI (L-04); quick hardening L-07..L-16; `x/text` upgrade | `go install` and image names resolve; every L-07..L-16 item has a test or a check in `security.sh` | M |
| **WP-2 Passes its own scan** | AEAD-only TLS 1.2 suites, HSTS on TLS responses (L-06) | An automated test scans the product's own HTTPS listener and finds **no finding**; L3 or better | S |
| **WP-3 Offset theme and flat logos** | DESIGN.md v2 with the Offset tokens; Geist, Geist Mono and Newsreader bundled; the flat logo (chosen concept) in three versions; favicon; the rail, buttons, badges and charts re-tokened; PDF cover lockup | Visual review in light, dark, tablet and phone; WCAG AA contrast check on every token pair; no gradient left (a CSS lint check) | M |
| **WP-4 The product tells its story** | Sign-in value panel; Overview eyebrow and headline; About as a product page; empty states with one line of why | The journey asserts the pillars on sign-in, Overview and About; copy checked for no em-dashes and no banned words | S |
| **WP-5 CLI verdict and CI** | `tls scan` prints the evaluation (readiness level, hygiene score, findings) by default; `--json` includes it; `--fail-on level<L3`, `--fail-on severity>=high`; documented exit codes; a GitHub Actions example | Golden-output tests; exit-code table tested against demo targets | M |
| **WP-6 STARTTLS** | SMTP, Submission, IMAP, POP3, FTP, XMPP, LDAP, PostgreSQL negotiation before the handshake, for every probe; `--starttls` and an automatic choice by well-known port; UI field | A demo STARTTLS server per protocol; the scan matches a direct-TLS scan of the same server | L |
| **WP-7 Deployment** | Published multi-arch image; README quick start; production compose with Caddy and hardening; systemd unit; `db backup`; verified with Podman; Linux script verified on Debian, UBI and Alpine | A container smoke test (`testing/deploy/smoke.sh`): build, start, set up, scan, back up; the script run in three distributions in CI | M |
| **WP-8 Launch materials** | README rewrite; docs site (GitHub Pages, Offset theme); re-recorded GIF and screenshots; comparison table; launch posts drafted | Links checked; quick start run from a clean machine | M |
| **WP-9 Scope and accountability** *(recommended for 1.0)* | Scan scope allow-list (L-01); action audit trail with an administrator view and CSV (L-02) | A scan outside the scope is refused at add and connect time; every state change writes one audit row (tested per route) | M |

### Release 1.1, enterprise-ready (after launch, unless pulled forward)

- TOTP MFA (L-03), then OIDC single sign-on.
- Notifications (webhook first, then email) for certificate expiry and regressions.
- Discovery: CIDR and domain expansion, and a CSV import of hosts.
- Fleet trend over time.
- Config snippets per server (nginx, Apache, IIS, HAProxy, Caddy, OpenSSL).
- Report branding (client, assessor, logo).
- Standards views (CNSA 2.0, the NIST IR 8547 lists).
- A public demo instance.

## 3. Quality: how "it works" is proven

| Layer | What runs | Gate |
|---|---|---|
| Unit and integration | `go test ./...` with new tests per WP; fuzz targets for the facts parser and CSV import (L-15) | All green; coverage reported per package |
| Static and supply chain | golangci-lint (gosec), govulncheck, CodeQL, dependency review | 0 issues; no reachable vulnerability |
| Browser journey | `journey.mjs` with new checks per acceptance criterion (sign-in panel, theme, STARTTLS in the UI, audit view, scope refusal) | All green, including 390px and dark |
| Security | `security.sh` extended (cookie prefix, HSTS, scope, audit, rotation on password change) | All green |
| Self-scan | A test scans the product's own HTTPS with the product | No finding |
| Deployment | `testing/deploy/smoke.sh` (Podman/Docker); Linux script in three distributions | Green on Linux CI and here |
| Visual | Screenshots of every page, light, dark, tablet, phone; contrast check | Reviewed against DESIGN.md v2 |
| Release | A pre-release tag on a fork; cosign, SBOM and provenance verified from a clean machine | Verified |

## 4. Decisions needed from the owner

1. **GitHub organisation and module path** (for example `github.com/offsetsecurity/cipherhorizon`) and the
   **security contact** address.
2. **Logo concept:** A (flat hexagon), B (horizon parallelograms) or C (hexagon with a horizon band).
3. **Adopt the Offset design system** (palette, Geist, Geist Mono, Newsreader). This needs permission to download
   the three OFL font families once and bundle them.
4. **Scope of 1.0:** WP-1..8, plus WP-9 (recommended)? Pull anything from 1.1 forward?
5. **Validation downloads:** permission to pull the pinned base images (`golang`, `distroless`) and the Debian,
   UBI and Alpine images with Podman for the deployment and script tests.
6. **Public demo instance:** wanted for launch? If so, who hosts it?

## 5. Decisions (owner, 2026-10-08)

| # | Decision |
|---|---|
| 1 | GitHub organisation, module path and security contact: **decide later**; the rename is the last step before release (WP-1 proceeds without it) |
| 2 | Logo: **concept B, horizon parallelograms** |
| 3 | **Adopt the Offset design system**; download and bundle Geist, Geist Mono and Newsreader (OFL) |
| 4 | Scope of 1.0: **WP-1..9** (scan scope and action audit trail included); MFA, notifications and the rest stay in 1.1 |
| 5 | **Container images may be pulled** with Podman for the deployment and Linux-script validation |
| 6 | Public demo instance: not decided; stays in 1.1 |
