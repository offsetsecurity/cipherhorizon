# 01 · Security audit (launch, 2026-10-08)

**Scope:** the product at `16dbc82`, which includes:
- the server, API and sign-in (ADR-0018);
- the web UI;
- the TLS scanner's network behaviour;
- the machine-inventory scripts and signature database;
- uploads and imports, PDF and CSV generation, storage;
- the container image, the release pipeline, and repository hygiene.

**Method:**
1. **Read the code paths that handle untrusted input or decide access.**
2. **Re-check every security suppression.**
3. **Run tools:** govulncheck, and gosec through golangci-lint.
4. **Probe a live instance.** These probes are reproducible with `testing/e2e/security.sh`, which passes 110/110.
5. **Fuzz the new facts-file parser.**
6. **Scan the product's own HTTPS listener with the product.**

**Not covered:**
- A third-party penetration test.
- The release pipeline end to end; it has never run.
- The Linux inventory script on a real Linux host.

Severity is judged for a self-hosted tool that holds an organisation's map of weak cryptography, deployed by a team
behind sign-in. *Launch blocker* marks an item that is not a vulnerability but must be done before a public
release.

## Verdict

**No critical or high vulnerability.** The core controls hold. There are **5 medium** findings: three about
accountability and scope in a multi-user deployment (scan scope, action audit trail, second factor) and two about
supply chain (scripts that run as root, a release pipeline never exercised). There are 11 low findings and 3
informational ones, and **3 launch blockers** in repository hygiene.

## Controls verified as working

| Area | Control | Evidence |
|---|---|---|
| Authentication | Salted PBKDF2-SHA256 (600k iterations); one generic error; the same hashing work for unknown accounts; a locked account is refused before its password is checked; lockout plus per-client and per-client-and-account limits; at most 4 concurrent hashes | read `internal/auth`, `accounts.go`; `accounts_test.go`; `security.sh` |
| Sessions | 256-bit random token, stored only as SHA-256; HttpOnly, SameSite=Strict, Secure over HTTPS; new token at every sign-in; idle and absolute expiry; server-side sign-out; disable or role change ends sessions | read; tests; `security.sh` cookie flags |
| Authorisation | One central check (`authorize`) for every route: viewer read-only, accounts and audit trail for administrators, forced password change first | read; `TestRolesAndAccountAdministration`; E2E-A.8 |
| First run | Administrator only with a one-time code from the server log; atomic insert, so a race cannot make two | read; tests |
| Cross-site forgery | Required custom header, same-origin `Origin`, `Sec-Fetch-Site`, JSON-only bodies; covers sign-in too (no login CSRF) | `security.sh` |
| Injection into the page | No `innerHTML`, `eval` or inline handlers in the UI; every string through `textContent`; every `href` through `safeHref` (in-app routes and `https://` only); strict CSP, no inline script or style | grep; `dom.js` |
| Response headers | CSP `default-src 'none'`, `frame-ancestors 'none'`, nosniff, `X-Frame-Options`, COOP, CORP, `Referrer-Policy`, `Permissions-Policy`, `no-store` on the API; no `Server` banner; no CORS headers (a foreign preflight gets 401) | live probe |
| SQL | Parameterised everywhere; the few concatenations join constant identifiers or `?` placeholders (each re-checked) | grep and suppressions review |
| Paths | Static files from the embedded filesystem; `..` gives 404; collector binaries only by a name the server discovered itself | live probe; read |
| SSRF | Address checked on the real connection after DNS (link-local, metadata, unspecified, NAT64-embedded; loopback opt-in); the HTTP check sends one raw request on the same guarded connection and follows no redirect | read `guard.go`, `http.go` |
| Uploads | 32 MiB cap; depth, count and string-length limits before decoding; two concurrent uploads; per-host and total storage quotas | read; previous audit |
| PDF | Strings escaped as PDF literals (parentheses, backslash, non-printables); link targets only `http(s)` and only from built-in citations | read `pdf.go`, `frame.go` |
| CSV | Formula injection defused on export (`csvSafe`) | previous audit |
| Files at rest | Database and every pre-migration backup created `0600` before data is written | read `perm.go`, `backup` |
| Scripts | Facts lines built with `printf`; untrusted text through `clean()` (tabs and newlines become spaces), so a hostile file name cannot inject a fact; key files and key folders never opened; no command capability exists in the signature schema | read; `TestValidationRefusesWhatAnEngineMustNotDo` |
| Parsers | Fuzz targets for TLS records, X.509, OCSP, SCT, PEM, PE imports and versions, HSTS, CBOM import; **facts parser fuzzed for this audit: 37,496 inputs, no crash** | `go test -fuzz` |
| Dependencies | govulncheck: no reachable vulnerability | govulncheck |
| Container | Distroless static, non-root (65532), base images pinned by digest, no shell | read Dockerfile |
| Release (designed) | Actions pinned by SHA, least-privilege tokens, cosign keyless signatures, SBOMs, SLSA provenance | read workflows |

## Findings

| ID | Sev | Finding | Why it matters | Recommendation |
|---|---|---|---|---|
| L-01 | **Medium** | **No scan scope.** Any analyst (or the automation token) can make the server scan any routable address, including the whole private network. | With several users, the server becomes an internal TLS port scanner whose reach is set by the least careful account. Many organisations require scanners to be restricted to approved ranges. | `serve --scan-allow CIDR\|domain` (repeatable). A scan outside it is refused at add time and at connect time, with the reason. Default: allow all, with a startup notice. |
| L-02 | **Medium** | **No audit trail for actions.** Who added, scanned or deleted an endpoint, uploaded a machine, imported a CBOM or triaged a finding is not recorded. Only sign-in events and system edits are. | Accountability is the reason accounts exist. An auditor will ask "who scanned this host?". | Write the existing append-only `audit_log` for every state change (actor, object, action, before/after). Show it to administrators next to the sign-in log, with a CSV export. |
| L-03 | **Medium** | **No second factor and no single sign-on.** | Enterprise security teams expect MFA for a tool holding this data. Without SSO, accounts are one more set of passwords to manage. | TOTP (RFC 6238, standard library only) as an option per account, which administrators can make required. Then OIDC sign-in. Until then, document the reverse-proxy pattern (oauth2-proxy). |
| L-04 | **Medium** | **Script integrity rests on the server that serves it.** The inventory scripts run as Administrator or root; the SHA-256 shown in the UI comes from the same server. | If the server is compromised, the scripts can be changed and their displayed hash with them. That would be a privileged foothold on every inventoried machine. | Publish each release's script hashes in signed release notes and the cosign-signed checksums file. The UI says where to verify. Later: an Authenticode-signed PowerShell script and a cosign-signed shell script. |
| L-05 | **Medium** | **The release pipeline has never run.** Signing, SBOM and provenance exist only on paper. | The first public release is the first time the supply-chain controls execute. A failure then means unsigned artefacts or a delayed launch. | A dry run on a fork with a pre-release tag, then verify signatures, SBOMs and provenance from a clean machine. |
| L-06 | Low | **The product's own HTTPS fails its own checks.** Scanned with itself: TLS 1.2 offers `ECDHE-ECDSA-AES-CBC-SHA` (IANA "Not Recommended"), and **no `Strict-Transport-Security` header** is sent. Post-quantum key exchange (`X25519MLKEM768`, L3) is already on. | A TLS scanner that would flag its own server undermines trust, and a tester will check this first. | AEAD-only TLS 1.2 suites; HSTS (`max-age=31536000`) on TLS responses. Add a test that the product scans itself with no finding. |
| L-07 | Low | **The session token is not rotated on a password change.** Other sessions end, but the current one keeps its token. | Best practice is a new token after any change of credentials. | Issue a fresh token in `authPassword` and the forced change. |
| L-08 | Low | **The cookie has no `__Host-` prefix** when Secure. | The prefix makes the browser refuse a cookie set by a sibling subdomain (cookie tossing). | Name it `__Host-ch_session` on HTTPS. |
| L-09 | Low | **The setup code never expires** while no account exists. | A server left half-installed stays claimable by anyone who later reads the log (log shipping, support bundles). | Expire it after 24 hours; restart for a new one. Say so in the log line. |
| L-10 | Low | **The Linux script falls back to a predictable `/tmp` name** when `mktemp` is missing. | As root, a symlink planted there could overwrite another file. | Refuse to run without `mktemp`; `set -C` (noclobber) for the temp file. |
| L-11 | Low | **The facts file is written with the default umask** on both platforms. | It lists certificates, packages and SSH settings. Other local users can read it. | `umask 077` in the shell script; owner-only ACL in PowerShell. |
| L-12 | Low | **The Linux file capability lets the shell expand `names` against the working directory** (globbing is re-enabled before the loop). Latent: no Linux signature uses `file` today. | A pattern like `libssl*.so` would match files in the current folder, giving a wrong search. A correctness issue that becomes one the day such a signature ships. | `set -f` around the loop; a test with a matching file in the working directory. |
| L-13 | Low | **The compose file does not harden the container**: no `read_only`, `cap_drop: [ALL]` or `no-new-privileges`. | Defence in depth if the binary were ever exploited. | Add them, plus `tmpfs` for `/tmp`; verify the image still starts and scans. |
| L-14 | Low | **Pre-migration backups are never pruned.** Each holds the full database, now including password and session hashes. | Old copies accumulate next to the live file. | Keep the last three; say so in the log; document. |
| L-15 | Low | **No permanent fuzz targets** for the facts parser or the CSV import. | Both read untrusted input. The audit's run found nothing, but nothing keeps it that way. | Add `FuzzParseFacts` and `FuzzImportSystemsCSV`; run fuzzing in CI on Linux (Windows stalls on these targets). |
| L-16 | Low | **The Windows instructions use `-ExecutionPolicy Bypass`.** | Common, but security teams dislike documentation that tells admins to bypass policy. | Document `Unblock-File` with `RemoteSigned` as the first option; Bypass as the fallback; a signed script later (L-04). |
| L-17 | Low | **A wide pool of client addresses can occupy the four hash slots.** | Distributed guessing could slow sign-in for real users. | Accepted (inherent to slow hashing). The limits already bound it per client. Note it in SECURITY.md. |
| I-01 | Info | `golang.org/x/text` v0.39.0 has GO-2026-6629 in `secure/precis`, which this code does not use. | Not reachable. | Upgrade to v0.41.0 with the next dependency bump. |
| I-02 | Info | The database is not encrypted at rest. | SQLite; the file is owner-only. | Document disk encryption as part of deployment. |
| I-03 | Info | The sign-in log stores client addresses (personal data in some jurisdictions). | Capped at 5,000 lines. | State the retention in the docs. |
| B-01 | **Launch blocker** | The module path is `github.com/offsetsecurity/cipherhorizon` (161 Go files), and `<owner>` placeholders remain in the README, Dockerfile, compose and GoReleaser. | `go install`, image names and links do not work publicly. | Decide the GitHub organisation, then run the rename (`docs/engineering/RENAME.md`). |
| B-02 | **Launch blocker** | `SECURITY.md` has a placeholder security contact. | A reporter has nowhere to send a vulnerability. | Use a real address (for example `security@offsetsecurity.net`) and enable GitHub private vulnerability reporting. |
| B-03 | **Launch blocker** | The image label still describes the product as a ranking tool, and the README is long and inward-facing (see `02-market-research.md`). | Not a vulnerability; first impressions. | Covered by the launch plan. |

## Recommendation

- **Before a public release:**
  - **Fix:** the launch blockers, L-04, L-05 and L-06 (cheap, and visible to the first tester).
  - **Quick hardening:** L-07 to L-16 (most take under an hour).
- **For the first enterprise-ready release:** L-01, L-02 and L-03.

This audit's evidence is reproducible:
- `make check`
- `testing/e2e/security.sh`
- the self-scan:
  1. `cipherhorizon serve --tls-cert … --tls-key …`
  2. `cipherhorizon tls scan 127.0.0.1:8443`
