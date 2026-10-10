# 01 · Security audit (pre-0.1.0)

**Role:** Security reviewer. **Scope:** the server and API, the web UI, the TLS scanner's network behaviour, the host
collector, the ingest path, storage, the CI/release pipeline, and defaults. **Method:** read the code paths that handle
untrusted input, exercise them against a live instance, and check each control that earlier documents claim.
**Not covered:** a third-party penetration test; the container image and the release workflows were reviewed but have
never run (nothing is pushed yet).

## Controls verified as working

| Area | Control | How it was checked |
|---|---|---|
| Cross-site forgery | every state-changing `/api/` call needs `X-Requested-With`, a same-origin `Origin`, no `Sec-Fetch-Site: cross-site`, and JSON content type | read `mutationGuard`; `testing/e2e/security.sh` |
| DNS rebinding | Host header allow-list when no token is set | read `hostCheck`; `security.sh` |
| Unauthenticated exposure | refuses to listen beyond loopback without a token | read `serveCmd`; `security.sh` |
| Token check | constant-time compare, scheme required | read `auth` |
| SSRF | address check on the real connection (dialer `Control`, after DNS), link-local and cloud metadata refused, loopback opt-in | read `Guard` |
| Injection into the page | no `innerHTML`, `insertAdjacentHTML`, `eval` or inline handlers anywhere in `web/static`; strict CSP with no inline script or style | grep of the whole UI tree |
| SQL | every statement is parameterised; the only `Sprintf` in `internal/store` builds a display string | grep |
| CSV export | spreadsheet formula injection defused (`csvSafe`) | read |
| Bodies and timeouts | 1 MiB JSON limit, 32 MiB CBOM limit, `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout` set | read |
| Retention | 200 scans per endpoint and 50 snapshots per host are kept | read store |
| Supply chain | actions pinned by SHA, least-privilege `permissions:`, no `pull_request_target`, Dependabot, CodeQL, dependency review, keyless signing | read all five workflows |
| Collector | no subprocess, no network, allow-listed attributes, hostile names skipped and reported, redaction, enforced dependency set | earlier review (`artifacts/security-review-level-1.md`) and `internal/archtest` |

## Findings

Severity is the reviewer's judgement of impact on a self-hosted tool that holds an organisation's cryptographic
inventory.

| ID | Sev | Finding | Why it matters | Recommendation |
|---|---|---|---|---|
| SEC-01 | **Medium** | The SQLite file (and its `-wal`/`-shm`) is created with the process umask, typically `0644`. | It holds every scanned endpoint, every host inventory and the raw uploaded CBOMs: reconnaissance data. Any local user can read it. | Create it `0600` before SQLite opens it; tighten an existing file on start (POSIX; Windows uses the profile ACL). |
| SEC-02 | Low | The collector writes `host.cbom.json` with mode `0644`. | A host inventory readable by every local user. | Default to `0600`. |
| SEC-03 | **Medium** | Any token is accepted, including one character; auth failures are neither logged nor slowed. | A network-exposed server with `--token a` is trivially guessed and nothing records the attempts. | Require at least 16 characters; log each failed attempt (method, path, remote address, never the value); add a short fixed delay to failures. |
| SEC-04 | Low | The SSRF guard does not refuse `0.0.0.0/8` or IPv6 addresses that embed an IPv4 one (NAT64 `64:ff9b::/96`). | A NAT64 form of `169.254.169.254` would pass the literal check on some networks. | Refuse `0.0.0.0/8`; unwrap `64:ff9b::/96` and re-check the embedded IPv4. |
| SEC-05 | Low | Host names supplied on upload reject `\r\n\t` only; other control characters and invalid UTF-8 pass. | Stored, then shown (always as text, so not exploitable in the UI) and used in a download filename path. | Reject any control character and invalid UTF-8. |
| SEC-06 | Low | Worst-case storage per host is 50 snapshots × 32 MiB. | Disk exhaustion by anyone who can reach the ingest endpoint. | **Defer:** needs a decision on a per-instance size budget; typical CBOMs are under 1 MiB. Documented as a limit. |
| SEC-07 | Info | No `Permissions-Policy` header. | Defence in depth; the UI uses none of these features. | Add a deny-all policy. |
| SEC-08 | Low | Workflow checkouts persist the job token in the working copy. | A later step (or a compromised action) could reuse it. | `persist-credentials: false` on every checkout. |
| SEC-09 | Info | No user accounts, roles or audit log; one shared bearer token; no TLS listener (a proxy is expected). | Fine for the stated self-hosted, single-team model; a gap for multi-team use. | **Defer** to the roadmap; state plainly in `SECURITY.md`. |
| SEC-10 | Info | `SECURITY.md` has a placeholder contact; the module owner is `example`. | A reporter has nowhere to send a vulnerability. | Blocked on the user (GitHub username and contact); tracked in the release checklist. |

## Result

No critical or high finding. Two medium findings (SEC-01, SEC-03) and three low ones are cheap to fix and are approved
in `05-pm-decision.md`. The remaining items are recorded as accepted risks with a reason.
