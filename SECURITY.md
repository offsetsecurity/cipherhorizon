# Security policy

CipherHorizon connects out to systems you tell it to and gives whoever can reach its API the ability to make
this program do that. Treat reports about it the way you would for any tool that touches live network
services: promptly, and privately until a fix is out.

## Supported versions

This project is in its `0.x` pre-release series. Only the **latest released version** and the `main` branch are
supported; older releases do not receive fixes, so please reproduce against the latest release (or `main`)
before reporting. Security fixes ship as a patch release with a GitHub Security Advisory
([release process](docs/engineering/RELEASING.md)).

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report it privately using GitHub's [private vulnerability reporting](../../security/advisories/new) for this
repository (Security tab → "Report a vulnerability"), or email **`<maintainer-security-contact — set this
before publishing>`**. Include:

- what you found and why it is a vulnerability (not just unexpected behaviour);
- steps to reproduce, ideally against `cmd/demo-targets` or another target you control — see "Scope" below;
- the version or commit you tested;
- the impact you believe it has.

You should get an acknowledgement within 5 business days. We aim to agree a disclosure timeline with you once
the report is confirmed; 90 days from confirmation is the default if we don't agree on something else.

## Scope

In scope: the `cipherhorizon` binary and the packages under `internal/` and `web/` in this repository —
in particular the HTTP API and web UI (`internal/server`), the TLS scan engine and its own wire-protocol
parsers (`internal/tlsprobe`), the SSRF/target-safety guard (`internal/server/guard.go`), and the CBOM/PQC
classification logic (`internal/cbom`, `internal/pqc`), and the endpoint collector
(`cmd/cipherhorizon-collector`, `internal/sense`, `internal/discover`) — a file it should never open, a value it
should have tokenised, or a hostile file name that changes its behaviour is in scope.

Out of scope: vulnerabilities that require the attacker to already have an administrator account, the
automation token, or shell access to the machine running it; findings from automated scanners with no working proof of concept; a target
server's own TLS misconfiguration (that is what this tool is *for* reporting, not a vulnerability in it).

**Never test against a target you do not own or are not authorised to test.** `cmd/demo-targets` (see
[testing/README.md](testing/README.md)) starts servers of known posture on loopback for exactly this purpose;
use it, or your own infrastructure, instead of a third party's.

## Known limits of the security model (0.x)

These are deliberate for a self-hosted, single-team tool, and are stated so nobody has to discover them:

- **Sign-in is off by default** for one person on their own machine (the server listens on loopback). It is
  turned on in Settings, which creates the first administrator, or forced with `--sign-in on` (`--sign-in off`
  forces it off). A database that already has accounts keeps sign-in on after an upgrade. A server listening
  beyond loopback with sign-in off refuses to start unless `--open-network` says it is meant to be open, and
  Settings cannot turn sign-in off on such a server. While sign-in is off, anyone who reaches the server has
  every right, including scanning through it.
- **Turning sign-in off** takes an administrator signed in with their own account, who types their password
  again. It ends every session, and while it is off a leftover session cookie grants nothing different: everyone
  is the same anonymous operator. Accounts are kept but frozen (they cannot be added, changed or removed, so
  nobody can prepare an account to take over when sign-in returns). History keeps the names of who did what
  while sign-in was on; actions while it is off are recorded as anonymous with the client's address. Turning it
  on again asks everyone to sign in, with the roles they had.
- **Accounts and sessions are local to the server** ([ADR-0018](docs/decisions/ADR-0018-accounts-and-sign-in.md)).
  Passwords are salted PBKDF2-SHA256 hashes (600,000 iterations); sessions are random 256-bit tokens kept only as
  their SHA-256, in an HttpOnly, SameSite=Strict cookie, ending after 30 minutes idle or 12 hours. Over HTTPS
  the cookie is `__Host-ch_session` (Secure, bound to this exact host, so a sibling subdomain cannot plant or
  overwrite it). Changing a password ends every session of that account, including the one that changed it,
  which is then signed in again with a new token. Five wrong passwords lock an account for 15 minutes; twenty
  failures from one address within 15 minutes get 429. There is no single sign-on and no second factor yet; use
  a reverse proxy that adds them if you need them now. Whoever can read the server's log during first run can
  claim the administrator account with the setup code it prints; the code stops working once used, or after
  24 hours (restart the server for a new one). Whoever can run `cipherhorizon user` on the server can reset any
  password (they could read the database anyway).
- **Password hashing is deliberately expensive and bounded.** At most four PBKDF2 computations run at once, so a
  flood of sign-in attempts cannot exhaust CPU or memory; the cost is that such a flood makes honest sign-ins
  wait their turn. Put a rate-limiting proxy in front if the sign-in page faces the internet.
- **The sign-in log keeps client addresses.** Every sign-in, failure and lock-out is recorded with the user name
  and client address, for the administrator to review. The newest 5,000 entries are kept; older ones are
  deleted.
- **The automation token** (`--token`) acts as an analyst on the API for scripts and CI. It must be at least 16
  characters; failed attempts are logged (never the value) and delayed. Treat it like a password.
- **Plain HTTP is refused beyond loopback** unless `--plain-http` says a TLS-terminating proxy is in front; with
  `--tls-cert/--tls-key` the server speaks TLS 1.2 (ECDHE with authenticated encryption only) and TLS 1.3,
  offers the hybrid post-quantum key exchange X25519MLKEM768, and sends HSTS. Its own scanner checks this
  configuration in the test suite: the server passes its own scan.
- **The database holds reconnaissance data** (every scanned endpoint, every host inventory, the raw uploaded
  CBOMs) and the password and session hashes. It is created owner-only on Linux and macOS; on Windows the
  profile's ACL applies. It is not encrypted at rest: put it on an encrypted volume if the disk can leave your
  control. `cipherhorizon db backup FILE` writes an owner-only copy while the server runs; protect it as you
  would the database. Before a schema migration the server keeps a copy next to the database; only the newest
  three such copies are kept.
- **Storage is bounded per asset, not per instance:** 200 scans per endpoint and 50 uploads per host (each upload
  up to 32 MiB). Anyone who can reach the upload endpoint can fill the disk; keep it behind the token.
- **The endpoint collector** (`cipherhorizon-collector`) reads files and makes no network connection or child
  process; its output names installed software and paths (user names are tokenised, `--redact-host` withholds the
  host name). The CBOM file it writes is owner-only. It reports what a file *claims* (a version string); it does
  not verify signatures.
- **The inventory scripts** are plain text the server hands out. They are not code-signed; check one before you
  run it: its SHA-256 must match `cipherhorizon scripts list` from the same version, or the
  `inventory-scripts.sha256` file each release ships under its signed checksums. The facts file they write is
  readable by its owner only (and, on Windows, Administrators and SYSTEM).

## What "security" means for this project specifically

A few things worth knowing when triaging or reporting:

- **The scanner is meant to connect to network targets.** That is the product, not a bug. The interesting
  reports are ones where it does more than that — reaches somewhere the SSRF guard (`internal/server/guard.go`)
  should have blocked, or where a scanned target's malicious response causes something worse than a wrong
  finding (a crash, a hang, memory disclosure, or code execution) in the wire parsers under
  `internal/tlsprobe/wire`, which are written to treat every byte from a peer as hostile and are fuzz-tested,
  but fuzzing finds bugs, it doesn't prove their absence.
- **The web UI renders data a scanned server controls** (certificate subjects, cipher suite names). If any of
  that ever reaches the DOM other than through `textContent`/element properties (see
  `web/static/js/dom.js`), that is a real finding — file it.
- **PQC and TLS hygiene verdicts being wrong** (a misclassification, a missing citation, a finding that should
  or shouldn't have fired) is a correctness bug, not usually a security vulnerability — please open a normal
  issue for those instead, unless the wrong verdict is itself security-relevant (e.g. silently downgrading a
  critical finding).

Thank you for helping keep this project and its users safe.
