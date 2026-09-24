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

Out of scope: vulnerabilities that require the attacker to already have the API's access token or shell
access to the machine running it; findings from automated scanners with no working proof of concept; a target
server's own TLS misconfiguration (that is what this tool is *for* reporting, not a vulnerability in it).

**Never test against a target you do not own or are not authorised to test.** `cmd/demo-targets` (see
[testing/README.md](testing/README.md)) starts servers of known posture on loopback for exactly this purpose;
use it, or your own infrastructure, instead of a third party's.

## Known limits of the security model (0.x)

These are deliberate for a self-hosted, single-team tool, and are stated so nobody has to discover them:

- **One shared bearer token, no user accounts, roles or audit log.** Anyone who holds the token can do
  everything. The token must be at least 16 characters; failed attempts are logged (never the value) and
  delayed. Treat it like a password and put a TLS-terminating reverse proxy in front if the server is shared:
  the server itself speaks plain HTTP.
- **The database holds reconnaissance data** (every scanned endpoint, every host inventory, the raw uploaded
  CBOMs). It is created owner-only on Linux and macOS; on Windows the profile's ACL applies. Back it up and
  protect the backup as you would the inventory itself.
- **Storage is bounded per asset, not per instance:** 200 scans per endpoint and 50 uploads per host (each upload
  up to 32 MiB). Anyone who can reach the upload endpoint can fill the disk; keep it behind the token.
- **The endpoint collector** (`cipherhorizon-collector`) reads files and makes no network connection or child
  process; its output names installed software and paths (user names are tokenised, `--redact-host` withholds the
  host name). The CBOM file it writes is owner-only. It reports what a file *claims* (a version string); it does
  not verify signatures.

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
