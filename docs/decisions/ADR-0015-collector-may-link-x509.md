# ADR-0015: The collector may link `crypto/x509` (and, through it, `net`)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Deciders:** Product Manager, Security Architect
- **Relates to:** ADR-0004 (no subprocess), ADR-0005 (secret safety), ADR-0006 (host/network separation), PRD-003 REQ-CERT-2/3, SECARCH-001 SR-06

## Context

The certificate sensors must read X.509 certificates: subject, validity, key algorithm and size, signature algorithm. Go's standard `crypto/x509` does that, and it is the audited parser everything else in the ecosystem relies on. It also imports the `net` package (for IP address types in subject alternative names).

The collector had a structural rule: it must not link `net`, because a collector that cannot link the network package cannot reach the network by accident. That rule was checked on Linux; on Windows it was already relaxed because `golang.org/x/sys/windows` imports `net` for socket type definitions, with nothing calling it.

## Options considered

1. **Write our own X.509 reader** with `encoding/asn1` (which does not import `net`) so the collector stays free of `net`.
2. **Allow `crypto/x509`** and tighten the rule from "does not link `net`" to "`net` is linked only through named standard-library importers, and no package of this module imports it".
3. **Do not read certificates in the collector**; have the server parse them.

## Decision

Option 2.

- The collector may link `crypto/x509`. `net` may appear in its dependency graph only when imported by `crypto/x509` (and, on Windows, `golang.org/x/sys/windows`). Any other importer, and any package of this module, fails `TestCollectorLinksNoServerStoreOrScanner`.
- The other bans stand: no `net/http`, no `crypto/tls`, no database, no server, no store, no TLS scanner, no evaluation, and now no `internal/estate` (which imports the scanner's report types).
- Modules of this repository that collect evidence are still forbidden to import `net` directly (`archtest`, unchanged).

## Why

- Option 1 replaces an audited parser with a hand-written one that reads hostile files. We wrote and fuzzed such readers for PE files because nothing better existed; here something better exists.
- Option 3 would force the collector to ship raw certificate bytes to the server, moving a larger amount of data and forfeiting the rule that the collector describes and never transmits content.
- Linking `net` is not network access. What the rule protects against is a *call*; the tightened rule still catches any new importer, which is the change a careless edit would make.

## Consequences

- The collector binary grows slightly. It gains no capability to dial: nothing in the module imports `net`, and the test proves it for both platforms.
- If a future standard-library release adds another `net` importer inside the collector's dependency graph, the test fails and this ADR is revisited deliberately.
- A `certinfo` package holds the facts that are read from a parsed certificate, shared by the collector and the scanner, so the same certificate has the same attributes whichever way it was found.
