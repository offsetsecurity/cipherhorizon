# ADR-0016: Windows certificate store enumeration

- **Status:** Accepted, conditional on the written syscall review (`docs/host-discovery/wp3-security-review.md`) and the oracle comparison
- **Date:** 2026-09-26
- **Deciders:** Product Manager, Security Architect
- **Amends:** ADR-0013 ("nothing opens or enumerates a certificate"), ADR-0005 decision 4
- **Relates to:** PRD-003 REQ-CERT-1/3/4, SECARCH-001 SR-06, SR-07

## Context

CISA says certificates are where the key-length data explicitly exists (PRD-003 §3.3), and on Windows the certificates that matter (the machine's own, the trust anchors, those of local services) live in the system certificate stores, not in files. ADR-0013 deliberately kept the Windows layer away from certificates: "nothing opens a key, a certificate or a secret, and nothing enumerates key or certificate material". That was right for the cryptography-provider inventory. It has to change for a certificate inventory, so the rule is restated here precisely rather than quietly relaxed.

## Decision

The platform layer (`internal/winapi`) gains one capability: **list the certificates in a fixed allow-list of system stores and return each certificate's DER encoding and a private-key flag.**

Constraints, each enforced by code and test:

1. **Fixed stores.** Locations `LocalMachine` and `CurrentUser`; store names `MY`, `Root`, `CA`, `TrustedPeople`, `TrustedPublisher`, `AuthRoot`. Anything else is refused before Windows is called. (The `Disallowed` store, which lists certificates a system explicitly distrusts, is left out on purpose: a "root" that is on a deny list would read as a trust anchor.)
2. **Read-only and existing only.** Stores are opened with `CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG`, so the call cannot create or change anything. A store that does not exist is an empty answer, not an error.
3. **Public parts only.** The layer copies the certificate's own encoded bytes. It never calls a function that opens, exports, acquires or uses a private key: no `CryptAcquireCertificatePrivateKey`, no `NCryptOpenKey`, no `CryptAcquireContext`, no key export. A test scans the layer's source for these names and fails on any.
4. **Private-key presence is a property read, not a key open.** `CertGetCertificateContextProperty` is called with **one** property id, `CERT_KEY_PROV_INFO_PROP_ID`, and **no output buffer**: it can only answer "does this certificate have a key association?", it cannot return the association's contents (container and provider names) and it does not touch the key. The answer is yes, no or unknown. (`no` means no key is associated with the certificate in that store.)
5. **Bounded.** At most 20,000 certificates per store and 64 KiB per certificate; larger values are skipped and counted. Every certificate context is freed on every path, including when the cap stops the loop early.
6. **Sensor discipline.** The sensor (`windows-certs`) runs only for a live Windows host (as `windows-cng`), calls each store under a 15 s budget, treats an access-denied store as `unknown(permission)` and keeps going, and declares its method **adjacent** to secrets so the decoy and mutation tests apply.

## Consequences

- One new syscall surface in the only package allowed to have one. The written review is a gate before this ships.
- `winapi`'s package comment and the stage-2 review's "nothing enumerates certificates" statement now say "except the certificate stores enumerated under ADR-0016".
- The oracle is independent: the .NET `X509Store` classes and `certutil -store`, compared certificate by certificate (`testing/hostdiscovery/compare-certs.ps1`).
- `Disallowed`, smart-card, Group-Policy and physical stores, and stores of other users, are not read; they are listed among the sensor's blind spots.
