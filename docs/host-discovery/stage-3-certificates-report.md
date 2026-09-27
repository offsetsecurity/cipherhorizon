# Stage 3 report: certificates (Linux files, Windows stores)

Implements PRD-003 REQ-CERT-1…6 and 8 (host side), REQ-CERT-7 (rules). Decisions: ADR-0015 (the collector may link `crypto/x509`), ADR-0016 (Windows certificate stores). Security reviews: `docs/program/reviews/WP-2-security-review.md`, `docs/host-discovery/wp3-security-review.md`.

## What is collected

| | Linux (`cert-files`) | Windows (`windows-certs`) |
|---|---|---|
| Where | fixed directories under `etc` and `usr`: trust stores (`etc/ssl/certs`, `etc/pki/ca-trust/…`, `usr/share/ca-certificates`, `usr/local/share/ca-certificates`), service directories (`etc/letsencrypt/live`, `etc/nginx`, `etc/apache2`, `etc/httpd`, `etc/haproxy`, `etc/postfix`, `etc/dovecot`) | six system stores, for the machine and the current user: MY, Root, CA, TrustedPeople, TrustedPublisher, AuthRoot |
| How | walks the directories; opens files named `*.crt/.cer/.pem/.der` and OpenSSL hash links; reads CERTIFICATE blocks only | asks Windows (`CertOpenStore` read-only, `CertEnumCertificatesInStore`); parses each certificate's own bytes |
| Private keys | files named like keys are counted and never opened; a key block inside an opened file is counted and never decoded; the certificate is marked `privateKey=yes` for that file | one property query (no buffer) says whether a key association exists; no key function is called |
| Symbolic links | followed once, only to a regular file inside the root, through real directories; anything else refused and counted | n/a |
| Runs when | a Linux host with any of the directories | a live Windows host only |

For each certificate: subject, issuer, serial, SHA-256 fingerprint (its identity), validity, key algorithm **and size and curve**, signature algorithm, names, key usage, CA and self-signed flags, and for each place it was found whether a private key is associated there. The facts come from one shared package (`internal/certinfo`), so a certificate a server presents and the same certificate a host holds have identical attributes, and the estate graph shows them as one entity with several places.

## What is not collected (stated in the sensors' blind-spot lists)

Keys (never); certificates in application stores (Java, Firefox, language runtimes) or embedded in software and databases; the Windows `Disallowed` store, other users' stores, smart-card and Group-Policy stores; whether a system trusts a certificate; whether anything uses it.

## How it was checked

| Check | Result |
|---|---|
| Unit and golden tests | Linux sensor: 8 sensor tests, 5 PEM tests, 2 fuzz targets (**the fuzzer found a real bug** in the first version of the ASN.1 element check: it accepted a private-class tag; fixed and kept as a regression seed); Windows sensor: 11 tests with a fake API; layer: 4 tests including the source scan for key functions |
| Mutation checks | 4 on the Linux guards (open key-named files; decode every PEM block; follow links unconditionally; no size cap) and 5 on the Windows layer; every mutation failed a test. One mutation initially **survived** (decoding key blocks left no trace in the output); the test was strengthened (a key block must never reach the certificate parser) and the mutation then failed |
| Independent oracle, Windows | `compare-certs.ps1` (.NET `X509Store`): 142 placements expected, 140 detected, the 2 missing are the certificate the sensor reported as unparseable, 0 extra, 0 key-size and 0 key-flag mismatches, no key text. Five negative controls all caught |
| Independent oracle, real Linux-style tree | `compare-certs.sh` with OpenSSL over Git for Windows' bundled Mozilla CA files (`etc/pki/ca-trust/extracted/pem/*.pem`): 212 certificate placements in the CBOM and 212 found by OpenSSL, same set: AGREE. **Limit:** key-size comparison is made only for the first certificate of each file (OpenSSL's `x509` reads one), so 3 of 212; the rest are compared by fingerprint only. No negative controls were run for this oracle (each run takes minutes) |
| Real-machine sensor test | 140 observations on the development machine; roots carry no key association; output valid against the evidence contract |
| End to end | a certificate presented by a test server and held in two files on a host is one entity with three places and two systems; a planted key appears in no API response |
| CBOM validity | host CBOMs with certificates validate against the CycloneDX 1.6 schema |
| URL cache | unchanged by a full run (118 files before and after) |

## Findings made along the way (fixed)

| | |
|---|---|
| A retry of a failed migration in the same second could not take its backup | fixed in WP-1 |
| `evidence.Validate` accepted control characters in attribute values | fixed: rejected now, for every kind |
| The first ASN.1 element check accepted a non-universal class | found by fuzzing; fixed |
| A certificate's per-place facts (private-key answer, path) had been placed on the shared subject and would have collapsed | moved to `Source.Attrs` and per-occurrence `additionalContext` |
| The collector's "no `net` linked" rule could not survive reading certificates | rule tightened to "only through `crypto/x509`" (ADR-0015), mutation-checked |
| The CBOM said a sensor was partial without saying how much it left out | every sensor's counted limits are now `cipherhorizon:coverage-limit` properties |

## Not validated

**Linux on a live host** (no working Linux environment on the development machine; the sensor and its oracle are proven on a real Linux-style file tree, not on a running distribution: Debian's symlink farm, RHEL's `extracted` layout and the symlink rules in particular are proven by fixtures and by the traversal-resistant filesystem test, which **skips on this machine because unprivileged symlink creation is not available**, so it runs only in Linux CI). Windows Server, ARM64, builds before 24H2, elevated runs, other users' stores.
