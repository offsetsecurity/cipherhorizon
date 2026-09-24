# ADR-0005 — Secret safety by construction: allow-lists, forbidden calls, canary gate, privilege tiers

- **Status:** Proposed (Agent 3), pending Agent 4 challenge
- **Date:** 2026-09-24

## Context

The collector runs on sensitive machines and must collect cryptographic **metadata only** — never private
keys, passwords, tokens, cookies or credentials (brief §25). "Be careful" is not a control. Windows key stores
and Linux key files sit next to the certificates we want; configs often embed secrets.

## Options considered

1. Guidelines and code review only.
2. Structural controls (what the code *cannot* do) plus an automated leak test.

## Evidence

- Certificates were enumerated without opening any key; `HasPrivateKey` is a reference flag (Agent 2 §2.5).
- A private-key file cannot be characterised without parsing it; a certificate's public key already gives the
  algorithm and size, so cert-paired keys need not be opened (Agent 2 §1.1 A3).
- The syscall wrappers for cert properties/CNG do not exist in `x/sys` and must be hand-written (Agent 2 §2.5).
- Prior tool (`cbomkit-theia`) itself warns files may be read and contents printed to stderr.

## Decision

1. **Attribute allow-lists per subject kind**; anything else is dropped and counted.
2. **Config parsing by directive allow-list**; never emit raw config text; secret-shaped values are never copied.
3. **Orphan private keys: presence only** (path, mode). An optional, off-by-default fixed-length armor-label read
   may report `encrypted`/`unencrypted`; the bytes are discarded and never logged.
4. **The hand-written syscall layer has a fixed function set; a forbidden-symbol test** fails on any key-export
   or key-material function (`NCryptExportKey`, `CryptExportKey`, …).
5. **Canary-secret corpus is a release gate**: synthetic private keys, tokens and passwords planted on test hosts
   must appear nowhere in Batch, CBOM, logs or error strings.
6. **Privilege tiers**: `user` (default, complete on its own) · `admin` · `debug`; elevation is a separate switch;
   the CBOM records the highest tier used; a denied call is `unknown(permission)`.

## Why

Controls that a reviewer can verify mechanically survive turnover and refactors; guidelines do not.

## Trade-offs

Less flexible config parsing (an allow-list means new directives need code); orphan keys carry little metadata;
canary tests need maintained fixtures.

## Consequences

- A key metadata claim beyond presence/size-via-certificate is out of scope until a safe method is proven.
- Any new sensor declares its **secret proximity** in the method registry; `adjacent` requires added tests.
- Agent 6 (security review) checks the syscall layer line by line.
