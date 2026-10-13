# ADR-0019 — SSH endpoints: our own prober, the shared evaluation shape, Go 1.27

Status: accepted, 2026-10-12. Requirements: [PRD-008](../product/PRD-008-pq-signatures-and-ssh.md).

## Context

SSH is the second protocol every estate runs, and recorded SSH sessions are as exposed to
harvest-now-decrypt-later as TLS. The product has one scanner (`internal/tlsprobe`), one evaluation shape
(`eval.Evaluation`), and one asset kind for network services (`tls-endpoint`). Every fleet view depends on all
three: endpoints, findings, systems ranking, inventory, schedules and the PDF.

We have three options for the prober:

- **x/crypto/ssh as the client.** It refuses what a scanner most needs to see: `ssh-dss`, SHA-1 key exchanges,
  CBC, broken servers and partial handshakes. It also hides what it negotiated.
- **Shelling out to `ssh -vvv` or `ssh-keyscan`.** The binary isn't present everywhere, it isn't
  deterministic, and it breaks the self-contained single binary.
- **Our own, small, client-side-only implementation.** It needs the identification line, the binary packet
  framing before encryption starts, KEXINIT, and one ECDH-style key exchange up to the server's reply.

## Decision

1. **An own prober, `internal/sshprobe`, standard library only.**
   - It never derives session keys and never sends anything after the server's key-exchange reply. It stops before
     NEWKEYS, so it never authenticates or opens a channel.
   - Key exchanges it can complete: `mlkem768x25519-sha256` (`crypto/mlkem`, `crypto/ecdh`), `curve25519-sha256`,
     ECDH P-256/384/521, and MODP groups 14, 16 and 18 (`math/big`).
   - It verifies the server's signature over the exchange hash. Supported: Ed25519, ECDSA, RSA PKCS#1 with SHA-1,
     SHA-256 and SHA-512, ML-DSA (`crypto/mldsa`), and the composite `ssh-mldsa44-ed25519` (ML-DSA-44 + Ed25519,
     draft-miller-sshm-composite-sigs), which OpenSSH 10.6 enables by default.
   - `ssh-dss` is read but not verified, and the report says so.
2. **`golang.org/x/crypto/ssh` is a test and demo dependency only.**
   - It's the independent server our tests scan, so a misreading of the RFC can't pass because both ends share it.
   - `demo-targets` uses it too.
   - The release binary must not import it: `internal/archtest` enforces this.
3. **SSH endpoints are a new asset kind `ssh-endpoint`** in the existing tables.
   - The scan row keeps `report_json` with `schemaVersion: "ssh-report/1"`.
   - Migration 13 adds `scans.service` (e.g. `OpenSSH_10.0`) and `scans.host_key` (e.g. `Ed25519`) for lists.
4. **The SSH evaluation returns `eval.Evaluation`.** Same findings, readiness, hygiene, sections, checks,
   fix-first and vulnerabilities. Section IDs are SSH's own; the shared post-quantum finding IDs are reused, so
   the fleet groups exposure across protocols.
5. **Every consumer of `report_json` dispatches on the asset kind**, never on guessing the JSON. The consumers are:
   evaluation and re-evaluation, CBOM, PDF, inventory, diff, the graph projection, and the SSLv2 index (TLS only).
6. **Minimum Go 1.27.** `crypto/mldsa` arrived in 1.27. It's needed for the ML-DSA host-key and certificate
   checks, and for the demo and test fixtures. The toolchain was already pinned to 1.27.2.

## Consequences

- The fleet code paths stay single. A new protocol costs one prober, one rule set, one CBOM builder and one PDF
  renderer, plus the dispatch points listed in 5.
- Our KEX code is security-relevant parsing of hostile input. It is bounded and fuzzed (PRD-008 REQ-SHN-5), and the
  oracle against real OpenSSH (REQ-SHN-2) is part of QA.
- Contributors need Go 1.27.
