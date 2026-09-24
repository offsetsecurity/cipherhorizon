# Security review — Level 1

```
AGENT      6 — Security Reviewer (a separate reviewing pass; did not write the code under review)
DATE       2026-09-24
SCOPE      internal/evidence, internal/knowledge, internal/derive, internal/sense/**, internal/hostinfo,
           internal/discover, internal/cbom/hostbuild.go, internal/app (run), the new tests
METHOD     Read the code adversarially against SR-1..SR-12 (artifacts/agent-01), then attacked it with tests.
VERDICT    Two findings needed fixing before acceptance (both fixed and re-tested); five are accepted risks or
           documented limits. No secret-read path found.
```

## Findings

### F1 — A hostile file or directory name could abort the whole run  (HIGH, availability) — FIXED

**Where:** `internal/sense/pefiles/pefiles.go` (path -> `Source.Location`, attributes) and `evidence.Validate`.
**Attack:** a low-privilege user creates a directory under their own `AppData\Local\Programs` containing a newline
or control character (possible on NTFS through the `\\?\` namespace; trivially possible on Linux), holding a file
named like a crypto library. When an administrator (or the user) runs the collector, `Validate` rejects the
observation and `AddBatch` fails, so `discover.Run` returns "a sensor broke the evidence contract" and **no
inventory is produced at all** for the machine. A denial of service that any local user can mount against the
audit.
**Root cause:** the design treated a contract violation as a sensor bug (correct) but the sensor let attacker-supplied
text reach the validator (wrong).
**Fix:** `evidence.SafeText` / `evidence.Clean`. The file sensor skips a matched file whose path is not safe text
(control characters, invalid UTF-8, over 1024 bytes) and **reports it** (`Coverage.Limits["skippedUnsafeNames"]`,
status `partial`, reason `unsupported`); the dpkg sensor and the os-release reader clean every host-supplied value.
**Tests:** `TestHostileNamesAreSkippedAndReportedNotFatal`, `TestHostileStanzaValuesAreCleaned`, `TestSafeText`,
`TestClean`. The contract validator itself stays strict.
**Residual:** a hostile *directory* name is only noticed if a recognised library sits inside it (the path is checked
when a file matches). That is enough: nothing is emitted for it.

### F2 — A persistent device identifier was emitted by default  (MEDIUM, privacy) — FIXED

`cipherhorizon:host-id` (a one-way hash of the machine GUID / `/etc/machine-id`) appeared in every CBOM. It is not
reversible, but it is a stable per-device identifier leaving the machine without the operator asking for it.
**Fix:** it is emitted only when `--redact-host` is set (then it *is* the subject name). Test:
`TestHostIDIsNotEmittedUnlessRedacting`. ADR-0009 states the rule.

### F3 — Version provenance was unstated  (LOW, evidence integrity) — FIXED

A file's version is the file's own claim (Firefox's `nss3.dll` reports Firefox's version, 156.0.1.575). A consumer
could read it as the library's version. **Fix:** every component with a version carries
`cipherhorizon:version-source` (`package-database` or `file-version-resource`). Version-gated capability
(OpenSSL >= 3.5) rests on that claim; see F5.

### F4 — Family-level capability credits every file in the family  (LOW, precision) — ACCEPTED, documented

`libssl-3-x64.dll` is credited with what OpenSSL can do, though the primitives live in `libcrypto`. It matches the
existing Debian behaviour (`libssl3`). It over-credits *which file*, not the host. Refinement belongs to L2.

### F5 — A file can lie about its version  (MEDIUM, inherent) — ACCEPTED, stated

A tampered `libcrypto-3-x64.dll` can claim 3.5.7 and be credited with ML-KEM. Host collectors cannot defeat a host
that lies (Agent 1 §6). Mitigations kept: capability requires a *parsed* PE, the version's provenance is labelled
(F3), signatures are not trusted because they are not verified (below), and the CBOM says
`whether a file is genuine: version strings are what the file claims`. Verifying an Authenticode signature is
deliberately *not* done at L1: `WinVerifyTrust` can perform revocation checks over the network (SR-7).

### F6 — Elevated runs walk more, unmeasured  (MEDIUM, operational) — OPEN

As Administrator the walk enters `ProgramData\Microsoft\Crypto\...` (machine key stores) and
`Program Files\WindowsApps`. **No key material can be read:** only files whose *name* matches a recognised library
are ever opened, proven by a spying-filesystem test. But the traversal is larger, may hit the 60 s per-sensor default
timeout (reported as incomplete, exit 2), and was **never measured** because this session cannot elevate.
**Required before claiming elevated support:** an elevated run on a real machine, recording time and coverage.

### F7 — A slow or hung directory read can outlast the timeout  (LOW) — ACCEPTED

`fs.ReadDir` on a stalled network mount cannot be interrupted by the context; the walk checks the context between
entries. Default roots are local fixed locations only, and network mounts are not walked. Noted for the daemon.

## What was checked and found sound

| SR | Result |
|---|---|
| SR-1 no secrets | Files opened only if their **name** matches a recognised library (`TestNeverOpensAnythingButRecognisedLibraries`, a spying `fs.FS`); attributes allow-listed and rejected otherwise (`TestValidateRejects`); no path opens `*.key/*.pem/*.pfx`, `id_rsa`, credentials. PE reading touches headers and the resource directory only. |
| SR-2 read-only | No write call in sensor packages. |
| SR-4 no subprocess | `internal/archtest` fails the build on `os/exec` anywhere under `internal/` (negative control run: it detects a planted import). |
| SR-5 path safety | Symlinks and junctions are skipped, not followed; depth 8; 500,000 entries; 256 MiB file cap; the PE reader caps every read (64 KiB), directory entries (256), header (4 KiB), sections (96) and copied strings (128), sizes nothing from the file, and survived 2.8 M fuzz executions plus every truncation and 3,000 random corruptions of a valid image. It matched PowerShell on 400 genuine Microsoft DLLs. |
| SR-6 hostile strings | Now handled (F1). `product-name`/`fileVersion` are cleaned to printable ASCII, <= 128 bytes. |
| SR-7 no network | `net`, `net/http` banned in sensors (archtest); Authenticode not used. |
| SR-8 determinism | Two runs give identical observation IDs and CBOM bytes (tests). |
| SR-9 bounded | Budgets are reported as `partial`/`budget` (test), never silent. |
| SR-11 honest failure | Denied directories are counted (129 on the test machine as a standard user) and produce the privilege warning; failed sensors appear in coverage. |
| SR-12 minimisation | User names tokenised (`Users/%USER%/...`); `--redact-host` verified on the real machine (real host name and user name absent from the output); F2 fixed. |

## Not reviewed

The Windows syscall layer that L3 will need (it does not exist yet, by design); any Linux behaviour on a real host;
elevated-run behaviour (F6); the server's handling of uploaded host CBOMs beyond the existing tests.

## Recommendation

**Accept Level 1 for the standard-user tier** on Windows and Debian-family (fixtures) once F1-F3 are re-tested —
they are. Do **not** claim elevated-tier behaviour (F6) or live-Linux behaviour.
