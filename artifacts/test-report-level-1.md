# Test report — Level 1 (ground truth)

```
AGENT      7 — Test Engineer
DATE       2026-09-24
PRINCIPLE  Not "does the command run?" but EXPECTED vs DETECTED vs MISSING vs FALSE POSITIVE, against an
           independent oracle, on a real host where one exists.
```

## 1. Environments — what was and was not available

| Environment | Used? | Detail |
|---|---|---|
| **This Windows machine** | **Yes** | Windows 11 Pro build 26200, standard user (not in Administrators, not elevated), HP ProBook, Go 1.27. |
| **WSL** | **No** | Not installed. Installing it enables Windows features (elevation + reboot) and was not attempted; the user must run `wsl --install -d Debian` once (`testing/hostdiscovery/README.md`). |
| **Kali machine** | **No** | Not reachable from this session. |
| **Docker / VM** | **No** | Not installed. |
| **CI containers** | **Prepared, not run** | The repository is not on GitHub yet; the CI matrix already runs Linux/Windows/macOS unit tests and fuzzes the PE parser. |
| **Elevated (Administrator) run** | **No** | This session cannot elevate. |

Consequence, stated once and applying to every line below: **Linux, macOS and the elevated tier are not validated.**

## 2. Automated suite

| Check | Result |
|---|---|
| `go test ./...` | 322 top-level tests, **0 failures, 0 skips** |
| `golangci-lint` | 0 issues |
| `go vet` | clean for `GOOS=windows` and linux |
| Browser journey (Edge over CDP) | **44/44** steps |
| Legacy compatibility (`TestLegacyOutputIsPreserved`) | **pass**: for the Debian 13 and Ubuntu 24.04 fixtures the components, `provides`/`dependsOn` edges and every property of the frozen pre-refactor output are unchanged; only properties were added |
| Architecture (`internal/archtest`) | pass; negative control run (planted `os/exec` and a CycloneDX import were detected, then removed) |
| Fuzz `FuzzReadVersion` (PE parser) | 2,778,661 executions in 45 s, **no crash**; plus every truncation and 3,000 random corruptions of a valid image |

## 3. Ground truth — the PE parser against genuine binaries

The synthetic PE builder cannot catch a mistake real binaries expose. The parser was run on **400 genuine Microsoft
system DLLs** and compared with PowerShell's `VersionInfo`:

| Measure | Result |
|---|---|
| Files compared | 400 |
| File version identical to the oracle | **400 / 400** |
| Parse errors | **0** |
| Product name identical (where both present) | **388 / 388** |

(`internal/sense/pefiles/real_windows_test.go` keeps a lighter version of this on Windows: 300 binaries, >= 95%
yielding a version; observed 291/300, the 9 without a version resource carry none.)

## 4. Ground truth — the collector on this machine

`testing/hostdiscovery/compare-windows.ps1`: an oracle that lists **any** `.dll`/`.exe` under the same roots
(depth <= 8) whose *file name or embedded product/description* mentions crypto. It does not use the collector's
patterns.

| | Count |
|---|---|
| DETECTED by the collector | 22 artefacts |
| EXPECTED by the oracle (broad net) | 61 candidates |
| AGREED (found by both) | **22** |
| VERSION MISMATCHES | **0** |
| FALSE POSITIVES (collector-only) | **0** |
| MISSING (oracle-only) | 39, adjudicated below |
| Coverage | `partial`, reason `permission`, **129 locations denied** (standard user); the privilege warning was shown |
| Run time | about 3 seconds |

What it found and read correctly: **OpenSSL 3.5.7** (`libcrypto`/`libssl` in three Git locations, `openssl.exe`,
`msys-crypto`/`msys-ssl`), **libssh2 1.11.1**, **NSS** in Firefox, and Nettle/GnuTLS/GnuPG binaries that carry no
version resource (credited with ungated capability only, or none, as designed).

### Adjudication of the 39 MISSING (single reviewer: the author, so treat as provisional)

| Verdict | n | What |
|---|---|---|
| **Correct exclusion** (not a crypto library, or noise) | 34 | `EmbeddedBrowserWebView.dll` x8 (Chromium's crypto is statically linked: a stated blind spot); `libcurl-openssl-4.dll` x2 (curl, which *binds* OpenSSL: an L5 candidate); `System.Security.Cryptography.ProtectedData.dll` x2 (a .NET managed wrapper); `libgnutls_plugin.dll` (a VLC plugin, deliberately not matched); `msys-gpg-error-0.dll`; 17 GnuPG helper executables and 3 Nettle command-line tools (parts of packages already represented by `gpg.exe` / `libnettle`) |
| **Real gap** (a crypto artefact we should recognise) | 5 | `legacy.dll` (OpenSSL's *legacy provider*: MD4, RC4, DES), `SSLeay.dll`, `cryptocme2.dll` (RSA Crypto-C ME), `VBoxLibSsh.dll` (libssh derivative), `msys-hcrypto-4.dll` (Heimdal). Each needs a knowledge entry or a provider concept, not a wider pattern. |

Backtrack performed on the first run: **5 further gaps were real and cheap** (`openssl.exe` x2, `msys-gnutls`,
`msys-nettle`, `msys-hogweed`), so recognition was extended (with lookalike negatives in
`TestRecognizeFile`) and the run repeated: 16 -> 22 detected.

**Against the adjudicated set:** precision 22/22 (100%), recall 22/27 (81%) for crypto libraries and tools under the
searched roots. Not measurable: anything outside the roots, statically linked, or renamed.

## 5. The canary gate (SR-1), on the real host

Eight files were planted in `%LOCALAPPDATA%\Programs\zz-cipherhorizon-canary` (a location the collector walks) and
removed afterwards: `libcrypto.key`, `id_rsa`, `server.pfx`, `passwords.txt`, `token.json` (each holding a marker
such as `CANARY-PRIVATE-KEY-1`), `libssl-3-x64.dll.bak`, and two **decoys with recognised library names but text
content** (`libcrypto-3-x64.dll`, `nss3.dll`).

| Check | Result |
|---|---|
| Canary markers (`CANARY-`, `BEGIN ... PRIVATE KEY`, `hunter2`, `api_key`) anywhere in the CBOM or stderr | **0** |
| Key / pfx / password / token / backup files inventoried | **0** |
| Decoys | reported as **present, heuristic, `pe-valid=false`, no `provides-claim`** (never credited) |
| Directory removed afterwards | yes |

The synthetic version (`TestNeverOpensAnythingButRecognisedLibraries`, a filesystem that records every open) proves
the stronger property that nothing but recognised libraries is ever *opened*.

## 6. Redaction and privilege, on the real host

- Standard user: warning printed (`129 location(s) could not be read ... Administrator (Windows) or root (Linux) may
  reveal more`), recorded in the CBOM (`privilege-tier=user`, `coverage-note`, `coverage: ... denied=129`); exit code 0.
- `--redact-host`: subject became `host-b8c5491b4a82`; the real host name is absent; no user name in any path (only the
  word "Administrator" in the warning text); no `host-id` without the flag.
- Both real CBOMs validated against the CycloneDX 1.6 schema.

## 7. The Linux harness, exercised without a Linux host

`testing/hostdiscovery/lab-debian.sh` compares `dpkg-query` and `openssl version` (harness-side oracle) with the CBOM.
Its logic was run against the Debian 13 fixture with shims for `dpkg-query` and `openssl`:

- agreeing oracle: **3 expected, 3 detected, 3 agreed, 0 false positives, exit 0**;
- oracle saying OpenSSL 3.0 while the CBOM credits ML-KEM: **`CAPABILITY MISMATCH`, exit 1** (negative control);
- it also caught **a bug in the harness itself** (it treated collector exit code 1 as acceptable), now fixed.

This proves the harness's logic, **not** the collector on Linux.

## 8. Not tested, by category

| Not tested | Why | To close |
|---|---|---|
| Any live Linux host | no environment | install WSL (one elevated command) then run `lab-debian.sh`, as user and as root |
| Kali specifically | unreachable | same script on Kali |
| Elevated Windows run | cannot elevate here | run `compare-windows.ps1` from an elevated PowerShell; record time and denied count |
| Domain-joined / Server / Windows on ARM | not available | out of scope until a real target exists |
| Large estates | one machine | measure on a big `Program Files` |
| RHEL/SUSE/Alpine/Amazon, macOS | not implemented | later levels |

## 9. Recommendation to the gatekeeper

Standard-user Windows and Debian-family (fixtures): evidence supports acceptance. Everything in §8: **not validated**.
