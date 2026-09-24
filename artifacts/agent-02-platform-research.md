# Agent 2 — OS / Platform Research

```
AGENT      2 — OS / Platform Researcher
DATE       2026-09-24
OBJECTIVE  Challenge Agent 1's evidence model against what each platform can actually deliver, then
           determine how each evidence kind can be collected on Windows and Linux (macOS: research only).
INPUT      artifacts/agent-01-security-research.md and artifacts/handoff-01-security-to-platform.md
```

## 0. Conventions

Every cell and claim carries **how it is known**:

| Tag | Meaning |
|---|---|
| **[T]** | **Tested** by me on the Windows machine in this session (commands and results in §2). Note the scope: a **standard, non-elevated user** (`DESKTOP-KJRL2LP\Admin`, not in the Administrators group, no enabled privilege beyond `SeChangeNotify`), Windows 11 Pro build 26200. It is one machine, not "Windows". |
| **[C]** | Exercised by the repository's **existing code and unit tests** (the Debian/Ubuntu collector on synthetic `fstest.MapFS` fixtures) — *not* on a live Debian host. |
| **[R]** | **Researched** from vendor documentation or search results; not run by anyone here. |
| **[H]** | My reasoning; nothing cited. |

**Environmental limits, stated up front.** This machine has no WSL, no Docker and no Linux. **The Kali machine
named in the brief is not reachable from this session**, so *no Linux evidence in this document is tested*
except the existing Debian collector's fixtures. Everything Linux is `[R]`/`[C]`. That is a finding, not a
detail: **Agent 7 (test) must obtain Kali access or CI containers before any Linux collector is called
validated.** See §9.

Matrix symbols are the brief's: `✓` reliable · `△` partial · `✗` unavailable · `?` needs validation.

---

## 1. Challenge to Agent 1

I was asked not to accept the handoff blindly. Result per assumption and per anticipated challenge, with the
evidence that decided it.

### 1.1 Assumptions

| # | Agent 1 assumption | Verdict | Why (evidence) |
|---|---|---|---|
| A1 | Two axes: claim rung × method quality | **Accept the axes; change where method quality lives.** | Method quality is *nearly constant per (source, method)*: a `dpkg` row is authoritative, a filename match is heuristic. So it should be a **property of the collection method, declared once per collector method and referenced by each fact**, not a free per-fact number. The exception is real and I measured it: on Windows `Process.Modules` returned **one stub entry for `System`, `Idle`, `lsass`, `csrss`, `services`, `svchost`** and a full list for same-user processes **[T]** — quality varies *within one source*. So per-fact override must remain possible, but defaulting from the method keeps records small and auditable. |
| A2 | Ladder `present → capable → policy → provisioned → bound → loaded → exercised` | **Accept, with two changes:** (a) `capable` splits into two kinds; (b) the order of `provisioned` and `policy` is platform-dependent, so the ladder must be a *partial order*, not a strict sequence. | (a) see A5. (b) On Windows `provisioned` (cert stores) and `policy` (Schannel) were both trivially readable **[T]**; on a Debian host there is *no* system policy file at all, so `policy` is a per-application scavenger hunt while `provisioned` is a directory scan **[R]**. |
| A3 | Certificate/key **metadata** is obtainable without exposing key material | **Accept for certificates; qualify for keys.** | Certificates: `X509Store` enumeration returned algorithm, size, `HasPrivateKey` for 6 stores **[T]** — `HasPrivateKey` is a *presence* flag; no key was opened. Windows key metadata (`NCryptEnumKeys`, `NCryptGetProperty` length/export policy) is documented as metadata-only **[R]**. On Linux a **standalone private-key file cannot be characterised without parsing it**, which is exactly SR-1's forbidden act; only presence, permissions and an armor-label prefix are safe. **But** for a key that pairs with a discovered certificate, the certificate's public key already gives algorithm and size, so the private key need not be opened at all. That reframes the requirement: *"key metadata" = certificate-derived, plus presence for orphan keys.* |
| A4 | Policy evidence is common enough to be a level | **Accept — with a platform split.** | Strong on **RHEL-family, Amazon Linux 2023, SLE 15 SP4+** (`crypto-policies`: one state file, `update-crypto-policies --show`) and **Windows** (Schannel: `Get-TlsCipherSuite`, registry overrides, FIPS flag) **[T]/[R]**. **Weak** on Debian/Ubuntu/Alpine/Kali: no system-wide policy; only `openssl.cnf` (`MinProtocol`, `CipherString @SECLEVEL`) plus each daemon's own config **[R]**. On this Windows box the Schannel `Protocols` key exists but has **no subkeys** — i.e. *no overrides; defaults apply* **[T]** — so an honest record here is `policy = unspecified (defaults)`, not "nothing found". |
| A5 | "Capable" is *knowledge applied to present evidence* | **Reject as stated; split it.** | On Windows the OS can be **asked**: `BCryptOpenAlgorithmProvider("ML-KEM")` and `("ML-DSA")` returned `STATUS_SUCCESS`, and `BCryptEnumAlgorithms` listed 41 algorithms including legacy `RC4, MD2, MD4, DES, 3DES` **[T]**. That is a **probed capability** (an observation of the running OS), a stronger and different thing from **mapped capability** ("OpenSSL ≥ 3.5.0 provides ML-KEM", from a citation). They differ in strength, in failure mode and in what can falsify them, so they must not share one rung label. Also see §2.4: the same box's Schannel **cipher-suite list is entirely classical** and its curve list is `curve25519, NistP256, NistP384` — no hybrid — while CNG *can* do ML-KEM. **Capability of the crypto provider ≠ capability offered by the TLS stack.** That is the whole point of `policy` and `bound`, demonstrated on one machine. |

### 1.2 Agent 1's anticipated challenges

| Question | Answer |
|---|---|
| Is claim × method over-engineered vs a single confidence field? | Not if method is defaulted from the collector method (A1). A single number cannot express "authoritative source, weak claim". |
| Is `present` different from `capable` on Windows? | **Yes, and more than on Linux.** On Windows `present` (software) and `capable` (OS algorithm set) come from unrelated sources; there is no package→algorithm mapping for the OS itself. Keep both. |
| Does "never stronger than the weakest link" make the graph too pessimistic? | It is pessimistic by design but not useless: the *upper bound* remains informative ("nginx could offer ML-KEM"). Provide both the claim of each edge and the derived path claim; do not collapse them. |
| Is static vs deployment `bound` worth two rungs? | **One rung, with a `binding` kind.** I measured why they differ (§2.6) but the enterprise decision is the same ("could use"). Two rungs would fake precision. |
| Is the SR-1 armor-prefix idea safe? | **Safe only for a fixed, tiny prefix read and immediately discarded, and unnecessary for cert-paired keys.** For unpaired keys it is the only non-parsing signal available (`ENCRYPTED PRIVATE KEY` vs `PRIVATE KEY`). Recommend keeping it *optional and off by default*; file **name and permissions** alone give presence. |

### 1.3 New findings Agent 1 did not have

1. **Static imports are not enough for `bound` — and I can prove it.** `firefox.exe` statically imports 17 DLLs, **none crypto-named**; NSS (`nss3.dll`) is loaded in **at least 7 running Firefox processes** **[T]** — it is not in the import table, so it is loaded dynamically. Conversely `openssl.exe` and `libssl-3-x64.dll` import `libcrypto`/`libssl` statically **[T]**. And `curl.exe` (Git for Windows) imports 5 DLLs with no crypto name — the crypto is presumably *transitive* through `libcurl` (**[H]**: I did not resolve `curl.exe`'s dependency chain, and Git's curl may use Schannel). So `bound` is a **graph problem** (transitive closure over imports) and static analysis has a **known false-negative class** (dynamic loading) that only `loaded` evidence closes.
2. **The Go standard library cannot read PE imports through the obvious call.** `debug/pe.File.ImportedLibraries()` returned **0** for every binary I tried; `ImportedSymbols()` returned 221–1750 and correctly identified the DLLs **[T]**. `debug/elf` and `debug/macho` do implement library imports **[R]**. A collector must use `ImportedSymbols` (or its own PE parser) on Windows. That is the kind of platform trap Agent 4 should hear about.
3. **On Windows the interesting crypto is mostly *outside* any package database.** The uninstall registry has 31 entries, none named after a crypto library, yet a bounded file search found **OpenSSL 3.5.7 (Git for Windows), GnuTLS (VLC), NSS (Firefox)** as loose DLLs **[T]**. PE version resources gave `FileVersion=3.5.7, ProductName=The OpenSSL Toolkit` without loading the file **[T]**, and `Get-AuthenticodeSignature` reported it **`NotSigned`** **[T]** (useful integrity evidence, and a reminder we must not trust `CompanyName`, which anyone can set). Note the consequence for the *existing* mapping: `openssl` 3.5.x ⇒ ML-KEM capable applies to a **file version**, not a package version — the capability table must key on *(family, version)* independent of how the artefact was found.
4. **OpenSSL 3.5.7 is present on this box.** By Agent 1's own rule this file is `present` and, per the OpenSSL 3.5 mapping, `capable` of ML-KEM — yet Git's TLS *policy* is unknown and Schannel offers no hybrid. A correct assessment would say "candidate, not exposed" — the level structure must be able to say that.
5. **`Get-Tpm` returned nothing unelevated** (empty fields) **[T]**: TPM-backed key evidence is an admin-only rung on Windows.

---

## 2. Windows

### 2.1 Test bed

`DESKTOP-KJRL2LP`, Windows 11 Pro build 10.0.26200, Windows PowerShell 5.1, standard user, not elevated. Nothing was written. Output below was reduced to counts and algorithm names; **no subject names, thumbprints, serials or key bytes were printed or stored** (SR-1/SR-12 applied to the research itself).

### 2.2 `present` — software inventory

| Source | Result | Verdict |
|---|---|---|
| Uninstall registry (`HKLM`, `WOW6432Node`, `HKCU`) | 31 entries **[T]** | △ Lists installed products, not libraries; no crypto information. Includes per-user installs. |
| Package providers (`Get-Package`) | `msi, msu, NuGet, PowerShellGet, Programs` **[T]** | △ Overlaps the registry; slower. |
| `winget` | present **[T]** | △ Subprocess; covers only winget-managed apps. Avoid (SR-4). |
| **Loose files** (`libcrypto*.dll`, `nss3.dll`, …) via bounded directory walk (`Program Files`, `Program Files (x86)`, `%LOCALAPPDATA%\Programs`, depth 6) | 8 crypto DLLs in 3 products **[T]** | **✓ for finding bundled libraries; the only method that did.** |
| PE version resource (no load) | `FileVersion`, `ProductName` readable **[T]** | ✓ (`debug/pe` + resource parsing, or `golang.org/x/sys/windows` `GetFileVersionInfo`) |
| Authenticode signature status | `NotSigned` reported **[T]** | ✓ (API: `WinVerifyTrust`; via PowerShell here) — integrity evidence |

Conclusion: `present` on Windows **needs a filesystem walker as a first-class method**, not just a package
reader. It must be bounded (depth, file count, time), and allow-listed to install locations (SR-5, SR-9).

### 2.3 `capable` — probed (OS) vs mapped (bundled libraries)

**Probed** **[T]**: `BCryptOpenAlgorithmProvider` succeeded for `RSA, ECDSA_P256, ECDH_P256, AES, SHA256, ML-KEM, ML-DSA`; `BCryptEnumAlgorithms(all ops)` returned 41 names including `CHACHA20_POLY1305, SHA3-256…512, KMAC, RSA, DH, ECDH_P256/384/521, ECDSA_*, DSA, ML-DSA, Composite-ML-DSA` and the legacy `MD2, MD4, MD5, RC2, RC4, DES, DESX, 3DES`. (ML-KEM did not appear in the enumeration filter I used because it is a key-encapsulation operation, but opening the provider succeeded.) This is a direct OS observation and needs no privilege. The documentation says PQC arrived in Windows 11 24H2 Insider builds with GA to follow **[S]**; the probe supersedes that on this machine.

**Mapped**: bundled libraries (`libcrypto 3.5.7`) — the existing knowledge-table approach.

The two must be recorded as different claim kinds.

### 2.4 `policy` — Schannel and FIPS

| Item | Result | Verdict |
|---|---|---|
| Effective TLS cipher suites | `Get-TlsCipherSuite`: 28 enabled, all classical (TLS 1.3 AES-GCM plus TLS 1.2 ECDHE) **[T]** | ✓ cmdlet; **✗ no API for it in pure Go** — Schannel exposes it through the registry/`BCryptEnumContextFunctions` (`[R]`). Implementable as `BCryptEnumContextFunctions(CRYPT_LOCAL, "SSL")` (`[R]`, not tested by me). |
| Effective ECC curves | `Get-TlsEccCurve`: `curve25519, NistP256, NistP384` **[T]** | ✓ (same API family) |
| Registry overrides | `SCHANNEL\Protocols` exists with **no subkeys**; `Ciphers`, `CipherSuites`, `Hashes`, `KeyExchangeAlgorithms` keys exist **[T]** | ✓ readable unelevated. Emptiness = *defaults apply* → record as `unspecified`, never as `none`. |
| Group Policy (SSL Configuration) | `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` exists **[T]** | ✓ |
| FIPS mode | `FipsAlgorithmPolicy\Enabled = 0` **[T]** | ✓ |

Agent 1 asked whether Windows policy can be read *without registry scraping*. **Partly**: the *effective* configuration is obtained from a documented API/cmdlet; the *override direction* (an admin explicitly disabling TLS 1.0) is only in the registry/GPO **[R]**. Both are needed: the effective list tells you what Schannel will *offer*, the overrides tell you *why*.

### 2.5 `provisioned` — certificates and key metadata

| Item | Result |
|---|---|
| Certificate stores (CurrentUser and LocalMachine; My, Root, CA) | 6 stores enumerated, **no elevation** **[T]**: e.g. `CurrentUser\Root` 37 certs = `RSA-2048×15, RSA-4096×14, ECC×4, RSA-1024×4`; `CurrentUser\My` 1 cert (RSA-2048, `HasPrivateKey=True`) |
| Finding worth noting | **RSA-1024 ×4 in the machine root store; RSA-512 ×1 in the intermediate store [T]** — direct, cheap, high-value evidence of weak trust anchors, obtained without touching any key |
| ECC size/curve | `PublicKey.Key.KeySize` returned blank for ECC in this .NET Framework path **[T]** — the curve needs the key-parameters path (`ECDsa.ExportParameters(false)` — public only). Do not assume the easy property works. |
| Key metadata beyond `HasPrivateKey` | `NCryptEnumKeys` + `NCryptGetProperty` (length, export policy) are documented metadata-only **[R]**; **not tested by me**. Machine-scope keys and TPM/Pluton providers need elevation **[H]** (`Get-Tpm` empty unelevated **[T]**). |
| CNG/CAPI providers | 9 KSPs registered (Software, Smart Card, Platform/TPM, Pluton, Passport, …) from `HKLM\...\Cryptography\Providers` **[T]** (registry read) |

Pure-Go route, **verified against the module cache (`golang.org/x/sys` v0.47.0, already an *indirect*
dependency in `go.mod`)**: it wraps `CertOpenStore`, `CertOpenSystemStore`, `CertEnumCertificatesInStore`,
`CertGetNameString`, `CertFindExtension` and the chain functions, so **store enumeration needs no PowerShell and no cgo**.
It does **not** wrap `CertGetCertificateContextProperty` (needed for the "has a key reference"
`CERT_KEY_PROV_INFO_PROP_ID` test) **nor any `bcrypt.dll`/`ncrypt.dll` function**, so `HasPrivateKey`, the CNG algorithm probe and key
properties need our own thin `NewLazySystemDLL` bindings. Consequences for Agent 4: (a) promoting `x/sys` from indirect to direct is a small,
already-vendored-in-the-graph dependency change; (b) the hand-written syscall layer is security-sensitive and must be
review-gated (it is the one place a call to `NCryptExportKey` could sneak in — see §7).

### 2.6 `bound` — application ↔ library/material

| Method | Result |
|---|---|
| **Static imports** (PE import table) | Works in pure Go via `debug/pe.File.ImportedSymbols` **[T]**; `openssl.exe` → `libcrypto-3-x64.dll`+`libssl-3-x64.dll` ✓; `ssh.exe` (Git) → `msys-crypto-3.dll` ✓; `curl.exe` and `firefox.exe` → **no crypto DLL named** (transitive / dynamic) **[T]**. `ImportedLibraries()` is **broken (returns 0)** **[T]**. |
| Services (deployment association) | 301 services (124 running) readable unelevated via CIM **[T]**; each carries an image path → feeds the import walk. Pure-Go equivalent: service-control-manager API (`golang.org/x/sys/windows/svc/mgr`, **[R]**, may need rights for some services). |
| Schannel/CNG as an implicit binding | Any process that imports `schannel`/`bcrypt`/`ncrypt` is bound to the OS provider; the import walk already sees `bcrypt.dll`, `crypt32.dll` etc. **[T]** |
| Config-driven binding (IIS/HTTP.sys bindings, `netsh http show sslcert`, app configs) | **[R]** Not tested. `netsh` is a subprocess (SR-4); the same data lives in the registry (`HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo`) **[H]**. |

### 2.7 `loaded` — runtime

| Method | Result |
|---|---|
| `Process.Modules` (unelevated, same user) | Populated for user processes: found `nss3.dll` in at least 7 Firefox processes and Schannel/CNG DLLs in others **[T]** — this proved the static-import blind spot (§1.3). |
| Same call on protected/other-context processes | Returned **1 stub entry** for `System, Idle, lsass, csrss, services, svchost, MsMpEng` **[T]** — *not an error*. **A naive collector would record "1 module, none crypto" as a negative.** This is the clearest false-negative trap found. Must be treated as `unknown`, and detected (e.g. module count of 1 for a process whose image is not the sole module). |
| Elevated inspection / ETW / Schannel event log | **[R]** Requires admin; not tested. |

### 2.8 `exercised`

Schannel logs handshakes to the System event log **only if** SChannel logging is enabled (registry
`EventLogging`) **[R]**; default is errors only. **Not a reliable general source.** Real observation of use is
the **network side's** job (`tls scan`), consistent with Agent 1 §5.

### 2.9 Windows summary of what reads without privilege

Certificate stores ✓, Schannel effective config (via cmdlets) ✓, Schannel/GPO/FIPS registry ✓, uninstall
registry ✓, loose-file walk ✓, PE version + signature ✓, CNG algorithm probe ✓, CNG provider list ✓, services ✓,
same-user process modules △. Needs elevation/uncertain: TPM (`Get-Tpm` empty) ✗, other users' process modules
✗ (stubbed), machine-scope key metadata ?, ETW ✗.

---

## 3. Linux (research; **nothing below is tested**)

Linux is many platforms. Each is described by the **five things a collector needs**: how packages are
recorded, where crypto policy lives, where certificates live, what FIPS looks like, and privilege.

### 3.1 Common to all Linux

| Evidence | Mechanism | Notes |
|---|---|---|
| Static linkage (`bound`) | `debug/elf` `ImportedLibraries()` — DT_NEEDED **[R]** (Go stdlib implements it for ELF); resolves only names, so transitive closure needs `ldconfig` cache (`/etc/ld.so.cache`, a binary file we would parse ourselves) or package `Depends` | ✓/△ pure Go |
| Package-dependency association | dpkg `Depends:` / rpm `Requires` / apk `D:` give *package-level* "X depends on libssl3" without opening any binary | ✓ **cheapest, most reliable `bound` on Linux [R]**; already inside the database we read for `present` |
| Runtime (`loaded`) | `/proc/<pid>/maps` (own processes unprivileged; others need root or `ptrace_scope` permissions) **[R]** | △ |
| systemd services | `/etc/systemd/system`, `/usr/lib/systemd/system` unit files | ✓ parse text (deployment `bound`) |
| FIPS mode | `/proc/sys/crypto/fips_enabled` (`1`) **[R]** | ✓ file read, unprivileged |
| OpenSSL config | `/etc/ssl/openssl.cnf` (Debian family, Alpine), `/etc/pki/tls/openssl.cnf` (RHEL family): `MinProtocol`, `CipherString`, `Ciphersuites`, `Groups`, providers | ✓ parse `[system_default_sect]`; follows `.include` — needs bounded include resolution (SR-5) |
| Trust stores | `/etc/ssl/certs`, `/usr/local/share/ca-certificates` (Debian), `/etc/pki/ca-trust` (RHEL) | ✓ PEM/DER directory scan |
| Java | `java.security` (`jdk.tls.disabledAlgorithms`), `cacerts` | △ needs JDK discovery |
| Application config | `sshd_config` (`KexAlgorithms`, `Ciphers`, `HostKey`), nginx/Apache TLS directives | ✓ per-application parsers; each is its own work item |

### 3.2 Per distribution

| Distro | Package DB | System crypto policy | Notes / traps |
|---|---|---|---|
| **Debian / Ubuntu** | `/var/lib/dpkg/status` text **[C]** | **None system-wide**; `openssl.cnf` only; Ubuntu 22.04 default `CipherString = DEFAULT:@SECLEVEL=2` **[S]** | Existing collector applies. Policy is a scavenger hunt. |
| **Kali** | dpkg **[R]** | **Deliberately weakened**: since 2021.3 `openssl.cnf`+`kali.cnf` re-enable TLS 1.0/1.1 and old ciphers **[S]** (Kali docs) | **A test environment, not representative** — and, usefully, a *ground-truth for a "legacy" host*: expected `policy` there is *permits legacy*. |
| **RHEL / Rocky / Alma** | RHEL 9+: `rpmdb.sqlite` (SQLite); RHEL 8 and earlier: Berkeley DB **[S]** | **Strong**: `crypto-policies` — policy in `/etc/crypto-policies/config`; generated backend snippets; `update-crypto-policies --show` (**subprocess** — read the state files directly instead **[H]**); levels `DEFAULT, LEGACY, FUTURE, FIPS` **[S]** | Best host for `policy` evidence. Setting the `FIPS` *policy* is **not** FIPS *mode* (`fips=1` kernel flag) — two facts, keep both **[S]**. |
| **SUSE / SLE / openSUSE** | rpm; SUSE reportedly uses the **ndb** backend (`Packages.db`) which needs a dedicated reader **[S]** | `crypto-policies` since **SLE 15 SP4**; levels incl. `BSI`, `NEXT`, `EMPTY` **[S]** | Reader availability for ndb is unverified — ask Agent 4/7 to prove it on a real SLE/openSUSE image. |
| **Alpine** | `/lib/apk/db/installed` — plain text, `P:` name `V:` version `D:` deps **[S]** | None; `openssl.cnf` only; musl libc | Simplest format of all; trap: Alpine has switched between **LibreSSL and OpenSSL** across releases (OpenSSL again since 3.9, Jan 2019 **[S]**), so a library name does not imply its family/version mapping |
| **Amazon Linux** | AL2023: rpm (sqlite; `[R]`, verify); AL2: BDB | AL2023: `crypto-policies` + `fips-mode-setup` **[S]** | AL2023 documented FIPS 140-3 validation **[S]** |

**Pure-Go RPM reading.** `github.com/knqyf263/go-rpmdb` (MIT) is built on `github.com/glebarez/go-sqlite`, i.e. the
pure-Go **modernc** SQLite **[S]** (its `go.mod`), and is the reader used by container scanners; whether it
covers **NDB** is **unverified** **[R]**. This project already depends on `modernc.org/sqlite`
**[C]** (`go.mod`), so the added weight is small. Whether to depend on it or write a narrow reader is Agent
4's call; **licence and maintenance need review either way** ("no unnecessary dependencies" — standing
project constraint).

### 3.3 Privilege on Linux (research)

Unprivileged: package DBs (world-readable by default), `/etc` configs (mostly), certificate directories,
`/proc/sys/crypto/fips_enabled`, own-process `/proc/<pid>/maps`. Root/`CAP_SYS_PTRACE`: other users'
`/proc/<pid>/maps`, `/etc/ssl/private/*`, some service configs with secrets (`/etc/nginx` may be readable, keys not), `/root`.
**Design consequence** [H]: *do not* run as root by default; where a file is unreadable, record `unknown
(permission)` — never silence.

---

## 4. macOS — researched, NOT implemented, NOT validated

Full notes in `docs/platform/MACOS_SUPPORT.md`. Summary: the Security framework (`SecItemCopyMatching`,
Keychain) is the certificate/key-metadata API, and `SecItemCopyMatching` with `kSecReturnData=false`/
`kSecReturnRef` is the non-exporting metadata path **[S]**; Full Disk Access (TCC) gates large areas of disk and
is granted by MDM profile or the user **[S]**; there is no single package database (receipts,
Homebrew, `.pkg`) **[R]**; SIP restricts process introspection **[R]**; distribution requires Developer ID
signing plus notarization (`notarytool`, `stapler`) **[S]**. The Go stdlib has `debug/macho` for Mach-O
imports **[R]**. **No cell for macOS is anything but `?`.**

---

## 5. The matrix

Legend: `✓` reliable · `△` partial · `✗` unavailable · `?` needs validation. Suffix: `ᵀ` tested here, `ᶜ` repository code/fixtures only, `ʳ` researched only. Column *Amazon* is added to the brief's set.

| Evidence | Windows | Debian | Ubuntu | RHEL | SUSE | Alpine | Amazon | Kali | macOS |
|---|---|---|---|---|---|---|---|---|---|
| **Package** (installed products) | △ᵀ (uninstall registry; no crypto info) | ✓ᶜ | ✓ᶜ | ✓ʳ (el9 sqlite) △ʳ (el8 BDB) | ?ʳ (ndb) | ✓ʳ | ✓ʳ (AL2023) △ʳ (AL2) | ✓ᶜ | ?ʳ |
| **Crypto libraries** (system + bundled) | ✓ᵀ bundled via file walk + PE version; system libs are OS components | △ʳ pkg ✓ᶜ, bundled needs file walk | △ʳ (same) | △ʳ | △ʳ | △ʳ | △ʳ | △ʳ | ?ʳ |
| **Crypto providers** | ✓ᵀ CNG providers + algorithm probe (incl. ML-KEM/ML-DSA) | △ʳ OpenSSL providers via `openssl.cnf`, PKCS#11 (p11-kit), NSS | △ʳ | △ʳ | △ʳ | △ʳ | △ʳ | △ʳ | ?ʳ |
| **Configuration** (policy) | ✓ᵀ Schannel effective + overrides + GPO + FIPS | △ʳ `openssl.cnf`, no system policy | △ʳ (same) | ✓ʳ `crypto-policies` + FIPS | ✓ʳ (SLE 15 SP4+) △ʳ before | △ʳ `openssl.cnf` only | ✓ʳ (AL2023) | △ʳ (weakened defaults) | ?ʳ |
| **Certificates** | ✓ᵀ (6 stores, unelevated) | ✓ʳ dir scan | ✓ʳ | ✓ʳ | ✓ʳ | ✓ʳ | ✓ʳ | ✓ʳ | ?ʳ Keychain, TCC |
| **Key metadata** | △ᵀ `HasPrivateKey` ✓; CNG key properties ?ʳ; TPM ✗ᵀ unelevated | △ʳ presence + cert-paired only (SR-1) | △ʳ | △ʳ | △ʳ | △ʳ | △ʳ | △ʳ | ?ʳ |
| **Application association** | △ᵀ static imports ✓ (transitive/dynamic ✗), services ✓ | ✓ʳ pkg `Depends` + `debug/elf` | ✓ʳ | ✓ʳ pkg Requires | ✓ʳ | ✓ʳ apk `D:` | ✓ʳ | ✓ʳ | ?ʳ |
| **Runtime evidence** | △ᵀ same-user modules ✓; protected processes **stubbed (false-negative trap)**; ETW ✗ᵀ unelevated | △ʳ `/proc/*/maps` (root for others) | △ʳ | △ʳ | △ʳ | △ʳ | △ʳ | △ʳ | ✗?ʳ SIP/TCC |

Two honest readings of the matrix: **(1)** the only fully-`ᵀ` column is Windows, on one standard-user machine —
it does not certify "Windows"; **(2)** the Linux columns are almost entirely `ʳ`, which is exactly what makes
Linux the *higher-risk* platform for Agent 5 to claim complete.

---

## 6. Privilege ladder (what needs what)

| Tier | Windows | Linux |
|---|---|---|
| **Standard user** | cert stores, Schannel config/registry, CNG probe, uninstall registry, file walk of install dirs, PE analysis, services list, own-session modules **[T]** | package DBs, `/etc` configs, cert dirs, FIPS flag, own `/proc/*/maps` **[R]** |
| **Administrator / root** | TPM, machine key metadata, other users' modules, event logs/ETW **[R]** | other users' `/proc`, private dirs, some service configs **[R]** |
| **Process-inspection / debug capability** | `SeDebugPrivilege`-class access | `CAP_SYS_PTRACE` |

**Recommendation to Agent 3 [H]:** design for the standard-user tier as the *default and complete-in-itself
level*, with each elevated tier a separate, separately-reported capability.

## 7. Secret-safety analysis (SR-1..SR-12) per path

| Path | Closest approach to secrets | Structural safeguard |
|---|---|---|
| Certificate stores | The store also holds private keys | Use enumeration APIs that return the *certificate context*; never call key-open/export; `HasPrivateKey`/`CERT_KEY_PROV_INFO_PROP_ID` are references, not material |
| CNG key enumeration | `NCryptOpenKey` yields a key handle | Read properties only; **never** call `NCryptExportKey`; consider forbidding that symbol in the package by a lint/`depguard`-style test |
| Linux private-key files | Contents *are* the secret | Presence, mode, owner by `Stat`; optional fixed-prefix armor label, never logged; **prefer cert-paired derivation** |
| Config parsing | Configs often embed passwords/`PSK`/`ssl_password_file` | Parse only an **allow-list of directive names**; never emit raw config text; redact values not in a value allow-list |
| File walk | Could open anything | Allow-listed roots, extension filter, size cap, symlink policy (SR-5) |
| `/proc/*/maps` | Reveals paths | Emit only module names matching a crypto pattern |
| Subprocess | Injection, environment leakage | Avoid (SR-4); all probes above have API/file alternatives, except `winget` and `netsh` which are not needed |
| Certificate subjects | Attacker-controlled | Treat as text (SR-6) |

A concrete testable rule for Agent 6/7 **[H]**: a **canary corpus** — synthetic private keys, passwords in
configs, tokens — must be placed on the test hosts and must appear **nowhere** in any output, log or CBOM.

## 8. Cost and stability (SR-9)

Measured **[T]**, roughly: certificate stores are instant; the bounded file walk (3 roots, depth 6) finished in
seconds; `Process.Modules` over 272 processes was the slowest probe and touches every process (invasive at
scale, and the source of the stub trap). Not measured: Linux, large file systems, network shares. **Never
recurse network mounts or pseudo-filesystems by default** **[H]**. Budgets (time, files, bytes) must be
explicit configuration and be reported when hit — a hit budget is `incomplete`, not `done`.

## 9. What can be tested where (input to Agent 7)

| Environment | Available now? | Notes |
|---|---|---|
| This Windows machine | **Yes** | Standard user only; an elevated run must be a deliberate, documented step |
| Kali machine | **No — not reachable from this session** | The user's Kali host must be provided (SSH, or the user runs a script and returns output). Kali is atypical (§3.2) |
| Docker / VM | **Not installed here** | — |
| **GitHub Actions** (the repo is going to GitHub) | **Yes, cheaply** | `ubuntu-latest` runs Docker: images for Debian, Ubuntu, Alpine, Rocky/Alma (RHEL family), openSUSE, Amazon Linux 2023 and Kali (`kalilinux/kali-rolling`) exist **[S]**; `windows-latest` runners exist. Containers share the host kernel: `/proc/sys/crypto/fips_enabled` and process-level evidence are **not** faithful in containers **[H]**, so FIPS and runtime tests need real VMs |
| macOS | **GitHub `macos-latest` runners exist [S]**, but the brief defers macOS and a CI runner is not an enterprise Mac (MDM, TCC, Keychain state) | Keep "NOT VALIDATED" until Agent 7 decides |

## 10. Signed collector and deployment (separate workstream)

| Platform | Findings | Status |
|---|---|---|
| **Windows** | Authenticode signing removes "Unknown publisher"; SmartScreen judges **publisher reputation and file-hash reputation**, and reputation is **keyed to the certificate thumbprint, so renewing a certificate resets it**; the **EV-certificate SmartScreen shortcut was removed in 2024** [S]. Store-published MSIX is re-signed by Microsoft [S]. Enterprise channels: MSI/MSIX via Intune or SCCM — search returned no detail on them **[unverified]** | R |
| **Linux** | Trust is via the **package manager**: APT repositories are signed (`Release.gpg`/`InRelease`, `signed-by=` keyrings), RPM packages carry GPG signatures and `repo_gpgcheck` verifies metadata [S]; enterprise = internal signed repository + configuration management | R |
| **macOS (future)** | Developer ID + notarization (`notarytool`, `stapler`), hardened runtime; MDM (Jamf/Intune/Munki) delivery [S] | R, not validated |

**Finding:** the distribution model is not one-size. The evidence points to the brief's own combination —
**a signed standalone collector *and* native packages** — because Windows enterprises deploy MSI/MSIX through
management tools and Linux enterprises install from a signed repository, while ad-hoc/ephemeral runs want a
single verifiable file. A **persistent agent** is a separate decision (it changes SR-2, SR-3, SR-7, SR-10).
This repository's release workflow already produces **cosign keyless signatures, SLSA provenance and SBOMs**
for the standalone archives **[C]**; **Authenticode, `.deb/.rpm`, and repository signing are not built**.

## 11. Recommendations to Agent 3

1. Model the ladder as a **partial order** with **two kinds of `capable`**: *probed* (asked of the running
   system; Windows CNG) and *mapped* (cited knowledge applied to a present artefact). (A5)
2. Key **capability mappings on (family, version)**, independent of *how* the artefact was found (package,
   loose file, container layer). (§1.3-3)
3. Make **a bounded filesystem walker a first-class collection method** alongside package readers. (§2.2)
4. Represent policy as **`permits / forbids / unspecified`** and record `unspecified (defaults)` for empty
   override sets (Schannel proved the case). (§2.4)
5. Model `bound` as a **graph with edge kinds** (`static-import`, `package-depends`, `service-config`,
   `dynamic-load`), keeping the strongest *path* claim separate from each edge. Static imports have a **proven false-negative class** (dynamic
   loading); do not present the absence of a static edge as absence of use. (§1.3-1)
6. Treat `loaded` evidence as **`unknown`**, not negative, when the source cannot see a process (stub trap). (§2.7)
7. Default to the **standard-user tier**; every elevated capability is separate and reported. (§6)
8. Make **`unknown (reason)`** a first-class outcome: permission, budget, unsupported, stub. (SR-11)
9. Treat **canary-secret tests** as a gate. (§7)
10. Decide **Windows without PowerShell**: every Windows probe I ran has an in-process API equivalent; PowerShell
    subprocesses conflict with SR-4 and add a dependency on the shell's version (5.1 here). Use PowerShell only
    as a *test oracle* to cross-check the Go implementation.
11. **Do not claim Linux support beyond `[R]`** until real hosts or containers are tested. (§9)

## 12. Assumptions, risks, open questions

| Assumption | Risk if wrong |
|---|---|
| The Windows machine is representative of a *standard-user* Windows endpoint | Domain-joined, GPO-managed, Server SKUs and Windows Server Core will differ (e.g. FIPS on, TLS overrides present) |
| Container images are a faithful stand-in for package/config evidence | Kernel-level evidence (FIPS, `/proc`) is not faithful |
| go-rpmdb (or similar) reads NDB | SUSE support needs its own reader |

| Risk | Severity | Note |
|---|---|---|
| Stub-module false negatives (Windows runtime) | High | Found by test, not documentation |
| Linux support declared without any live test | High | §9 |
| ML-KEM-capable *library* mistaken for an ML-KEM-*using* application | High | The same box shows OS capable, Schannel classical-only |
| Scope creep into application-specific config parsers | Medium | Each parser is its own work item; do not promise a set |

**Open questions:** (1) `NCryptEnumKeys`/`NCryptGetProperty` behaviour unelevated — not tested. (2) Can Schannel's
effective list be read via `BCryptEnumContextFunctions` from pure Go? Documented; not tested. (3) NDB reading.
(4) Real Kali/RHEL/SLE/Alpine hosts. (5) Domain-joined Windows behaviour. (6) The Intune/SCCM packaging
specifics.

## 13. What failed

- No WSL/Docker/Linux here; Kali unreachable; **all Linux is untested**.
- `Get-Tpm` empty unelevated; `winget`/subprocess paths not pursued.
- `go-rpmdb` README/`go.mod` pages did not state NDB/BDB support; Windows Intune/SCCM search returned no detail.
- First Go PE probe used `ImportedLibraries()` and returned 0 for every binary — the wrong API; corrected to `ImportedSymbols()`. (Recorded because it is exactly the mistake a builder would make.)
- A Python heredoc mangled a probe source once; the file was rewritten (tooling, not a finding).

## Sources

Tested here: see §2 (commands run against this machine; probe programs kept in the session scratchpad, not the repo).

Documentation / search (secondary unless noted):
- Microsoft Learn: [CNG algorithm identifiers](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers), [Cipher suites in TLS/SSL (Schannel)](https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel), [TLS registry settings](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings), [NCryptGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty), [NCryptEnumKeys](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptenumkeys), [Key storage property identifiers](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers), [Code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options), [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- Red Hat: [Using system-wide cryptographic policies (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening), [Switching RHEL to FIPS mode](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening), [SQLite RPM database in RHEL 9](https://access.redhat.com/articles/6891951)
- SUSE/openSUSE: [SDB:Crypto-policies](https://en.opensuse.org/SDB:Crypto-policies), [SLES 15 SP6 FIPS 140-3](https://documentation.suse.com/sles/15-SP6/html/SLES-all/cha-security-fips.html)
- Amazon: [Enable FIPS mode on AL2023](https://docs.aws.amazon.com/linux/al2023/ug/fips-mode.html)
- Alpine: [Apk spec](https://wiki.alpinelinux.org/wiki/Apk_spec)
- Kali: [OpenSSL configuration](https://www.kali.org/docs/general-use/openssl-configuration/); Ubuntu: [OpenSSL](https://ubuntu.com/server/docs/explanation/crypto/openssl/)
- RPM readers: [go-rpmdb](https://github.com/knqyf263/go-rpmdb), [Fedora: SQLite rpmdb](https://fedoraproject.org/wiki/Changes/Sqlite_Rpmdb)
- Apple: [SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)), [Developer ID](https://developer.apple.com/developer-id)
- Debian/APT: [SecureApt](https://help.ubuntu.com/community/SecureApt); Red Hat: [RPM and GPG](https://www.redhat.com/en/blog/rpm-gpg-verify-packages)
