# Authenticode evidence: an offline-verification investigation

**Question.** Can the host collector verify a file's embedded Authenticode signature **without any network
activity** and still give a useful answer? The earlier design cut Authenticode from level 1 because `WinVerifyTrust`
performs certificate revocation checks that can reach the network, which a collector must never do
(ADR-0004, ADR-0005; `artifacts/agent-04-implementation-design.md`), and because it was believed to need hand-written
syscalls. This investigation tests both beliefs. **Nothing here ships in the collector.**

**Tool.** [`testing/hostdiscovery/authenticode-probe`](../../testing/hostdiscovery/authenticode-probe/main.go),
a standalone Windows program. It verifies each file twice:

| Mode | `RevocationChecks` | `ProvFlags` |
|---|---|---|
| offline (what a collector would use) | `WTD_REVOKE_NONE` | `WTD_REVOCATION_CHECK_NONE \| WTD_CACHE_ONLY_URL_RETRIEVAL` |
| online (default, network-capable) | `WTD_REVOKE_WHOLECHAIN` | none |

and, around each call, looks for the two visible side effects of a network fetch: TCP connections owned by the
process (sampled every millisecond) and new or updated files in the CryptoAPI URL cache
(`%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache`), where fetched CRLs and OCSP responses are stored.

**Environment.** Windows 11 build 26200, standard user, network **connected** (this is not a disconnected-network
test; see "What this does not prove"). Run 2026-09-26.

## Results

| # | File | What it is | offline | online | URL cache changed (offline / online) |
|---|---|---|---|---|---|
| 1 | Firefox `nss3.dll` | third-party, embedded signature (Mozilla) | valid, 149 ms | valid, 508 ms | **0 / 8** |
| 2 | copy of #1 in another folder | control: signature is not tied to the path | valid | valid | 0 / 0 |
| 3 | #1 with one byte changed in a section | content modified after signing | `TRUST_E_BAD_DIGEST` | same | 0 / 0 |
| 4 | #1 with one byte changed mid-signature | see note below | valid | valid | 0 / 0 |
| 5 | #1 with 16 bytes changed across the signature | corrupted signature | `0x80093103` (ASN.1 corrupt) | same | 0 / 0 |
| 6 | #1 cut off at the signature | signature stripped | `TRUST_E_NOSIGNATURE` | same | 0 / 0 |
| 7 | #1 with a lying security-directory length | malformed header | `TRUST_E_NOSIGNATURE` | same | 0 / 0 |
| 8 | text file named `.dll` | decoy | `TRUST_E_SUBJECT_FORM_UNKNOWN` | same | 0 / 0 |
| 9 | Git for Windows `libcrypto-3-x64.dll` | unsigned third-party | `TRUST_E_NOSIGNATURE` | same | 0 / 0 |
| 10 | this project's `cipherhorizon-collector.exe` | unsigned | `TRUST_E_NOSIGNATURE` | same | 0 / 0 |
| 11 | `msedge.exe` | Microsoft, embedded signature | valid, 46 ms | valid | 0 / 0 (already cached) |
| 12 | `System32\kernel32.dll` | Microsoft system file | valid | valid | 0 / 0 |
| 13 | `System32\notepad.exe` | Microsoft, **catalog-signed** | `TRUST_E_NOSIGNATURE` | same | 0 / 0 |

Windows' own `Get-AuthenticodeSignature` agreed on the ground truth for the files it was asked about: #1 valid
(Mozilla Corporation), #9 and #10 NotSigned. It also reports `notepad.exe` as *Valid*, which the file-mode call in
row 13 does not (see finding 3).

## Findings

1. **The offline flags produce no observable network side effect; the default mode does.** In the first online run
   the call changed **8** URL-cache files, and the offline call changed **0** (later online runs also changed 0,
   presumably because the data was by then cached). This matches what the flags are documented to do
   (`WTD_CACHE_ONLY_URL_RETRIEVAL` restricts URL retrieval to the cache; `WTD_REVOKE_NONE` turns revocation
   checking off; the documentation was read from memory here and should be re-read before the sensor is built)
   and is the kind of evidence the ADR asked for. The TCP sampler saw nothing in *either* mode, including the online run that demonstrably fetched, so the
   sampler is too coarse to be evidence on its own and the URL cache is the better signal.
2. **The offline answers are the same as the online ones** for every file tested, and useful: valid, content
   modified, signature corrupt, signature absent, not a signature-bearing file. Offline verification is also fast
   (about 30 to 150 ms a file, dominated by the first cold call).
3. **Catalog-signed files look unsigned in file mode.** Windows system files such as `notepad.exe` are signed by a
   *catalog*, not embedded, and the file-mode call reports `TRUST_E_NOSIGNATURE` for them. A collector must
   therefore report that result as **"no embedded signature found (catalog signatures are not evaluated)"** and
   never as "unsigned". Evaluating catalogs needs the `CryptCATAdmin*` family, which `golang.org/x/sys/windows`
   does not wrap; it would be a small hand-written binding and is not needed for third-party libraries, which are
   almost always embedded-signed or unsigned.
4. **One flipped byte in the middle of the signature blob was not detected** (row 4). That is probably not a fault
   in the API: the byte most likely fell in a part of the PKCS#7 structure that verification does not
   authenticate (an unused certificate or padding), but this was not confirmed by locating the byte. Row 5 shows real corruption is caught. It is a reminder that "valid" means *the
   verification passed*, not *every byte of the file is authenticated*, and it is why the SHA-256 (Stage 1) is
   recorded separately.
5. **`x/sys/windows` already wraps `WinVerifyTrustEx`**, its structures and the flag constants. The earlier note
   that Authenticode "needs hand-written syscalls" was wrong for embedded signatures. (`x/sys` still lacks the
   `bcrypt`/`ncrypt` and certificate-property wrappers that levels 2 and 3 need.)

## What this does not prove

- **Not a disconnected-network test.** The network was up. The evidence is that the offline flags left no trace a
  fetch leaves and that the online mode did. A test with the network genuinely unavailable (a VM or an isolated
  machine) should be run before the sensor ships.
- **A missing intermediate certificate.** With cache-only retrieval, a chain that needs an intermediate not in the
  file or the local store cannot be completed (AIA fetching is disabled). The signature would then be intact but
  the chain unverified; the collector should report that as a distinct result, not as a failure of the file.
- **The observation window.** A sampling interval of 1 ms cannot rule out very short connections.
- **One machine, one signer set.** Mozilla, Microsoft and unsigned files.

## Recommendation

**Feasible; propose as an optional, separate sensor in a later stage. Do not add it to the current collector.**
If built, its rules would be:

- run only on files **already validated as PE images by the collector's own parser** (so `WinVerifyTrust` is never
  handed an arbitrary file, and no third-party signature-format handler is invoked for a decoy);
- offline flags only, in code, with a test that fails if a network-capable flag is ever set;
- evidence kind **`signature`**, not `present`: results `valid`, `content-modified`, `signature-corrupt`,
  `no-embedded-signature (catalog not evaluated)`, `chain-incomplete-offline`, each with the numeric result code;
- the verified **signer subject** becomes the *verified publisher*, kept separate from the PE version resource's
  `CompanyName`, which anyone can write and which stays "claimed";
- a test on a machine with the network genuinely disabled.

## Reproduce

```powershell
go build -o dist\authenticode-probe.exe .\testing\hostdiscovery\authenticode-probe
.\dist\authenticode-probe.exe "C:\Program Files\Mozilla Firefox\nss3.dll"
```

The tampered copies in rows 3 to 8 are made by reading a signed DLL and changing bytes (a few lines of PowerShell;
the offsets come from the PE security data directory). The probe writes nothing and changes no system setting.
