# macOS support — future work item

```
Research:        ✓   (desk research only; see below)
Architecture:    ✗   (only constraints recorded)
Implementation:  ✗   NOT IMPLEMENTED
Testing:         ✗   NOT VALIDATED — no macOS test environment
Production:      ✗   macOS is NOT supported
```

**Do not claim macOS support anywhere in the product, README, release notes or CBOM output** until every line
above except Research is ✓ on a real macOS environment. The README and release notes must say
plainly that macOS is not supported, and list only the platforms and levels that have actually been validated.

## Why this is deferred

There is no macOS machine. macOS behaviour depends on state that cannot be inferred from documentation:
Keychain contents and lock state, TCC (Transparency, Consent and Control) grants, SIP, MDM profiles, hardware
(Apple silicon vs Intel), OS version. Nothing here was run.

## What desk research found (all secondary; none tested)

| Topic | Finding | Source type |
|---|---|---|
| Certificates / key metadata | The Security framework holds X.509 certificates, keys and identities. `SecItemCopyMatching` returns attributes or references; `kSecReturnData=false` / `kSecReturnRef` avoid retrieving item data. `SecItemExport` is the export path and must not be used. | Apple docs, forum threads |
| Access model | Reading protected locations needs **Full Disk Access**, granted by user or MDM profile; without it "large portions of the system are invisible" to a scanner. The user keychain is per-user and may be locked (`errSecInteractionNotAllowed`-class failures reported when the device is locked). | Vendor support pages, forums |
| Packages | No single package database: installer receipts (`/var/db/receipts`), Homebrew's `Cellar`, application bundles. | [H] |
| Libraries | System TLS is Apple's (Secure Transport/Network framework, CryptoKit); OpenSSL/LibreSSL builds may be bundled or via Homebrew. | [H] |
| Binary analysis | Go's `debug/macho` reads Mach-O imports (analogous to `debug/elf`; *note the Windows lesson: verify the exact API returns data*). | [H]/stdlib docs |
| Process inspection | SIP and TCC restrict inspecting other processes. | [H] |
| Distribution | Signing with a **Developer ID** certificate, **hardened runtime**, **notarization** (`notarytool`), `stapler` for offline verification; `.pkg` needs Developer ID *Installer*; MDM (Jamf/Intune/Munki) for enterprise delivery. | Apple docs, vendor guides |

## What must happen before implementation

1. Obtain a real macOS environment (or explicitly decide a CI runner is acceptable for *specific* levels and
   document the gap: a CI runner has none of an enterprise Mac's MDM/TCC/Keychain state).
2. Prove, by test, each mechanism above — especially `SecItemCopyMatching` metadata-only enumeration, what a
   *non-FDA* process can see, and that no path prompts the user or returns key material.
3. Re-run the Agent 2 procedure for macOS as a tested column of the platform matrix.
4. Decide the distribution: Developer ID + notarization is mandatory for a downloadable collector.

## Tracking

- Matrix column: every cell `?`.
- Any code path added for macOS must be behind an explicit, off-by-default build/config gate until validated.
