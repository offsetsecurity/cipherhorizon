# PRD-012 · Open any certificate and read the whole X.509 document

Status: baselined 2026-10-21. The owner approved [ENH-003](ENH-003-certificate-viewer.md) with both open decisions
as recommended:
- a full page, not a side panel;
- the SHA-1 fingerprint shown, labelled as an identifier only.

Issue #21. Status per requirement: [RTM](../program/RTM.md). Results: QA-REPORT-011.

## 1. Goals

| # | Goal | Measure |
|---|---|---|
| G-1 | Every certificate the product shows can be opened | Every chain node and certificate link leads to one page |
| G-2 | That page is the whole X.509 document | Every field and every extension the DER holds, decoded or as OID and hex |
| G-3 | Nothing new is stored, and old scans gain the view | Decoded from the DER on request |

## 2. Requirements

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-XV-1** | **Decode.** `GET /api/v1/certificates/{sha256}/x509` returns, from the stored DER, every field of ENH-003 §3.2: identity, names, public key with its classical strength and post-quantum status, signature with its strength, every extension (name, OID, critical, decoded value), fingerprints and the PEM. An extension it does not decode is OID and hex. | Matches `openssl x509 -text` on the test corpus | `TestX509DecodeShowsEveryExtension` | P0 |
| **REQ-XV-2** | **Hostile input.** The decoder never panics or hangs on any DER. | | `FuzzX509Decode` | P0 |
| **REQ-XV-3** | **Where the DER comes from.** The scan the page was opened from (`?scan=`), else the newest endpoint scan that saw it; only endpoint scans keep DER. A certificate known only from a report without DER (before tls-report/2), a machine inventory or an imported CBOM shows the fields it has, and says the raw certificate was not kept. | | `TestX509WithoutDERSaysSo` | P1 |
| **REQ-XV-4** | **Reached from everywhere.** Every node of *Chain as served*, the quick-look cards, and the CBOM tab's certificates link to `#/certificates/{sha256}`. When reached from a scan, the page names the scan and the chain position and links back. | Back returns to the chain | `script:testing/e2e/x509-phase.mjs#E2E-XV-1` | P0 |
| **REQ-XV-5** | **The page.** The sections of ENH-003 §3.2, in that order. The panel that said *every field* is renamed *Quick look*. | | `script:testing/e2e/x509-phase.mjs#E2E-XV-2` | P0 |
| **REQ-XV-6** | **PEM.** *Copy PEM* and *Download .pem* give a PEM that parses back to the same SHA-256. | | `TestPEMRoundTrip`, `script:testing/e2e/x509-phase.mjs#E2E-XV-3` | P1 |
| **REQ-XV-7** | **Text only.** Every value is rendered as text: certificates carry attacker-chosen strings. | The hostile-subject fixture runs no script | `script:testing/e2e/x509-phase.mjs#E2E-XV-4` | P0 |
| **REQ-XV-8** | **Phone and keyboard.** The page works at 375 px without sideways scroll, and every link and button is reachable by Tab. | | `script:testing/e2e/x509-phase.mjs#E2E-XV-5` | P1 |
| **REQ-XV-9** | **Documentation.** Help and the API reference describe the page and the endpoint. | | `report:docs/methodology.md` | P2 |
