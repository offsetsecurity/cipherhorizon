# ENH-003 · Open any certificate and read the whole X.509 document

Status: decisions taken by the owner 2026-10-21 (§5: OD-1 and OD-2 as recommended); to be baselined as PRD-012. Raised by the owner: "the certs are just shown as a chain; clicking
one should show more details of the X.509 document." Reviewed against `feat/classical-strength` (PR #19).

## 1. Short answer

**The data is there; the screens hide it, or do not have it.**
- The scanner keeps every certificate as served: the DER bytes and about 30 parsed fields, every extension
  included (`internal/tlsprobe/report.go`, `CertInfo`).
- What a user sees is far less:
  - the report's *Chain as served* is a list that cannot be clicked;
  - its details sit in a collapsed *Validity, names and every field* panel, which shows 14 fields;
  - the Inventory’s certificate page shows 14.
- Neither shows the extensions, their criticality or their values, or the key identifiers, the revocation
  pointers, the policies, the constraints or the PEM.
- The panel's title promises "every field", which it does not show.

## 2. Evidence

| # | Where | Today | Gap |
|---|---|---|---|
| X-1 | Report › Configuration › *Chain as served* | Position, subject, role, key, expiry | Not clickable; no way from a node to its details |
| X-2 | Report › *Validity, names and every field* | Subject, issuer, key, key OID, signature, signature OID, serial, validity, type, SHA-256, SANs, must-staple, SCT | **Missing although recorded:** key usage, extended key usage, basic constraints (path length), name constraints, policies and validation type, AKI/SKI, OCSP and CA-issuer URLs, CRL points, RSA exponent, SPKI SHA-256, RSASSA-PSS parameters, every extension with its criticality, the PEM |
| X-3 | Inventory › Certificate | 14 fields, findings, where it was seen | No link to the scan report or the chain it was served in; same gaps as X-2 |
| X-4 | Both | Key shown as "ECDSA 256-bit (P-256)" | No classical strength or post-quantum status on the certificate's own page (PRD-010 has both) |
| X-5 | Model | Extensions recorded as OID, name, critical | The **values** of extensions we do not model (an unknown private extension, the SCT list) are not kept, though the DER is |
| X-6 | Export | Certificates CSV and JSON for the whole scan | No PEM for one certificate, which is what an engineer pastes into `openssl x509 -text` |

## 3. Proposal

### 3.1 One certificate page, reached from everywhere
The certificate page (`#/certificates/{sha256}`) becomes the single place a certificate is read:
- every node of *Chain as served* is a link to it;
- so is every certificate in the Inventory, Findings and the CBOM tab.

When the link comes from a report, the page names that scan ("served by modern-hybrid, position 0 of 2") and links
back to it. Back returns to the chain.

### 3.2 What the page shows, in the order an engineer reads it

1. **Summary line:**
   - who it is for and who issued it;
   - the days left;
   - trust per store (when reached from a scan);
   - its findings.
2. **Identity:** subject, issuer (a link to the issuer's page when we hold it), serial, version, validity, lifetime
   and validation type (DV, OV or EV).
3. **Names:** SANs by type (DNS, IP, e-mail, URI), wildcards, and whether the CN is the only name.
4. **Public key:**
   - algorithm, size or curve, and the RSA exponent;
   - SPKI SHA-256 (for pinning);
   - the **classical strength** and the **post-quantum status**, both from PRD-010 and the catalogue.
5. **Signature:** algorithm, OID, PSS parameters, and its strength (the weaker of the hash and the issuer's key;
   ENH-002 §3.2).
6. **Extensions, every one:**
   - name, OID, a *critical* mark, and the decoded value;
   - covers key usage, EKU, basic constraints with the path length, name constraints, AKI and SKI, AIA (OCSP and CA
     issuers), CRL distribution points, certificate policies, the SCT list (log and time) and must-staple;
   - an extension we do not decode is shown as its OID and its hex value, never dropped.
7. **Fingerprints:** SHA-256, plus SHA-1 marked as an identifier only.
8. **Raw:**
   - the PEM, with *Copy* and *Download .pem*;
   - the `openssl x509 -text -noout` line to inspect it locally.
9. **Where it was seen**, as today.

### 3.3 Server
- `GET /api/v1/certificates/{sha256}/x509` decodes the stored DER on request: the fields above, every extension
  with its value, and the PEM. It is read only.
  - Nothing new is stored, so old scans gain the view without a rescan, as long as they kept the DER (tls-report/2
    and later).
  - Earlier reports show the parsed fields they have and say the raw certificate was not kept.
- The decode is the standard library's `x509.ParseCertificate`, plus a small table of extension decoders. It is
  fuzzed: the DER comes from the network.

### 3.4 Report changes
- *Chain as served*: each node is a link, with a *details* affordance and a keyboard focus ring.
- The collapsed *Validity, names and every field* panel is renamed *Quick look*, since it is not every field, and
  points to the full page.

## 4. Requirements (draft for PRD-012)

| ID | Requirement | Test |
|---|---|---|
| REQ-X509-1 | `GET /api/v1/certificates/{sha256}/x509` returns every field of §3.2, every extension with criticality and value, and the PEM; an unknown extension is returned as OID and hex | `TestX509DecodeShowsEveryExtension` (a corpus of real and crafted certificates) |
| REQ-X509-2 | The decoder never panics or hangs on hostile DER | `FuzzX509Decode` |
| REQ-X509-3 | Every node in *Chain as served*, and every certificate link in the app, opens the certificate page; Back returns | e2e `E2E-X509-1` |
| REQ-X509-4 | The page shows the sections of §3.2 in that order, with the key's classical strength and post-quantum status | e2e `E2E-X509-2` |
| REQ-X509-5 | *Copy* and *Download .pem* give a PEM that `x509.ParseCertificate` reads back to the same SHA-256 | `TestPEMRoundTrip`, e2e `E2E-X509-3` |
| REQ-X509-6 | A report without DER says so and shows what it has | `TestX509WithoutDERSaysSo` |
| REQ-X509-7 | All values render as text: certificates carry attacker-chosen strings (the existing hostile-subject fixture) | e2e `E2E-X509-4` |
| REQ-X509-8 | The page is usable at 375 px and with the keyboard alone | e2e `E2E-X509-5` |

## 5. Decisions (owner, 2026-10-21)

- **OD-1: a full page or a side panel? Decided: a full page.** It can be linked to and shared, Back works, and it
  is the page the Inventory already has. A side panel would be a second place that shows the same thing.
- **OD-2: show the SHA-1 fingerprint? Decided: yes, labelled as an identifier only**, because that is what people
  still search for in CA portals and browsers.

## 6. Size

Medium:
- one read-only API endpoint with a decoder and a fuzz test;
- one page extended;
- links from four places.

No scanner change, and no stored-data change.
