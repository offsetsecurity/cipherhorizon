# CRYPTO-REVIEW-001 · Every number and claim on the rebuilt screens (PRD-013)

Date: 2026-10-21. Reviewer role: cryptographer (PRD-013 REQ-VIS-12). Build: branch `feat/classes-and-x509`.
Scope: what the Summary, Configuration, the certificate page, the Inventory and the SSH tables *show*: each
number, word, glyph and sentence, checked against the evaluation it is drawn from and against the source that
evaluation cites. The evaluation's own rules were reviewed for PRD-010 and PRD-011; they are re-read here only
where a screen states them.

Data: the CI journey's demo estate (TLS targets 9440 to 9459, SSH targets 9460 to 9467, the imported CBOMs and
the machine inventories), as the screens render it. Agreement between screen and API is checked by the journey
(E2E-STR-1, E2E-CLS-1, E2E-CLS-2, E2E-VIS-3, E2E-VIS-4, E2E-VIS-6, E2E-XV-2); this review checks that what the API
says is right.

## Verdict

**Signed off**, with the four defects below fixed in this branch and three notes left as they are, each with its
reason. No number on the rebuilt screens disagrees with its cited source.

## Numbers checked against their sources

| Shown | Value | Source | Holds |
|---|---|---|---|
| RSA and finite-field DH | 1024 → 80, 2048 → 112, 3072 → 128, 7680 → 192, 15360 → 256 | NIST SP 800-57 Part 1 Rev. 5, Table 2 | yes |
| Elliptic curves | P-256, X25519, Ed25519 → 128; P-384 → 192; P-521 → 256 (half the base-point order) | SP 800-57 Table 2; SP 800-186 Table 1 | yes |
| Hybrid groups | X25519MLKEM768 and SecP256r1MLKEM768 → 192; SecP384r1MLKEM1024 → 256 | the stronger component: breaking a hybrid needs both components broken (draft-ietf-tls-ecdhe-mlkem); ML-KEM-768 is category 3 (FIPS 203) | yes |
| ML-KEM, ML-DSA, SLH-DSA | 512/44/128x → 128; 768/65/192x → 192; 1024/87/256x → 256 | NIST PQC security categories 1, 3, 5 (2 for ML-DSA-44, rated 128 as its SHA-256 collision bound), FIPS 203, 204, 205 | yes |
| AES, ChaCha20 | by key: 128, 192, 256 | SP 800-57 Table 2 | yes |
| 3DES | 112, disallowed | SP 800-131A Rev. 2 (disallowed for encryption after 2023); 64-bit block (SWEET32) makes its suites Weak | yes |
| RC4, export, NULL, single DES, anonymous | broken | RFC 7465; RFC 9325 §4.1 | yes |
| Hashes in key derivation | SHA-256 and SHA-384 (HKDF, PRF) → 256 | SP 800-57 Table 3, KDF column | yes |
| Hashes in a signature, and alone | SHA-256 → 128, SHA-384 → 192, SHA-512 → 256 (collision resistance); SHA-1 and MD5 broken | SP 800-57 Table 3; SP 800-131A | yes |
| A signature | the weaker of its hash and its key: ECDSA-SHA256 on P-256 → 128; SHA256withRSA on RSA-2048 → 112 | SP 800-57 §5.6.1.2 | yes |
| HMAC | HMAC-SHA-1 → 128, HMAC-SHA-256 and -512 → 256; HMAC-MD5 not rated | SP 800-57 Table 3, HMAC column; RFC 6151 | yes |
| Suite word | Insecure under 80 or a broken part; Weak 80 to 111, a 64-bit block or no forward secrecy; Acceptable 112 to 127 or not AEAD; Strong otherwise | PRD-010 §2, from RFC 9325 §4.1 and §4.2 | yes: every suite on six reports agrees (E2E-STR-1) |
| Bands of the bits bar | red < 80, amber 80 to 111, grey 112 to 127, green ≥ 128 | the same edges as the suite word | yes, and Help states them |
| Readiness L0 to L4 | the level stepper fills to the evaluation's level | PRD-004 readiness model | yes (E2E-VIS-4) |
| Certificate validity | days left, of the lifetime; "today" placed where today falls | the certificate's notBefore and notAfter | yes, after fix 4 |
| Fingerprints | SHA-256 of the DER; SPKI SHA-256; SHA-1 marked "an identifier for searching, never for trust" | the DER (E2E-XV-3 hashes the PEM shown) | yes |

## Claims checked

- **"A suite is as strong as its weakest part, ringed."** True of the rule (PRD-010 §2) and of the screen: the ringed
  cell is the evaluation's `weakest` part on every suite of the journey's reports (E2E-CLS-2). When two parts tie,
  the first in column order is ringed, which is the part the evaluation names.
- **"A current client gets TLS 1.3 + suite + group."** The banner is the scan's negotiated handshake (the default
  client hello), not a guess. Correct.
- **Off versions "as they should be".** Only said when TLS 1.2 or 1.3 is on; SSL 2, SSL 3, TLS 1.0 and 1.1 off is
  right per RFC 8996. TLS 1.3 off says "should be on" (RFC 9325 §3.1.1 SHOULD); after fix 2, so does TLS 1.2 when
  neither modern version is on (RFC 9325 §3.1.1 MUST).
- **Post-quantum glyphs.** A shield with a check (quantum-safe) on ML-KEM, ML-DSA, SLH-DSA, the hybrids, AES and
  SHA-2; a shield with a cross on RSA, ECDH, ECDSA, EdDSA and finite-field DH. AES-128 as quantum-safe follows NIST
  IR 8547 (AES-128 stays approved; Grover gives no practical break) and the cited classification the CBOM carries.
- **Heartbeat.** "Negotiated" when the server echoes the extension (RFC 6520), with the note that nothing needs it;
  the probe does not send a heartbeat request, so it never claims Heartbleed is present or absent (that stays
  *Not tested* under Weaknesses). 0-RTT says *Not probed yet*: correct, nothing sends early data.
- **Revocation.** "The CA's responder and CRL are not contacted" is true of the scanner: it reads a stapled response
  and the URLs the certificate names, and never fetches them.
- **The chain.** "No trusted root" and "Missing intermediate" follow the PKI view's own diagnosis (RFC 5280 path
  building against the bundled stores and the system's CA bundle); the dashed card says what to do.
- **HSTS.** The header is shown as sent. After fix 3, an invalid header says browsers ignore it (RFC 6797 §8.1),
  instead of reading as `max-age 0`.

## Defects found and fixed in this branch

1. **"Finite-field DH: not offered" next to an accepted `TLS_DH_anon` suite.** The scan accepted a DH suite but kept
   no prime for it (the report's `dh` is empty), so the screen must not say the opposite of the suite list. The chip now says *offered ·
   prime not recorded*, and keeps *not offered* for when no DH suite was accepted.
2. **TLS 1.2 off, with neither modern version on, showed only "!"**. It now says *should be on*, as TLS 1.3 does.
3. **An invalid HSTS header read as "max-age 0: switched off".** A header with problems (duplicate directives, no
   max-age, bad syntax) is ignored by user agents. The tile now says so, in the problem tone, and shows the header.
4. **The certificate page put "today" mid-way under the validity bar** whatever the date, which reads as half the
   lifetime used. It is now placed where today falls (and left out near either end, where the dates are).
5. **An EC key with *Key encipherment* passed silently.** An elliptic-curve key cannot encipher; RFC 8813 §3 says a CA
   must not assert it for one. The usage chip is now marked *not for an EC key*, with the reason in its tooltip.
   (The demo's self-signed `localhost` certificate asserts it.)
6. **"Not a quantum question" on algorithms no source classified.** The Inventory's `unknown` status (HMAC, 3DES, RC4,
   MD5, and `SHA256withRSA` from an imported CBOM) showed the dot with that tooltip, which is wrong for RSA. *Not
   classified* now has its own glyph (a question mark) and the class bars' legend says *not classified*.

## Notes left as they are

- **TLS 1.3 suites are rated with the weakest group the server accepts.** In TLS 1.3 the suite does not fix the
  group; a client that offers only X25519 gets X25519 from a server that prefers X25519MLKEM768. Rating with the
  weakest accepted group is the honest worst case, and the group chips beside each version show which groups those
  are, with their bits. Kept.
- **SSL 3 suites name their MAC "HMAC-MD5" and "HMAC-SHA-1".** SSL 3's MAC is the pre-HMAC construction of
  RFC 6101 §5.2.3.1, not HMAC. Its strength is shown as not rated (MD5) or by its hash (SHA-1), and the version is
  marked *should be off* regardless, so no verdict changes. Renaming would change the CBOM's algorithm names; left
  for the catalogue owner, noted here.
- **The Inventory rates a hash alone by collision resistance** (SHA-256 → 128), while Configuration rates the same
  hash deriving keys at 256. Both are right for their use; Help says which is which, and each figure's tooltip
  names its basis.

## Sign-off

The numbers and claims on the rebuilt screens are correct against their sources, with fixes 1 to 6 in this branch.
Signed off for PRD-013 REQ-VIS-12, cryptography.
