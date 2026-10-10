package algo

import cdx "github.com/CycloneDX/cyclonedx-go"

// Provenance of every value below:
//
//   - OIDs for NIST-registered algorithms (AES arc, SHA-2, ML-KEM, ML-DSA,
//     SLH-DSA): NIST CSOR algorithm registration,
//     https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
//   - AES-128/256 in CBC, GCM and CCM: id-aes128-CBC ... id-aes256-CCM under the
//     NIST AES arc 2.16.840.1.101.3.4.1 (RFC 3565 for CBC, RFC 5084 for GCM and
//     CCM: .2/.42 CBC, .6/.46 GCM, .7/.47 CCM for 128/256-bit keys).
//   - rsaEncryption 1.2.840.113549.1.1.1: RFC 8017 appendix A.1.
//   - id-dsa 1.2.840.10040.4.1, dhpublicnumber 1.2.840.10046.2.1: RFC 3279.
//   - id-ecDH 1.3.132.1.12: RFC 5480 section 2.1.2.
//   - X25519 1.3.101.110 and Ed25519 1.3.101.112: RFC 8410.
//   - QuantumLevel: FIPS 203 (ML-KEM 1/3/5), FIPS 204 (ML-DSA 2/3/5),
//     FIPS 205 (SLH-DSA 1/3/5), each from the standard's own parameter-set table.
//
// Deliberately absent, because no single authoritative OID exists: ECDSA has
// none of its own (only per-hash signature OIDs), and the generic "AES" family
// entry has none (OIDs are per key size and mode, which is why the variants
// below exist: a TLS suite names its key size and mode, and a CBOM should too). QuantumLevel is unset for every classical
// algorithm and for AES and SHA-2; the pqc package carries the reasoning for
// those instead.
// Reasons an algorithm has no post-quantum verdict (Algorithm.NoPQCVerdict).
const (
	legacyNoVerdict = "The open question for this algorithm is its classical strength (see classical-status); no post-quantum verdict is asserted."
	noCitedCategory = "No cited post-quantum analysis covers this algorithm (the NIST PQC security categories cite SHA-256, SHA-384 and AES), so none is asserted."
)

var catalogue = []Algorithm{
	// Classical public-key algorithms.
	{ID: "RSA", Primitive: cdx.CryptoPrimitivePKE, OID: "1.2.840.113549.1.1.1"},
	{ID: "DSA", Primitive: cdx.CryptoPrimitiveSignature, OID: "1.2.840.10040.4.1"},
	{ID: "DH", Primitive: cdx.CryptoPrimitiveKeyAgree, OID: "1.2.840.10046.2.1"},
	{ID: "ECDSA", Primitive: cdx.CryptoPrimitiveSignature},
	{ID: "ECDH", Primitive: cdx.CryptoPrimitiveKeyAgree, OID: "1.3.132.1.12"},
	{ID: "Ed25519", Primitive: cdx.CryptoPrimitiveSignature, OID: "1.3.101.112"},
	{ID: "X25519", Primitive: cdx.CryptoPrimitiveKeyAgree, OID: "1.3.101.110"},

	// Symmetric primitives and hashes.
	{ID: "AES", Primitive: cdx.CryptoPrimitiveBlockCipher},
	{ID: "AES-128-CBC", Primitive: cdx.CryptoPrimitiveBlockCipher, OID: "2.16.840.1.101.3.4.1.2", ParameterSet: "128", Mode: "cbc"},
	{ID: "AES-256-CBC", Primitive: cdx.CryptoPrimitiveBlockCipher, OID: "2.16.840.1.101.3.4.1.42", ParameterSet: "256", Mode: "cbc"},
	{ID: "AES-128-GCM", Primitive: cdx.CryptoPrimitiveAE, OID: "2.16.840.1.101.3.4.1.6", ParameterSet: "128", Mode: "gcm"},
	{ID: "AES-256-GCM", Primitive: cdx.CryptoPrimitiveAE, OID: "2.16.840.1.101.3.4.1.46", ParameterSet: "256", Mode: "gcm"},
	{ID: "AES-128-CCM", Primitive: cdx.CryptoPrimitiveAE, OID: "2.16.840.1.101.3.4.1.7", ParameterSet: "128", Mode: "ccm"},
	{ID: "AES-256-CCM", Primitive: cdx.CryptoPrimitiveAE, OID: "2.16.840.1.101.3.4.1.47", ParameterSet: "256", Mode: "ccm"},
	// ChaCha20-Poly1305 (RFC 8439) has no single authoritative OID: unlike AES, no
	// PKIX or CMS registration assigns it one, so, as with ECDSA, OID is left empty.
	{ID: "ChaCha20-Poly1305", Primitive: cdx.CryptoPrimitiveAE},
	{ID: "SHA-256", Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.1"},
	{ID: "SHA-384", Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.2"},
	{ID: "SHA-512", Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.3"},

	// Algorithms Windows CNG registers that the catalogue did not yet carry (ADR-0013).
	// Every OID below was read from its source on 2026-09-26: MD5 and SHA-1 from RFC 3370
	// section 2 (md5 1.2.840.113549.2.5, sha-1 1.3.14.3.2.26); SHA3-256/384/512 from the NIST
	// CSOR hash registry (2.16.840.1.101.3.4.2.8, .9, .10). The others have no single
	// authoritative OID (an OID names a cipher IN a mode, not the cipher), so it is left
	// empty. Legacy statements say only what the cited source itself says.
	{ID: "SHA-1", NoPQCVerdict: legacyNoVerdict, Primitive: cdx.CryptoPrimitiveHash, OID: "1.3.14.3.2.26", Legacy: &Legacy{
		Summary:  "published attacks show it is not prudent to use where collision resistance is required",
		Citation: "RFC 6194, Security Considerations for the SHA-0 and SHA-1 Message-Digest Algorithms", URL: "https://www.rfc-editor.org/rfc/rfc6194"}},
	{ID: "MD5", NoPQCVerdict: legacyNoVerdict, Primitive: cdx.CryptoPrimitiveHash, OID: "1.2.840.113549.2.5", Legacy: &Legacy{
		Summary:  "has updated security considerations because of weaknesses",
		Citation: "RFC 6151, Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms", URL: "https://www.rfc-editor.org/rfc/rfc6151"}},
	{ID: "MD4", NoPQCVerdict: legacyNoVerdict, Primitive: cdx.CryptoPrimitiveHash, Legacy: &Legacy{
		Summary:  "moved to Historic status because of practical attacks",
		Citation: "RFC 6150, MD4 to Historic Status", URL: "https://www.rfc-editor.org/rfc/rfc6150"}},
	{ID: "MD2", NoPQCVerdict: legacyNoVerdict, Primitive: cdx.CryptoPrimitiveHash, Legacy: &Legacy{
		Summary:  "moved to Historic status because it is cryptographically broken",
		Citation: "RFC 6149, MD2 to Historic Status", URL: "https://www.rfc-editor.org/rfc/rfc6149"}},
	{ID: "SHA3-256", NoPQCVerdict: noCitedCategory, Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.8"},
	{ID: "SHA3-384", NoPQCVerdict: noCitedCategory, Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.9"},
	{ID: "SHA3-512", NoPQCVerdict: noCitedCategory, Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.10"},
	{ID: "RC4", NoPQCVerdict: legacyNoVerdict, Primitive: cdx.CryptoPrimitiveStreamCipher, Legacy: &Legacy{
		Summary:  "TLS clients and servers must never negotiate RC4 cipher suites (a statement about TLS)",
		Citation: "RFC 7465, Prohibiting RC4 Cipher Suites", URL: "https://www.rfc-editor.org/rfc/rfc7465"}},
	{ID: "RC2", NoPQCVerdict: noCitedCategory, Primitive: cdx.CryptoPrimitiveBlockCipher},
	{ID: "DES", NoPQCVerdict: legacyNoVerdict, Primitive: cdx.CryptoPrimitiveBlockCipher, Legacy: &Legacy{
		Summary:  "its standard, FIPS 46-3, was withdrawn on May 19, 2005",
		Citation: "NIST FIPS 46-3, Data Encryption Standard (withdrawn)", URL: "https://csrc.nist.gov/pubs/fips/46-3/final"}},
	{ID: "3DES", NoPQCVerdict: legacyNoVerdict, Primitive: cdx.CryptoPrimitiveBlockCipher, Legacy: &Legacy{
		Summary:  "NIST urged migration to AES and announced plans to disallow it for TLS and IPsec (July 2017 announcement; no sunset date given there)",
		Citation: "NIST, Update to Current Use and Deprecation of TDEA", URL: "https://csrc.nist.gov/news/2017/update-to-current-use-and-deprecation-of-tdea"}},
	// Whole-family entries for the two post-quantum standards, used when an operating
	// system reports the family but no parameter set could be confirmed.
	{ID: "ML-KEM", Primitive: cdx.CryptoPrimitiveKEM},
	{ID: "ML-DSA", Primitive: cdx.CryptoPrimitiveSignature},

	// FIPS 203: ML-KEM.
	{ID: "ML-KEM-512", Primitive: cdx.CryptoPrimitiveKEM, OID: "2.16.840.1.101.3.4.4.1", QuantumLevel: 1},
	{ID: "ML-KEM-768", Primitive: cdx.CryptoPrimitiveKEM, OID: "2.16.840.1.101.3.4.4.2", QuantumLevel: 3},
	{ID: "ML-KEM-1024", Primitive: cdx.CryptoPrimitiveKEM, OID: "2.16.840.1.101.3.4.4.3", QuantumLevel: 5},

	// RFC 10024: TLS 1.3 hybrid post-quantum key exchange (a classical ECDH group
	// combined with ML-KEM). No OID of its own: IANA assigns these a TLS
	// supported-group code point, not a PKIX object identifier. Combiner is the
	// primitive CycloneDX defines for exactly this construction. Only the three
	// groups RFC 10024 itself defines are catalogued; other hybrid names the IANA
	// registry carries cite an internet-draft, not an RFC, and are named in a TLS
	// scan's output without a catalogue entry (see internal/cbom/tlsbuild.go).
	{ID: "X25519MLKEM768", Primitive: cdx.CryptoPrimitiveCombiner},
	{ID: "SecP256r1MLKEM768", Primitive: cdx.CryptoPrimitiveCombiner},
	{ID: "SecP384r1MLKEM1024", Primitive: cdx.CryptoPrimitiveCombiner},

	// FIPS 204: ML-DSA.
	{ID: "ML-DSA-44", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.17", QuantumLevel: 2},
	{ID: "ML-DSA-65", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.18", QuantumLevel: 3},
	{ID: "ML-DSA-87", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.19", QuantumLevel: 5},

	// FIPS 205: SLH-DSA.
	{ID: "SLH-DSA-SHA2-128s", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.20", QuantumLevel: 1},
	{ID: "SLH-DSA-SHA2-128f", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.21", QuantumLevel: 1},
	{ID: "SLH-DSA-SHA2-192s", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.22", QuantumLevel: 3},
	{ID: "SLH-DSA-SHA2-192f", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.23", QuantumLevel: 3},
	{ID: "SLH-DSA-SHA2-256s", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.24", QuantumLevel: 5},
	{ID: "SLH-DSA-SHA2-256f", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.25", QuantumLevel: 5},
	{ID: "SLH-DSA-SHAKE-128s", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.26", QuantumLevel: 1},
	{ID: "SLH-DSA-SHAKE-128f", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.27", QuantumLevel: 1},
	{ID: "SLH-DSA-SHAKE-192s", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.28", QuantumLevel: 3},
	{ID: "SLH-DSA-SHAKE-192f", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.29", QuantumLevel: 3},
	{ID: "SLH-DSA-SHAKE-256s", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.30", QuantumLevel: 5},
	{ID: "SLH-DSA-SHAKE-256f", Primitive: cdx.CryptoPrimitiveSignature, OID: "2.16.840.1.101.3.4.3.31", QuantumLevel: 5},
}
