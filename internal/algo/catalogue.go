package algo

import cdx "github.com/CycloneDX/cyclonedx-go"

// Provenance of every value below:
//
//   - OIDs for NIST-registered algorithms (AES arc, SHA-2, ML-KEM, ML-DSA,
//     SLH-DSA): NIST CSOR algorithm registration,
//     https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
//   - rsaEncryption 1.2.840.113549.1.1.1: RFC 8017 appendix A.1.
//   - id-dsa 1.2.840.10040.4.1, dhpublicnumber 1.2.840.10046.2.1: RFC 3279.
//   - id-ecDH 1.3.132.1.12: RFC 5480 section 2.1.2.
//   - X25519 1.3.101.110 and Ed25519 1.3.101.112: RFC 8410.
//   - QuantumLevel: FIPS 203 (ML-KEM 1/3/5), FIPS 204 (ML-DSA 2/3/5),
//     FIPS 205 (SLH-DSA 1/3/5), each from the standard's own parameter-set table.
//
// Deliberately absent, because no single authoritative OID exists: ECDSA has
// none of its own (only per-hash signature OIDs), generic AES has none (OIDs
// are per key size and mode). QuantumLevel is unset for every classical
// algorithm and for AES and SHA-2; the pqc package carries the reasoning for
// those instead.
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
	{ID: "SHA-256", Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.1"},
	{ID: "SHA-384", Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.2"},
	{ID: "SHA-512", Primitive: cdx.CryptoPrimitiveHash, OID: "2.16.840.1.101.3.4.2.3"},

	// FIPS 203: ML-KEM.
	{ID: "ML-KEM-512", Primitive: cdx.CryptoPrimitiveKEM, OID: "2.16.840.1.101.3.4.4.1", QuantumLevel: 1},
	{ID: "ML-KEM-768", Primitive: cdx.CryptoPrimitiveKEM, OID: "2.16.840.1.101.3.4.4.2", QuantumLevel: 3},
	{ID: "ML-KEM-1024", Primitive: cdx.CryptoPrimitiveKEM, OID: "2.16.840.1.101.3.4.4.3", QuantumLevel: 5},

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
