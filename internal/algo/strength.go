package algo

import "math"

// Classical security strength, worked out the way NIST works it out (ENH-001). A security strength
// is "the amount of work needed to break a cryptographic algorithm" expressed in bits (SP 800-57
// Part 1 Rev. 5, section 5.6.1): about 2^s operations. These are estimates against classical
// computers only; a large quantum computer breaks the public-key ones outright (that is the
// post-quantum status, kept separately).
//
// Sources, each read and checked against this code's tests:
//
//   - IFC (RSA) and FFC (finite-field DH): the General Number Field Sieve estimate of the
//     FIPS 140-3 Implementation Guidance, section D.B (formerly FIPS 140-2 IG 7.5), as stated in
//     NIST SP 800-56B Rev. 2 Appendix D. Its Table 4 (2048: 110.1 → 112, 3072: 131.97 → 128, 4096:
//     149.73 → 152, 6144: 178.42 → 176, 8192: 201.7 → 200) and SP 800-56A Rev. 3 Table 26 (the
//     RFC 7919 ffdhe groups, "calculated using formula in Section 7.5 of the FIPS 140 IG and rounded
//     to the nearest multiple of eight bits") are reproduced by TestGNFSReproducesNISTTables.
//   - ECC: SP 800-186 section 3, "if an elliptic curve has a basepoint of order n, then the
//     security strength will be approximately one half of the bit length of n" (Pollard's rho),
//     with its Table 1 (P-224 112; P-256, Curve25519, Edwards25519 128; P-384 192; Curve448,
//     Edwards448 224; P-521 256) and the 256-bit ceiling of SP 800-57 Part 1 Table 2.
//   - Symmetric ciphers and hash functions: SP 800-57 Part 1 Rev. 5 Tables 2 and 3.

// GNFSEstimate is E(L), the work in bits of factoring an L-bit RSA modulus, or of computing a
// discrete logarithm in an L-bit prime field, with the General Number Field Sieve:
//
//	E(L) = ( 1.923 · ∛(L·ln 2) · ∛( (ln(L·ln 2))² ) − 4.69 ) / ln 2
//
// This is the heuristic GNFS running time exp((64/9)^⅓ · (ln N)^⅓ · (ln ln N)^⅔), with
// (64/9)^⅓ ≈ 1.923 and ln N = L·ln 2, converted to bits; the constant 4.69 calibrates it so that
// L = 1024 gives 80 bits, the strength SP 800-57 assigns to 1024-bit RSA.
func GNFSEstimate(bits int) float64 {
	if bits <= 0 {
		return 0
	}
	x := float64(bits) * math.Ln2 // ln N
	return (1.923*math.Cbrt(x)*math.Cbrt(math.Pow(math.Log(x), 2)) - 4.69) / math.Ln2
}

// RoundToEight is NIST's rounding of an estimate to a security strength: "the value of E will be
// rounded to the nearest integer multiple of eight" (SP 800-56B Rev. 2 Appendix D).
func RoundToEight(e float64) int {
	if e <= 0 {
		return 0
	}
	return int(math.Round(e/8)) * 8
}

// IFCStrength is the classical security strength of an RSA key with a modulus of bits bits, held
// to MaxStrength: the formula keeps climbing (15360 bits gives 262.6 → 264), but NIST assigns no
// strength above 256 (SP 800-57 Part 1 Table 2 lists k = 15360 at 256).
func IFCStrength(bits int) int { return min(RoundToEight(GNFSEstimate(bits)), MaxStrength) }

// FFCStrength is the classical security strength of finite-field Diffie-Hellman (or DSA) with a
// prime of bits bits. NIST uses the same GNFS estimate (SP 800-56A Rev. 3 Table 26). The private
// key must also be at least twice the strength; the named groups (RFC 7919, RFC 3526) meet that.
func FFCStrength(bits int) int { return min(RoundToEight(GNFSEstimate(bits)), MaxStrength) }

// MaxStrength is the largest security strength NIST assigns (SP 800-57 Part 1 Table 2).
const MaxStrength = 256

// ECCStrength is the classical security strength of elliptic-curve cryptography whose base point
// has an order of orderBits bits: half the bit length (SP 800-186 section 3), rounded to a multiple
// of eight like the other estimates, and at most 256 (SP 800-57 Part 1 Table 2, "f = 512+").
// Curve25519's order is 253 bits (126.5 → 128) and Curve448's 446 bits (223 → 224), as SP 800-186
// Table 1 lists them; P-521's 521 bits (260.5) is held to 256.
func ECCStrength(orderBits int) int {
	return min(RoundToEight(float64(orderBits)/2), MaxStrength)
}

// curveOrderBits are the bit lengths of the base-point orders of the curves this program names,
// from their defining documents (SP 800-186 for the NIST and Edwards curves, RFC 7748 for
// Curve25519 and Curve448: order 2^252 + … and 2^446 − …).
var curveOrderBits = map[string]int{
	"secp224r1": 224, "secp256r1": 256, "secp384r1": 384, "secp521r1": 521,
	"Curve25519": 253, "Ed25519": 253, "Curve448": 446, "Ed448": 446,
}

// CurveStrength is ECCStrength for a named curve; false when the curve is not one listed above.
func CurveStrength(curve string) (int, bool) {
	n, ok := curveOrderBits[curve]
	if !ok {
		return 0, false
	}
	return ECCStrength(n), true
}

// SymmetricStrength gives the classical strength of a symmetric cipher from SP 800-57 Part 1
// Table 2, or the key-search bound for one NIST no longer lists. Broken reports a cipher whose
// strength is below anything NIST approves (under 80 bits) or that has a cited practical break;
// it then has no strength to compare, only the reason.
//
//	AES-128/192/256: 128/192/256 (Table 2)
//	3TDEA: 112 (Table 2; deprecated through 2023, then disallowed, SP 800-131A Rev. 2)
//	2TDEA: 80 (Table 2)
//	DES: 56-bit key, exhaustive key search: broken
//	RC4: broken (RFC 7465), whatever its key length
//	ChaCha20: 256-bit key (RFC 8439); NIST does not list it, so this is the key length, stated as such
func SymmetricStrength(cipher string, keyBits int) (bits int, broken bool) {
	switch cipher {
	case "AES":
		return keyBits, false
	case "3DES":
		if keyBits <= 112 {
			return 80, false // 2TDEA (two keys)
		}
		return 112, false // 3TDEA: 168-bit key, 112-bit strength (meet in the middle)
	case "CHACHA20", "ChaCha20-Poly1305":
		return keyBits, false
	case "DES", "RC4", "RC2", "NULL":
		return min(keyBits, 56), true
	}
	return 0, false
}

// HashStrength gives the strength of a hash function where collision resistance is needed
// (digital signatures, certificate signatures): half the output length, and SHA-1 below 80 bits
// because of published collision attacks (SP 800-57 Part 1 Table 3, footnote 74). MD5 is broken
// (RFC 6151). HMACStrength is the strength in HMAC and key derivation, from the same table.
func HashStrength(hash string) (bits int, broken bool) {
	switch hash {
	case "SHA-224", "SHA-512/224", "SHA3-224":
		return 112, false
	case "SHA-256", "SHA-512/256", "SHA3-256":
		return 128, false
	case "SHA-384", "SHA3-384":
		return 192, false
	case "SHA-512", "SHA3-512":
		return 256, false
	case "SHA-1", "MD5":
		return 0, true
	}
	return 0, false
}

// HMACStrength is SP 800-57 Part 1 Table 3's strength for HMAC (and KDFs) with the hash, assuming
// a key at least that strong: SHA-1 128, SHA-224 192, SHA-256 and longer 256.
func HMACStrength(hash string) (int, bool) {
	switch hash {
	case "SHA-1":
		return 128, true
	case "SHA-224", "SHA-512/224", "SHA3-224":
		return 192, true
	case "SHA-256", "SHA-512/256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512":
		return 256, true
	}
	return 0, false
}
