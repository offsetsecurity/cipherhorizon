package algo

import (
	"fmt"
	"strconv"
	"strings"
)

// Strength is the classical security strength of one algorithm as this program states it
// (PRD-010 REQ-STR-1): a number of bits with the source it comes from, or a reason there is none.
type Strength struct {
	// Bits is the security strength, 0 when Status is not rated or broken.
	Bits int `json:"bits,omitempty"`
	// Status is rated, disallowed (rated, but NIST no longer allows it for protection), broken (a
	// cited practical break, or below anything NIST rates) or not-rated (no source gives a strength
	// for it, or it depends on a size or parameter not known here).
	Status string `json:"status"`
	// Basis is the source, or the reason for the status.
	Basis string `json:"basis"`
}

// The statuses of a Strength.
const (
	StrengthRated      = "rated"
	StrengthDisallowed = "disallowed"
	StrengthBroken     = "broken"
	StrengthNotRated   = "not-rated"
)

// Words is the strength for people: "128 bits", "112 bits, disallowed", "broken", "not rated".
func (s Strength) Words() string {
	switch s.Status {
	case StrengthRated:
		return fmt.Sprintf("%d bits", s.Bits)
	case StrengthDisallowed:
		return fmt.Sprintf("%d bits, disallowed", s.Bits)
	case StrengthBroken:
		return "broken"
	}
	return "not rated"
}

// Known reports whether the strength is a number (rated or disallowed).
func (s Strength) Known() bool { return s.Status == StrengthRated || s.Status == StrengthDisallowed }

const (
	basisTable2    = "NIST SP 800-57 Part 1 Rev. 5, Table 2"
	basisTable3    = "NIST SP 800-57 Part 1 Rev. 5, Table 3"
	basisGNFS      = "GNFS estimate, FIPS 140-3 IG D.B (SP 800-56B Rev. 2 Appendix D), rounded to a multiple of eight"
	basisSP800186  = "NIST SP 800-186, Table 1 (half the base-point order)"
	basisKeySearch = "exhaustive search of the key; NIST assigns this cipher no strength"
	basisFIPS203   = "FIPS 203: the NIST category's classical equivalent (category 1, 3, 5: AES-128, -192, -256 key search)"
	basisFIPS204   = "FIPS 204: the NIST category's classical equivalent (category 2: SHA-256 collisions; 3, 5: AES-192, -256)"
	basisFIPS205   = "FIPS 205: the NIST category's classical equivalent"
	basisHybrid    = "a hybrid is secure while either part is (RFC 10024, RFC 10042): its stronger part"
)

func rated(bits int, basis string) Strength {
	return Strength{Bits: bits, Status: StrengthRated, Basis: basis}
}
func broken(basis string) Strength   { return Strength{Status: StrengthBroken, Basis: basis} }
func notRated(basis string) Strength { return Strength{Status: StrengthNotRated, Basis: basis} }

// StrengthOf is the classical strength of an algorithm by the name this program gives it: a
// catalogue ID, a size or curve variant it derives (RSA-2048, ECDSA-P256, DSA-2048), or a
// certificate signature variant (ecdsa-with-SHA256). It never guesses: a name it does not know is
// not rated.
func StrengthOf(name string) Strength {
	if s, ok := fixedStrength[name]; ok {
		return s
	}
	switch {
	case strings.HasPrefix(name, "RSA-"):
		if n, err := strconv.Atoi(strings.TrimPrefix(name, "RSA-")); err == nil {
			return KeyStrength("RSA", n, "")
		}
	case strings.HasPrefix(name, "DSA-"):
		if n, err := strconv.Atoi(strings.TrimPrefix(name, "DSA-")); err == nil {
			return KeyStrength("DSA", n, "")
		}
	case strings.HasPrefix(name, "ECDSA-P"):
		return KeyStrength("ECDSA", 0, "P-"+strings.TrimPrefix(name, "ECDSA-P"))
	case strings.HasPrefix(name, "oid-") || strings.Count(name, ".") > 2:
		return notRated("an algorithm this program does not recognise")
	}
	return notRated("no strength is recorded for this algorithm")
}

// goCurves maps Go's curve names to the SECG names curveOrderBits uses.
var goCurves = map[string]string{"P-224": "secp224r1", "P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1"}

// KeyStrength is the classical strength of a public key: RSA by its modulus (GNFS), DSA and DH by
// their prime (GNFS), EC by its curve (SP 800-186), Ed25519 and Ed448 by theirs, ML-DSA by its
// parameter set. A key of unknown size is not rated.
func KeyStrength(algorithm string, bits int, curve string) Strength {
	switch strings.ToUpper(algorithm) {
	case "RSA":
		if bits > 0 {
			return ifc(bits)
		}
	case "DSA", "DH":
		if bits > 0 {
			return ifc(bits)
		}
	case "ECDSA", "EC", "ECDH":
		c := curve
		if g, ok := goCurves[curve]; ok {
			c = g
		}
		if s, ok := CurveStrength(c); ok {
			return rated(s, basisSP800186)
		}
	case "ED25519":
		return rated(128, basisSP800186)
	case "ED448":
		return rated(224, basisSP800186)
	default:
		if s, ok := fixedStrength[algorithm]; ok { // ML-DSA-65 and the other catalogue names
			return s
		}
	}
	return notRated("the key size or curve is not known")
}

// ifc rates an RSA modulus or a finite-field prime with the GNFS estimate. Below 80 bits (a key
// shorter than 1024 bits) nothing NIST rates is left: it is broken.
func ifc(bits int) Strength {
	s := IFCStrength(bits)
	if s < 80 {
		return Strength{Status: StrengthBroken, Basis: fmt.Sprintf("%d-bit modulus: %s gives %d bits, below the 80 NIST rates at all", bits, "the GNFS estimate", s)}
	}
	return rated(s, basisGNFS)
}

// GroupStrength is the classical strength of a TLS supported group (IANA name) or an SSH key
// exchange method's group: named curves by SP 800-186, RFC 7919 and RFC 3526 finite-field groups by
// the GNFS estimate of their prime, ML-KEM and the hybrids as in StrengthOf.
func GroupStrength(name string) Strength {
	switch {
	case strings.EqualFold(name, "x25519"):
		return rated(128, basisSP800186)
	case strings.EqualFold(name, "x448"):
		return rated(224, basisSP800186)
	case strings.HasPrefix(name, "ffdhe"):
		if n, err := strconv.Atoi(strings.TrimPrefix(name, "ffdhe")); err == nil {
			return ifc(n)
		}
	case strings.HasPrefix(name, "MLKEM"):
		return StrengthOf("ML-KEM-" + strings.TrimPrefix(name, "MLKEM"))
	}
	if s, ok := CurveStrength(name); ok {
		return rated(s, basisSP800186)
	}
	return StrengthOf(name)
}

// fixedStrength is every catalogue entry, and every derived name, whose strength does not depend
// on a size this program reads separately. TestEveryAlgorithmHasACitedStrength holds the catalogue
// to it: every entry is here or is a family whose size is read elsewhere.
var fixedStrength = map[string]Strength{
	// Families: their strength is their size's, read from the key or the suite.
	"RSA":    notRated("depends on the modulus size (see the key)"),
	"DSA":    notRated("depends on the prime size (see the key)"),
	"DH":     notRated("depends on the prime size (see the group or the DH parameters)"),
	"ECDSA":  notRated("depends on the curve (see the key)"),
	"ECDH":   notRated("depends on the curve (see the group)"),
	"AES":    notRated("depends on the key size"),
	"ML-KEM": notRated("depends on the parameter set"),
	"ML-DSA": notRated("depends on the parameter set"),

	"Ed25519":   rated(128, basisSP800186),
	"X25519":    rated(128, basisSP800186),
	"Ed448":     rated(224, basisSP800186),
	"X448":      rated(224, basisSP800186),
	"ECDH-P256": rated(128, basisSP800186),
	"ECDH-P384": rated(192, basisSP800186),
	"ECDH-P521": rated(256, basisSP800186),

	"AES-128-CBC": rated(128, basisTable2), "AES-128-GCM": rated(128, basisTable2), "AES-128-CCM": rated(128, basisTable2),
	"AES-128-CTR": rated(128, basisTable2),
	"AES-192-CBC": rated(192, basisTable2), "AES-192-CTR": rated(192, basisTable2),
	"AES-256-CBC": rated(256, basisTable2), "AES-256-GCM": rated(256, basisTable2), "AES-256-CCM": rated(256, basisTable2),
	"AES-256-CTR":       rated(256, basisTable2),
	"ChaCha20-Poly1305": rated(256, "256-bit key (RFC 8439); "+basisKeySearch),
	"3DES":              {Bits: 112, Status: StrengthDisallowed, Basis: basisTable2 + " (3TDEA, 112 bits); disallowed for encryption after 2023, NIST SP 800-131A Rev. 2"},
	"DES":               broken("56-bit key: exhaustive search is practical; FIPS 46-3 withdrawn"),
	"RC4":               broken("RFC 7465 prohibits RC4 in TLS; practical biases recover plaintext"),
	"RC2":               broken("40- to 128-bit key with published related-key and key-search breaks; never rated by NIST"),
	"Blowfish":          notRated("64-bit block; NIST assigns Blowfish no strength"),
	"CAST-128":          notRated("64-bit block; NIST assigns CAST-128 no strength"),

	// Hash functions where collision resistance is needed (signatures).
	"SHA-256": rated(128, basisTable3), "SHA-384": rated(192, basisTable3), "SHA-512": rated(256, basisTable3),
	"SHA3-256": rated(128, basisTable3), "SHA3-384": rated(192, basisTable3), "SHA3-512": rated(256, basisTable3),
	"SHA-1": broken(basisTable3 + ": below 80 bits for collision resistance (footnote 74); RFC 6194"),
	"MD5":   broken("collisions are practical (RFC 6151)"),
	"MD4":   broken("moved to Historic for practical attacks (RFC 6150)"),
	"MD2":   broken("moved to Historic as broken (RFC 6149)"),

	// MACs: SP 800-57 Table 3 gives HMAC the strength of its hash's HMAC row.
	"HMAC-SHA-1": rated(128, basisTable3), "HMAC-SHA-256": rated(256, basisTable3), "HMAC-SHA-384": rated(256, basisTable3),
	"HMAC-SHA-512": rated(256, basisTable3),
	"HMAC-MD5":     notRated("MD5 is not an approved hash, so SP 800-57 gives HMAC-MD5 no strength (RFC 6151: not for new designs)"),
	"UMAC":         notRated("depends on the tag length (UMAC-64, UMAC-128); NIST assigns UMAC no strength"),

	// Post-quantum algorithms: the classical strength of their NIST category.
	"ML-KEM-512": rated(128, basisFIPS203), "ML-KEM-768": rated(192, basisFIPS203), "ML-KEM-1024": rated(256, basisFIPS203),
	"ML-DSA-44": rated(128, basisFIPS204), "ML-DSA-65": rated(192, basisFIPS204), "ML-DSA-87": rated(256, basisFIPS204),
	"SLH-DSA-SHA2-128s": rated(128, basisFIPS205), "SLH-DSA-SHA2-128f": rated(128, basisFIPS205),
	"SLH-DSA-SHA2-192s": rated(192, basisFIPS205), "SLH-DSA-SHA2-192f": rated(192, basisFIPS205),
	"SLH-DSA-SHA2-256s": rated(256, basisFIPS205), "SLH-DSA-SHA2-256f": rated(256, basisFIPS205),
	"SLH-DSA-SHAKE-128s": rated(128, basisFIPS205), "SLH-DSA-SHAKE-128f": rated(128, basisFIPS205),
	"SLH-DSA-SHAKE-192s": rated(192, basisFIPS205), "SLH-DSA-SHAKE-192f": rated(192, basisFIPS205),
	"SLH-DSA-SHAKE-256s": rated(256, basisFIPS205), "SLH-DSA-SHAKE-256f": rated(256, basisFIPS205),

	// Hybrids: the stronger part.
	"X25519MLKEM768":           rated(192, basisHybrid+" (ML-KEM-768, 192)"),
	"SecP256r1MLKEM768":        rated(192, basisHybrid+" (ML-KEM-768, 192)"),
	"SecP384r1MLKEM1024":       rated(256, basisHybrid+" (ML-KEM-1024, 256)"),
	"mlkem768x25519-sha256":    rated(192, basisHybrid+" (ML-KEM-768, 192)"),
	"mlkem768nistp256-sha256":  rated(192, basisHybrid+" (ML-KEM-768, 192)"),
	"mlkem1024nistp384-sha384": rated(256, basisHybrid+" (ML-KEM-1024, 256)"),
	"sntrup761x25519-sha512":   rated(128, "at least its X25519 part (128, SP 800-186); NIST rates Streamlined NTRU Prime at nothing"),

	// Certificate signature algorithms: the hash's collision strength (the key is rated on its own).
	"sha256WithRSAEncryption": rated(128, basisTable3+" (SHA-256; the key is rated separately)"),
	"sha384WithRSAEncryption": rated(192, basisTable3+" (SHA-384; the key is rated separately)"),
	"sha512WithRSAEncryption": rated(256, basisTable3+" (SHA-512; the key is rated separately)"),
	"ecdsa-with-SHA256":       rated(128, basisTable3+" (SHA-256; the key is rated separately)"),
	"ecdsa-with-SHA384":       rated(192, basisTable3+" (SHA-384; the key is rated separately)"),
	"ecdsa-with-SHA512":       rated(256, basisTable3+" (SHA-512; the key is rated separately)"),
	"RSASSA-PSS":              notRated("its hash is a parameter: see the certificate's signature parameters"),
	"sha1WithRSAEncryption":   broken("SHA-1 signatures: " + basisTable3 + ", footnote 74; RFC 6194"),
	"ecdsa-with-SHA1":         broken("SHA-1 signatures: " + basisTable3 + ", footnote 74; RFC 6194"),
	"dsa-with-SHA1":           broken("SHA-1 signatures: " + basisTable3 + ", footnote 74; RFC 6194"),
	"md5WithRSAEncryption":    broken("MD5 signatures: collisions are practical (RFC 6151)"),
}
