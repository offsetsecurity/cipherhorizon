package cbom

import (
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CycloneDX 1.7 output (PRD-003 REQ-EXP-1, REQ-EXP-2).
//
// One internal model is built (it is shaped like 1.6, which every consumer accepts) and converted at
// the last step. The conversion does exactly what 1.7 asks and nothing else:
//
//   - a construct 1.7 deprecates is replaced by its replacement, not emitted alongside it:
//     certificateProperties.signatureAlgorithmRef and subjectPublicKeyRef, and
//     relatedCryptoMaterialProperties.algorithmRef become relatedCryptographicAssets;
//     algorithmProperties.curve becomes ellipticCurve (a name from the specification's registry);
//   - algorithmFamily is set only where the registry has a family for the algorithm, from the
//     table below, and never guessed;
//   - where the registry has no name for something (a curve, a family), the older field is kept
//     and nothing is invented, and the gap is listed by Registry17Gaps.

// Spec names the CycloneDX versions this program writes.
const (
	Spec16 = "1.6"
	Spec17 = "1.7"
)

// DefaultSpec is what the programs write unless asked otherwise.
const DefaultSpec = Spec17

// registryFamily maps a catalogue algorithm to its algorithm family in the 1.7 cryptography
// registry (cryptography-defs.schema.json), or says why there is none. The registry names schemes
// and constructions, not every catalogue entry, so a gap is honest and is listed rather than filled.
// TestRegistryMappingIsCompleteAndValid keeps this table in step with the catalogue and the registry.
var registryFamily = map[string]struct{ Family, Why string }{
	"3DES": {"3DES", ""}, "DES": {"DES", ""}, "RC2": {"RC2", ""}, "RC4": {"RC4", ""},
	"AES": {"AES", ""}, "AES-128-CBC": {"AES", ""}, "AES-128-CCM": {"AES", ""}, "AES-128-GCM": {"AES", ""},
	"AES-256-CBC": {"AES", ""}, "AES-256-CCM": {"AES", ""}, "AES-256-GCM": {"AES", ""},
	"ChaCha20-Poly1305": {"", "an AEAD construction of two registry families (ChaCha20 and Poly1305)"},
	"DH":                {"FFDH", ""}, "DSA": {"DSA", ""}, "ECDH": {"ECDH", ""}, "ECDSA": {"ECDSA", ""},
	"Ed25519": {"EdDSA", ""}, "X25519": {"ECDH", ""}, "Ed448": {"EdDSA", ""}, "X448": {"ECDH", ""},
	"ECDH-P256": {"ECDH", ""}, "ECDH-P384": {"ECDH", ""}, "ECDH-P521": {"ECDH", ""},
	"MD2": {"MD2", ""}, "MD4": {"MD4", ""}, "MD5": {"MD5", ""},
	"SHA-1": {"SHA-1", ""}, "SHA-256": {"SHA-2", ""}, "SHA-384": {"SHA-2", ""}, "SHA-512": {"SHA-2", ""},
	"SHA3-256": {"SHA-3", ""}, "SHA3-384": {"SHA-3", ""}, "SHA3-512": {"SHA-3", ""},
	"ML-DSA": {"ML-DSA", ""}, "ML-DSA-44": {"ML-DSA", ""}, "ML-DSA-65": {"ML-DSA", ""}, "ML-DSA-87": {"ML-DSA", ""},
	"ML-KEM": {"ML-KEM", ""}, "ML-KEM-512": {"ML-KEM", ""}, "ML-KEM-768": {"ML-KEM", ""}, "ML-KEM-1024": {"ML-KEM", ""},
	"RSA":                {"", "the registry names RSA by scheme (RSAES-OAEP, RSAES-PKCS1, RSASSA-PKCS1, RSASSA-PSS); a bare RSA key has none"},
	"SecP256r1MLKEM768":  {"", "a TLS hybrid group of two families (ECDH and ML-KEM)"},
	"SecP384r1MLKEM1024": {"", "a TLS hybrid group of two families (ECDH and ML-KEM)"},
	"X25519MLKEM768":     {"", "a TLS hybrid group of two families (ECDH and ML-KEM)"},
	// SSH (PRD-008). CAST-128 is the registry's CAST5 (RFC 2144 names the cipher both ways).
	"AES-192-CBC": {"AES", ""}, "AES-128-CTR": {"AES", ""}, "AES-192-CTR": {"AES", ""}, "AES-256-CTR": {"AES", ""},
	"HMAC-SHA-1": {"HMAC", ""}, "HMAC-SHA-256": {"HMAC", ""}, "HMAC-SHA-512": {"HMAC", ""}, "HMAC-MD5": {"HMAC", ""},
	"UMAC": {"UMAC", ""}, "Blowfish": {"Blowfish", ""}, "CAST-128": {"CAST5", ""},
	"mlkem768x25519-sha256":    {"", "an SSH hybrid key exchange of two families (ECDH and ML-KEM)"},
	"mlkem768nistp256-sha256":  {"", "an SSH hybrid key exchange of two families (ECDH and ML-KEM)"},
	"mlkem1024nistp384-sha384": {"", "an SSH hybrid key exchange of two families (ECDH and ML-KEM)"},
	"sntrup761x25519-sha512":   {"", "an SSH hybrid key exchange; the registry has no NTRU Prime family"},
}

// slhDSA covers the twelve SLH-DSA parameter sets by prefix.
const slhDSAPrefix = "SLH-DSA-"

// registryCurve maps the curve names this program emits (SECG names, RFC 5480) and the curves
// implied by an algorithm to the registry's identifiers.
var registryCurve = map[string]string{
	"secp256r1": "secg/secp256r1", "secp384r1": "secg/secp384r1", "secp521r1": "secg/secp521r1",
}

// impliedCurve is the registry curve an algorithm implies by its definition.
var impliedCurve = map[string]string{"X25519": "other/Curve25519", "Ed25519": "other/Ed25519", "X448": "other/Curve448", "Ed448": "other/Ed448"}

// FamilyFor returns the registry family for a component name: a catalogue ID, or one of the
// size- or curve-qualified names this program derives (RSA-2048, ECDSA-P256, DSA-2048).
func FamilyFor(name string) (family string, ok bool) {
	if e, found := registryFamily[name]; found {
		return e.Family, e.Family != ""
	}
	if strings.HasPrefix(name, slhDSAPrefix) {
		return "SLH-DSA", true
	}
	// A certificate's signature algorithm, by its ASN.1 name (RFC 5758, RFC 8017).
	if f, found := signatureFamily[name]; found {
		return f, true
	}
	switch {
	case strings.HasPrefix(name, "ECDSA-"):
		return "ECDSA", true
	case strings.HasPrefix(name, "DSA-"):
		return "DSA", true
	}
	return "", false
}

// signatureFamily is the registry family of each certificate signature algorithm the
// certificate builder names (cbom.sigVariants).
var signatureFamily = map[string]string{
	"md5WithRSAEncryption": "RSASSA-PKCS1", "sha1WithRSAEncryption": "RSASSA-PKCS1", "sha256WithRSAEncryption": "RSASSA-PKCS1",
	"sha384WithRSAEncryption": "RSASSA-PKCS1", "sha512WithRSAEncryption": "RSASSA-PKCS1", "RSASSA-PSS": "RSASSA-PSS",
	"ecdsa-with-SHA1": "ECDSA", "ecdsa-with-SHA256": "ECDSA", "ecdsa-with-SHA384": "ECDSA", "ecdsa-with-SHA512": "ECDSA",
	"dsa-with-SHA1": "DSA",
}

// Registry17Gaps lists catalogue entries the registry has no family for, with the reason. It is
// what the export documentation prints, so a gap is a stated fact and not a silent omission.
func Registry17Gaps() map[string]string {
	out := map[string]string{}
	for id, e := range registryFamily {
		if e.Family == "" {
			out[id] = e.Why
		}
	}
	return out
}

// To17 converts a 1.6-shaped BOM to 1.7 and returns a converted copy. The input is not changed.
func To17(in *cdx.BOM) *cdx.BOM {
	out := *in
	if in.Components != nil {
		cs := make([]cdx.Component, len(*in.Components))
		for i, c := range *in.Components {
			cs[i] = convert17(c)
		}
		out.Components = &cs
	}
	return &out
}

func convert17(c cdx.Component) cdx.Component {
	if c.Components != nil {
		cs := make([]cdx.Component, len(*c.Components))
		for i, x := range *c.Components {
			cs[i] = convert17(x)
		}
		c.Components = &cs
	}
	if c.CryptoProperties == nil {
		return c
	}
	cp := *c.CryptoProperties
	c.CryptoProperties = &cp
	switch cp.AssetType {
	case cdx.CryptoAssetTypeAlgorithm:
		if cp.AlgorithmProperties != nil {
			ap := *cp.AlgorithmProperties
			cp.AlgorithmProperties = &ap
			if fam, ok := FamilyFor(c.Name); ok && ap.AlgorithmFamily == "" {
				ap.AlgorithmFamily = fam
			}
			curve := ap.Curve
			if reg, ok := registryCurve[curve]; ok {
				ap.EllipticCurve, ap.Curve = reg, ""
			} else if imp, ok := impliedCurve[c.Name]; ok && curve == "" {
				ap.EllipticCurve = imp
			}
		}
	case cdx.CryptoAssetTypeCertificate:
		if cp.CertificateProperties != nil {
			p := *cp.CertificateProperties
			cp.CertificateProperties = &p
			var rel []cdx.RelatedCryptographicAsset
			if p.SubjectPublicKeyRef != "" {
				rel = append(rel, cdx.RelatedCryptographicAsset{Type: "publicKey", Ref: string(p.SubjectPublicKeyRef)})
				p.SubjectPublicKeyRef = ""
			}
			if p.SignatureAlgorithmRef != "" {
				rel = append(rel, cdx.RelatedCryptographicAsset{Type: "algorithm", Ref: string(p.SignatureAlgorithmRef)})
				p.SignatureAlgorithmRef = ""
			}
			if len(rel) > 0 {
				p.RelatedCryptographicAssets = &rel
			}
			// 1.7 has fields for the serial number and the fingerprint (CBOM-REVIEW-002 C-5); 1.6
			// has neither, so the 1.6 model carries the serial as a property and the fingerprint in
			// the bom-ref. Both move into their fields here.
			c.Properties = takeSerial(c.Properties, &p)
			if fp := strings.TrimPrefix(c.BOMRef, certificateRefPrefix); fp != c.BOMRef && isSHA256Hex(fp) {
				p.Fingerprint = &cdx.Hash{Algorithm: cdx.HashAlgoSHA256, Value: fp}
			}
		}
	case cdx.CryptoAssetTypeRelatedCryptoMaterial:
		if cp.RelatedCryptoMaterialProperties != nil {
			p := *cp.RelatedCryptoMaterialProperties
			cp.RelatedCryptoMaterialProperties = &p
			if p.AlgorithmRef != "" {
				p.RelatedCryptographicAssets = &[]cdx.RelatedCryptographicAsset{{Type: "algorithm", Ref: string(p.AlgorithmRef)}}
				p.AlgorithmRef = ""
			}
		}
	}
	return c
}

// certificateRefPrefix starts every certificate's bom-ref; the SHA-256 of its DER follows.
const certificateRefPrefix = "crypto/certificate/"

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// takeSerial moves the cert-serial property into the 1.7 serialNumber field and returns the
// remaining properties (nil when none is left). The input slice is not changed.
func takeSerial(props *[]cdx.Property, p *cdx.CertificateProperties) *[]cdx.Property {
	if props == nil {
		return nil
	}
	var rest []cdx.Property
	for _, x := range *props {
		if x.Name == PropertyNamespace+":cert-serial" && p.SerialNumber == "" {
			p.SerialNumber = x.Value
			continue
		}
		rest = append(rest, x)
	}
	if len(rest) == 0 {
		return nil
	}
	return &rest
}

// schemaURL17 is the JSON Schema id CycloneDX 1.7 documents declare.
const schemaURL17 = "http://cyclonedx.org/schema/bom-1.7.schema.json"

// EncodeSpec writes bom as CycloneDX JSON of the named version ("1.6" or "1.7"). An unknown
// version is an error, never a silent default.
func EncodeSpec(w io.Writer, bom *cdx.BOM, spec string, pretty bool) error {
	switch spec {
	case Spec16:
		return Encode(w, bom, pretty)
	case Spec17:
		out := To17(bom)
		out.SpecVersion = cdx.SpecVersion1_7
		out.JSONSchema = schemaURL17
		return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(pretty).SetEscapeHTML(false).Encode(out)
	}
	return &UnknownSpecError{Spec: spec}
}

// UnknownSpecError is returned for a version this program does not write.
type UnknownSpecError struct{ Spec string }

func (e *UnknownSpecError) Error() string {
	return "unknown CycloneDX version " + quote(e.Spec) + ": use 1.6 or 1.7"
}

func quote(s string) string {
	if len(s) > 20 {
		s = s[:20]
	}
	return "\"" + strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s) + "\""
}
