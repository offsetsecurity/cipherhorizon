package cbom

import (
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/collector"
)

// CertFacts is what a certificate says about itself, in the form CBOM assets are built
// from. The TLS scanner (a certificate a server presented) and the host inventory (a
// certificate a machine holds) both fill it, so the same certificate becomes the same
// components either way.
type CertFacts struct {
	Subject      string
	Issuer       string
	SerialHex    string
	SHA256       string // lower-case hex over the DER encoding
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgorithm string // as certinfo names it: RSA, ECDSA, Ed25519, ... or "unknown"
	KeyBits      int
	Curve        string
	SigName      string // as Go's x509 (or certinfo, for algorithms Go does not know) names the signature algorithm
	SigOID       string // the certificate's signatureAlgorithm OID, as read from it
	KeyOID       string // the SubjectPublicKeyInfo algorithm OID, as read from it

	// Extensions are the certificate extensions CycloneDX 1.7 names (certificateExtensions,
	// commonExtensionName). They are written only to 1.7 documents; 1.6 has no such field.
	Extensions []CertExtension
}

// CertExtension is one certificate extension by its CycloneDX 1.7 common name.
type CertExtension struct {
	Name  string // basicConstraints, keyUsage, extendedKeyUsage, certificatePolicies, ...
	Value string
	// Custom marks an extension 1.7 has no common name for: it is written as a customExtension,
	// named by Name (which carries the OID), the schema's own place for such extensions.
	Custom bool
}

// commonExtensions are the names the 1.7 schema allows for commonExtensionName.
var commonExtensions = map[string]bool{
	"basicConstraints": true, "keyUsage": true, "extendedKeyUsage": true, "subjectAlternativeName": true,
	"authorityKeyIdentifier": true, "subjectKeyIdentifier": true, "authorityInformationAccess": true,
	"certificatePolicies": true, "crlDistributionPoints": true, "signedCertificateTimestamp": true,
}

// CertificateAsset builds the certificate component and, when the key algorithm can be
// named, the component for the public key it certifies (with its size), in the shape the
// standard intends: the certificate's subjectPublicKeyRef references the key, and the key's
// algorithmRef references its algorithm. emit resolves a catalogue algorithm and emitAsset
// adds one this document derived itself (a key-size variant such as RSA-2048); both are the
// caller's, so every algorithm is emitted once per document. The caller sets Evidence and
// any properties; nothing here says how or where the certificate was found.
func CertificateAsset(f CertFacts, emit func(id string) (string, bool), emitAsset func(collector.CryptoAsset) string) (collector.CryptoAsset, *collector.CryptoAsset) {
	name := f.Subject
	if name == "" {
		name = f.SHA256[:16]
	}
	props := &cdx.CertificateProperties{SubjectName: f.Subject, IssuerName: f.Issuer, CertificateFormat: "X.509"}
	if !f.NotBefore.IsZero() {
		props.NotValidBefore = f.NotBefore.UTC().Format(time.RFC3339)
	}
	if !f.NotAfter.IsZero() {
		props.NotValidAfter = f.NotAfter.UTC().Format(time.RFC3339)
	}
	var exts []cdx.CertificateExtension
	for _, e := range f.Extensions {
		switch {
		case e.Custom && e.Name != "":
			exts = append(exts, cdx.CertificateExtension{Custom: &cdx.CustomCertificateExtension{Name: e.Name, Value: e.Value}})
		case commonExtensions[e.Name] && e.Value != "":
			exts = append(exts, cdx.CertificateExtension{Common: &cdx.CommonCertificateExtension{Name: cdx.CertificateExtensionName(e.Name), Value: e.Value}})
		}
	}
	if len(exts) > 0 {
		props.CertificateExtensions = &exts
	}

	certRef := "crypto/certificate/" + strings.ToLower(f.SHA256)
	var deps []string
	// A post-quantum signature (Go's x509 does not recognise it) is already an
	// exact catalogue name by the time it reaches here: see certinfo.
	if ref, ok := signatureAlgorithm(f.SigName, f.SigOID, emit, emitAsset); ok {
		props.SignatureAlgorithmRef = cdx.BOMReference(ref)
		deps = append(deps, ref)
	}

	// The certificate certifies a public key; that key is its own asset, of a
	// stated algorithm and size, and the certificate points at it. (CycloneDX's
	// subjectPublicKeyRef is "the bom-ref to the public key of the subject", so it
	// must reference the key, not the algorithm the key happens to use.)
	var key *collector.CryptoAsset
	if algRef, ok := keyAlgorithm(f, emit, emitAsset); ok {
		keyRef := "crypto/key/public/" + strings.ToLower(f.SHA256)
		rp := &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePublicKey, AlgorithmRef: cdx.BOMReference(algRef)}
		if f.KeyBits > 0 {
			bits := f.KeyBits
			rp.Size = &bits
		}
		key = &collector.CryptoAsset{
			Component: cdx.Component{
				BOMRef: keyRef, Type: cdx.ComponentTypeCryptographicAsset, Name: name + " public key",
				CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial, RelatedCryptoMaterialProperties: rp},
			},
			DependsOn: []string{algRef},
		}
		props.SubjectPublicKeyRef = cdx.BOMReference(keyRef)
		deps = append(deps, keyRef)
	}

	c := cdx.Component{
		BOMRef: certRef, Type: cdx.ComponentTypeCryptographicAsset, Name: name,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate, CertificateProperties: props},
	}
	return collector.CryptoAsset{Component: c, DependsOn: deps}, key
}

// sigAlgFamily maps the fixed set of strings Go's x509.SignatureAlgorithm.String()
// can return to the catalogue entry for that signing algorithm family. It is a
// closed lookup table against a closed standard-library enum, not a guess: a
// post-quantum signature (which Go's x509 does not recognise, so this table
// never sees it) is separately identified in describeSignature by exact OID
// match against the same catalogue, and so needs no entry here.
var sigAlgFamily = map[string]string{
	"MD5-RSA": "RSA", "SHA1-RSA": "RSA", "SHA256-RSA": "RSA", "SHA384-RSA": "RSA", "SHA512-RSA": "RSA",
	"SHA256-RSAPSS": "RSA", "SHA384-RSAPSS": "RSA", "SHA512-RSAPSS": "RSA",
	"DSA-SHA1": "DSA", "DSA-SHA256": "DSA",
	"ECDSA-SHA1": "ECDSA", "ECDSA-SHA256": "ECDSA", "ECDSA-SHA384": "ECDSA", "ECDSA-SHA512": "ECDSA",
	"Ed25519": "Ed25519",
}

// sigVariants names the exact signature algorithm of a certificate, with its OID, for each
// value of Go's x509.SignatureAlgorithm.String() that has one (CBOM-REVIEW-002 C-3). The names
// and OIDs are the ASN.1 ones of their RFCs: RFC 8017 appendix A.2.4 (PKCS #1 v1.5 and
// id-RSASSA-PSS, whose hash is a parameter, so the three PSS variants share it), RFC 5758
// section 3.2 (ecdsa-with-SHA2) and RFC 3279 section 2.2 (ecdsa-with-SHA1, id-dsa-with-sha1).
// DSA with SHA-256 (2.16.840.1.101.3.4.3.2) is left at its family: no rule cites that arc.
var sigVariants = map[string]struct{ name, oid string }{
	"MD5-RSA":       {"md5WithRSAEncryption", "1.2.840.113549.1.1.4"},
	"SHA1-RSA":      {"sha1WithRSAEncryption", "1.2.840.113549.1.1.5"},
	"SHA256-RSA":    {"sha256WithRSAEncryption", "1.2.840.113549.1.1.11"},
	"SHA384-RSA":    {"sha384WithRSAEncryption", "1.2.840.113549.1.1.12"},
	"SHA512-RSA":    {"sha512WithRSAEncryption", "1.2.840.113549.1.1.13"},
	"SHA256-RSAPSS": {"RSASSA-PSS", "1.2.840.113549.1.1.10"},
	"SHA384-RSAPSS": {"RSASSA-PSS", "1.2.840.113549.1.1.10"},
	"SHA512-RSAPSS": {"RSASSA-PSS", "1.2.840.113549.1.1.10"},
	"DSA-SHA1":      {"dsa-with-SHA1", "1.2.840.10040.4.3"},
	"ECDSA-SHA1":    {"ecdsa-with-SHA1", "1.2.840.10045.4.1"},
	"ECDSA-SHA256":  {"ecdsa-with-SHA256", "1.2.840.10045.4.3.2"},
	"ECDSA-SHA384":  {"ecdsa-with-SHA384", "1.2.840.10045.4.3.3"},
	"ECDSA-SHA512":  {"ecdsa-with-SHA512", "1.2.840.10045.4.3.4"},
}

// signatureAlgorithm resolves a certificate's signature algorithm to the most precise asset
// there is: its exact variant with OID, else its catalogue family, else the catalogue entry of
// that name (a post-quantum signature is already an exact catalogue name, see certinfo).
func signatureAlgorithm(goName, oid string, emit func(id string) (string, bool), emitAsset func(collector.CryptoAsset) string) (string, bool) {
	if v, ok := sigVariants[goName]; ok {
		return emitAsset(collector.CryptoAsset{Component: cdx.Component{
			BOMRef: "crypto/algorithm/" + strings.ToLower(v.name) + "@" + v.oid, Type: cdx.ComponentTypeCryptographicAsset, Name: v.name,
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveSignature}, OID: v.oid},
		}}), true
	}
	id, named := sigAlgFamily[goName]
	if !named {
		id = goName
	}
	if ref, ok := emit(id); ok {
		return ref, true
	}
	// No catalogue entry and no variant: keep the identifier the certificate states rather than
	// drop it (AUDIT-TLS-CBOM-001 A-1). No family is guessed.
	return unrecognised(oid, cdx.CryptoPrimitiveSignature, "signature algorithm", emitAsset)
}

// UnrecognisedStatus is the cipherhorizon:identifier-status of an algorithm this program could not
// name: it is in the document by the identifier it was read with, and nothing more is claimed.
const UnrecognisedStatus = "unrecognised"

// unrecognised emits an algorithm known only by the OID it was read with: named by the OID, with
// that OID, the primitive its position proves (a certificate's signature field holds a signature
// algorithm), no family, no verdict, and a property saying so. false when there is no OID either.
func unrecognised(oid string, prim cdx.CryptoPrimitive, what string, emitAsset func(collector.CryptoAsset) string) (string, bool) {
	if !validOID(oid) {
		return "", false
	}
	props := []cdx.Property{
		Property("identifier-status", UnrecognisedStatus),
		Property("pqc:unclassified-reason", "This "+what+" is not in the catalogue: it is listed by the OID read from the certificate, and no family or post-quantum verdict is guessed."),
	}
	return emitAsset(collector.CryptoAsset{Component: cdx.Component{
		BOMRef: "crypto/algorithm/oid-" + oid + "@" + oid, Type: cdx.ComponentTypeCryptographicAsset, Name: oid,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: prim}, OID: oid},
		Properties: &props,
	}}), true
}

// validOID reports whether s is a dotted OID (two or more arcs of digits), so nothing else read
// from a certificate can become a bom-ref or a name.
func validOID(s string) bool {
	if len(s) < 3 || len(s) > 128 || strings.Count(s, ".") < 1 {
		return false
	}
	prevDot := true
	for _, r := range s {
		switch {
		case r == '.':
			if prevDot {
				return false
			}
			prevDot = true
		case r >= '0' && r <= '9':
			prevDot = false
		default:
			return false
		}
	}
	return !prevDot
}

// eccCurves maps Go's elliptic curve names to the SECG names RFC 5480 section
// 2.1.1.1 gives them in PKIX, with the short form used in the variant's name.
var eccCurves = map[string]struct{ short, secg string }{
	"P-256": {"P256", "secp256r1"},
	"P-384": {"P384", "secp384r1"},
	"P-521": {"P521", "secp521r1"},
}

// idECPublicKey is the SubjectPublicKeyInfo algorithm OID of every elliptic-curve
// key (RFC 5480 section 2.1.1). It names the key type, not ECDSA the signature.
const idECPublicKey = "1.2.840.10045.2.1"

// keyAlgorithm names the algorithm of a certificate's public key at the
// precision the certificate itself states: RSA-2048, ECDSA-P256. "RSA" alone
// says nothing about how exposed a key is; the size and curve are the fact a
// migration plan needs. A key type with no size to state (Ed25519, a
// post-quantum key) is named by its catalogue entry; one the program cannot name
// at all yields false.
func keyAlgorithm(f CertFacts, emit func(id string) (string, bool), emitAsset func(collector.CryptoAsset) string) (ref string, ok bool) {
	ki := struct {
		Algorithm string
		Bits      int
		Curve     string
	}{f.KeyAlgorithm, f.KeyBits, f.Curve}
	derive := func(name, oid string, prim cdx.CryptoPrimitive, props func(*cdx.CryptoAlgorithmProperties)) string {
		ap := &cdx.CryptoAlgorithmProperties{Primitive: prim}
		props(ap)
		return emitAsset(collector.CryptoAsset{Component: cdx.Component{
			BOMRef: "crypto/algorithm/" + strings.ToLower(name) + "@" + oid, Type: cdx.ComponentTypeCryptographicAsset, Name: name,
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: ap, OID: oid},
		}})
	}
	switch {
	case ki.Algorithm == "RSA" && ki.Bits > 0:
		return derive(fmt.Sprintf("RSA-%d", ki.Bits), algo.MustGet("RSA").OID, cdx.CryptoPrimitivePKE,
			func(ap *cdx.CryptoAlgorithmProperties) { ap.ParameterSetIdentifier = fmt.Sprint(ki.Bits) }), true
	case ki.Algorithm == "DSA" && ki.Bits > 0:
		return derive(fmt.Sprintf("DSA-%d", ki.Bits), algo.MustGet("DSA").OID, cdx.CryptoPrimitiveSignature,
			func(ap *cdx.CryptoAlgorithmProperties) { ap.ParameterSetIdentifier = fmt.Sprint(ki.Bits) }), true
	case ki.Algorithm == "ECDSA":
		if c, known := eccCurves[ki.Curve]; known {
			return derive("ECDSA-"+c.short, idECPublicKey, cdx.CryptoPrimitiveSignature,
				func(ap *cdx.CryptoAlgorithmProperties) { ap.Curve = c.secg }), true
		}
	}
	if ref, ok := emit(ki.Algorithm); ok {
		return ref, true
	}
	// A key type with no catalogue entry keeps its SubjectPublicKeyInfo OID (AUDIT-TLS-CBOM-001 A-2).
	return unrecognised(f.KeyOID, cdx.CryptoPrimitiveUnknown, "public-key algorithm", emitAsset)
}

// PublicKeyAsset is a public key seen on its own, such as an SSH host key: the same
// related-crypto-material component a certificate's key gets, at the same precision (RSA-2048,
// ECDSA-P256), under the caller's bom-ref. false when the key's algorithm cannot be named.
func PublicKeyAsset(ref, name, algorithm string, bits int, curve string, emit func(id string) (string, bool), emitAsset func(collector.CryptoAsset) string) (collector.CryptoAsset, bool) {
	algRef, ok := keyAlgorithm(CertFacts{KeyAlgorithm: algorithm, KeyBits: bits, Curve: curve}, emit, emitAsset)
	if !ok {
		return collector.CryptoAsset{}, false
	}
	rp := &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePublicKey, AlgorithmRef: cdx.BOMReference(algRef)}
	if bits > 0 {
		b := bits
		rp.Size = &b
	}
	return collector.CryptoAsset{
		Component: cdx.Component{
			BOMRef: ref, Type: cdx.ComponentTypeCryptographicAsset, Name: name,
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial, RelatedCryptoMaterialProperties: rp},
		},
		DependsOn: []string{algRef},
	}, true
}
