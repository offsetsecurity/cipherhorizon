package cbom

import (
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/collector"
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

	certRef := "crypto/certificate/" + strings.ToLower(f.SHA256)
	var deps []string
	// A post-quantum signature (Go's x509 does not recognise it) is already an
	// exact catalogue name by the time it reaches here: see certinfo.
	sigID, sigNamed := sigAlgFamily[f.SigName]
	if !sigNamed {
		sigID = f.SigName
	}
	if ref, ok := emit(sigID); ok {
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
	return emit(ki.Algorithm)
}
