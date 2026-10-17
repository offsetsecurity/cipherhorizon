package certinfo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
)

// The facts a certificate states that AUDIT-TLS-CBOM-001 found the CBOM was losing: the
// RSASSA-PSS parameters (A-3), the key identifiers (A-7) and the list of every extension by OID
// (A-8). Parsing is bounded by what encoding/asn1 accepts from c.Raw, which crypto/x509 has
// already parsed once; nothing here is inferred.

var (
	oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// hashNames are the hash OIDs RFC 8017 appendix A.2.1 allows in RSASSA-PSS (FIPS 180-4 / NIST CSOR).
var hashNames = map[string]string{
	"1.3.14.3.2.26":          "SHA-1",
	"2.16.840.1.101.3.4.2.4": "SHA-224",
	"2.16.840.1.101.3.4.2.1": "SHA-256",
	"2.16.840.1.101.3.4.2.2": "SHA-384",
	"2.16.840.1.101.3.4.2.3": "SHA-512",
	"2.16.840.1.101.3.4.2.5": "SHA-512/224",
	"2.16.840.1.101.3.4.2.6": "SHA-512/256",
}

func hashWords(oid string) string {
	if n, ok := hashNames[oid]; ok {
		return n + " (" + oid + ")"
	}
	return oid
}

// pssParams is RSASSA-PSS-params (RFC 8017 appendix A.2.3).
type pssParams struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// describePSS states a certificate's RSASSA-PSS parameters as RFC 8017 defines them, marking each
// value the certificate left to its default. "" when the signature is not RSASSA-PSS; a parameter
// block that does not decode is reported as such, never guessed.
func describePSS(c *x509.Certificate) string {
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.Raw, &outer); err != nil || !outer.Alg.Algorithm.Equal(oidRSASSAPSS) {
		return ""
	}
	return pssWords(outer.Alg.Parameters.FullBytes)
}

// pssWords reads an RSASSA-PSS-params encoding. Exported to tests through describePSS's callers.
func pssWords(der []byte) string {
	var p pssParams
	if len(der) > 0 {
		if rest, err := asn1.Unmarshal(der, &p); err != nil || len(rest) > 0 {
			return "parameters do not decode"
		}
	}
	hash, hashDefault := "SHA-1 (1.3.14.3.2.26)", true
	if len(p.Hash.Algorithm) > 0 {
		hash, hashDefault = hashWords(p.Hash.Algorithm.String()), false
	}
	mgf, mgfDefault := "MGF1 with SHA-1", true
	if len(p.MGF.Algorithm) > 0 {
		mgfDefault = false
		if p.MGF.Algorithm.Equal(oidMGF1) {
			var inner pkix.AlgorithmIdentifier
			if _, err := asn1.Unmarshal(p.MGF.Parameters.FullBytes, &inner); err == nil {
				mgf = "MGF1 with " + strings.SplitN(hashWords(inner.Algorithm.String()), " (", 2)[0]
			} else {
				mgf = "MGF1 (hash does not decode)"
			}
		} else {
			mgf = p.MGF.Algorithm.String()
		}
	}
	def := func(isDefault bool) string {
		if isDefault {
			return " (default)"
		}
		return ""
	}
	// encoding/asn1 fills the defaults, so whether a field was present is read from the tags.
	salt := fmt.Sprintf("salt length %d", p.SaltLength)
	trailer := fmt.Sprintf("trailer field %d", p.TrailerField)
	saltDefault, trailerDefault := !hasTag(der, 2), !hasTag(der, 3)
	return "hash " + hash + def(hashDefault) + "; mask generation " + mgf + def(mgfDefault) + "; " +
		salt + def(saltDefault) + "; " + trailer + def(trailerDefault)
}

// hasTag reports whether the SEQUENCE der holds an element with the context tag n.
func hasTag(der []byte, n int) bool {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return false
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &v); err != nil {
			return false
		}
		if v.Class == asn1.ClassContextSpecific && v.Tag == n {
			return true
		}
	}
	return false
}

// Extension is one extension a certificate carries: its OID, whether it is critical, and the
// name this program decodes it by ("" when it does not decode it).
type Extension struct {
	OID      string
	Critical bool
	Name     string
}

// extensionNames are the extensions Describe decodes (RFC 5280 section 4.2; RFC 6962 for SCTs;
// RFC 7633 for the TLS Feature).
var extensionNames = map[string]string{
	"2.5.29.14": "subjectKeyIdentifier", "2.5.29.15": "keyUsage", "2.5.29.17": "subjectAlternativeName",
	"2.5.29.19": "basicConstraints", "2.5.29.30": "nameConstraints", "2.5.29.31": "crlDistributionPoints",
	"2.5.29.32": "certificatePolicies", "2.5.29.35": "authorityKeyIdentifier", "2.5.29.37": "extendedKeyUsage",
	"1.3.6.1.5.5.7.1.1": "authorityInformationAccess", "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestamp",
	"1.3.6.1.5.5.7.1.24": "tlsFeature",
}

func extensions(c *x509.Certificate) []Extension {
	out := make([]Extension, 0, len(c.Extensions))
	for _, e := range c.Extensions {
		oid := e.Id.String()
		out = append(out, Extension{OID: oid, Critical: e.Critical, Name: extensionNames[oid]})
	}
	return out
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}
