// Package certinfo describes an X.509 certificate's public metadata: identity,
// validity, key algorithm and size, signature algorithm, names and flags.
//
// It is the single place these facts are worked out. The TLS scanner (a certificate a
// server presented) and the host certificate sensors (a certificate a machine holds)
// both call it, so the same certificate yields the same attributes whichever way it
// was found, which is what lets the estate graph treat the two sightings as one entity.
//
// It reads a parsed certificate and nothing else: no key material, no network, no
// operating system, no file. It has no way to describe a private key.
package certinfo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"time"

	"github.com/example/cipherhorizon/internal/algo"
)

// Facts is what a certificate says about itself. Text fields come from the
// certificate and are attacker-controlled: callers clean and bound them before they
// travel further.
type Facts struct {
	Subject     string
	Issuer      string
	SerialHex   string
	DNSNames    []string
	IPAddresses []string
	NotBefore   time.Time
	NotAfter    time.Time
	IsCA        bool
	SelfSigned  bool
	SHA256      string // lower-case hex over the DER encoding: the certificate's identity
	KeyUsage    []string

	KeyAlgorithm string // RSA, ECDSA, Ed25519, ... or "unknown"; never guessed
	KeyOID       string // the SubjectPublicKeyInfo algorithm OID
	KeyBits      int    // 0 when the key size is not known
	Curve        string // named curve of an ECDSA key
	SigName      string
	SigOID       string

	OCSPServers    []string
	IssuerURLs     []string
	CRLPoints      []string
	OCSPMustStaple bool
	EmbeddedSCTs   bool
}

var (
	oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	oidSCTList    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// knownKeyOIDs names the public-key algorithms whose identity is fixed by RFCs.
// Anything else is looked up in the algorithm catalogue (which carries the
// NIST post-quantum OIDs) and otherwise reported as "unknown", never guessed.
var knownKeyOIDs = map[string]string{
	"1.2.840.113549.1.1.1":  "RSA",
	"1.2.840.10045.2.1":     "ECDSA", // id-ecPublicKey: also used by ECDH keys, but as a certificate key it signs
	"1.3.101.110":           "X25519",
	"1.3.101.111":           "X448",
	"1.3.101.112":           "Ed25519",
	"1.3.101.113":           "Ed448",
	"1.2.840.10040.4.1":     "DSA",
	"1.2.840.113549.1.1.10": "RSASSA-PSS",
}

// Describe reads a parsed certificate.
func Describe(c *x509.Certificate) Facts {
	sum := sha256.Sum256(c.Raw)
	f := Facts{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		SerialHex: c.SerialNumber.Text(16), DNSNames: c.DNSNames,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, IsCA: c.IsCA,
		SelfSigned:  bytes.Equal(c.RawSubject, c.RawIssuer),
		SHA256:      hex.EncodeToString(sum[:]),
		OCSPServers: c.OCSPServer, IssuerURLs: c.IssuingCertificateURL, CRLPoints: c.CRLDistributionPoints,
		KeyUsage: keyUsage(c),
	}
	for _, ip := range c.IPAddresses {
		f.IPAddresses = append(f.IPAddresses, ip.String())
	}
	for _, e := range c.Extensions {
		switch {
		case e.Id.Equal(oidSCTList):
			f.EmbeddedSCTs = true
		case e.Id.Equal(oidTLSFeature):
			// TLS Feature: SEQUENCE OF INTEGER; 5 is status_request, i.e. OCSP must-staple.
			f.OCSPMustStaple = bytes.Contains(e.Value, []byte{0x02, 0x01, 0x05})
		}
	}
	f.KeyAlgorithm, f.KeyOID, f.KeyBits, f.Curve = describeKey(c)
	f.SigName, f.SigOID = describeSignature(c)
	return f
}

func describeKey(c *x509.Certificate) (alg, oid string, bits int, curve string) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err == nil {
		oid = spki.Algorithm.Algorithm.String()
	}
	alg = keyName(oid)
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		alg, bits = "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		alg, curve, bits = "ECDSA", pub.Curve.Params().Name, pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		alg, bits = "Ed25519", 256
	}
	return alg, oid, bits, curve
}

func keyName(oid string) string {
	if n, ok := knownKeyOIDs[oid]; ok {
		return n
	}
	for _, a := range algo.All() {
		if a.OID != "" && a.OID == oid {
			return a.ID
		}
	}
	return "unknown"
}

// describeSignature reports the certificate's signature algorithm with its OID,
// read from the outer structure so it works for algorithms Go does not implement.
func describeSignature(c *x509.Certificate) (name, oid string) {
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.Raw, &outer); err == nil {
		oid = outer.Alg.Algorithm.String()
	}
	name = c.SignatureAlgorithm.String()
	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		name = keyName(oid) // e.g. an ML-DSA signature OID
		if name == "unknown" {
			name = "unknown (" + oid + ")"
		}
	}
	return strings.TrimSpace(name), oid
}

// keyUsage lists the key usages the certificate asserts, by the RFC 5280 names.
func keyUsage(c *x509.Certificate) []string {
	var out []string
	for _, u := range []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"}, {x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"}, {x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"}, {x509.KeyUsageEncipherOnly, "encipherOnly"}, {x509.KeyUsageDecipherOnly, "decipherOnly"},
	} {
		if c.KeyUsage&u.bit != 0 {
			out = append(out, u.name)
		}
	}
	return out
}
