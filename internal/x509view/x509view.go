// Package x509view decodes one certificate for people (PRD-012, ENH-003): every field of the
// X.509 document and every extension, in the order an engineer reads them, with the public key's
// and the signature's classical strength and post-quantum status. It decodes the DER the scanner
// kept; nothing is stored. Every value comes from the certificate, which an attacker may have
// chosen: callers render it as text only.
package x509view

import (
	"crypto/sha1" //nolint:gosec // the SHA-1 fingerprint is an identifier people search for, never a security decision
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/certinfo"
	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
)

// MaxDER bounds the certificate this package decodes: a real one is a few kilobytes.
const MaxDER = 64 << 10

// maxHex bounds how much of an undecoded extension's value is shown, in bytes.
const maxHex = 512

// View is one certificate, decoded.
type View struct {
	Version      int        `json:"version"`
	Serial       string     `json:"serial"`
	Subject      string     `json:"subject"`
	SubjectParts []NamePart `json:"subjectParts"`
	Issuer       string     `json:"issuer"`
	IssuerParts  []NamePart `json:"issuerParts"`
	NotBefore    time.Time  `json:"notBefore"`
	NotAfter     time.Time  `json:"notAfter"`
	LifetimeDays int        `json:"lifetimeDays"`
	Validation   string     `json:"validation,omitempty"` // DV, OV, IV, EV from the CA/Browser Forum policy
	IsCA         bool       `json:"isCa"`
	SelfSigned   bool       `json:"selfSigned"`
	Names        Names      `json:"names"`
	PublicKey    PublicKey  `json:"publicKey"`
	Signature    Signature  `json:"signature"`
	Extensions   []Ext      `json:"extensions"`
	SHA256       string     `json:"sha256"`
	SHA1         string     `json:"sha1"` // an identifier only
	PEM          string     `json:"pem"`
}

// NamePart is one attribute of a distinguished name, in the order the certificate lists them.
type NamePart struct {
	Type  string `json:"type"` // CN, O, OU, C, L, ST, or the OID
	Value string `json:"value"`
}

// Names are the subject alternative names, by type.
type Names struct {
	DNS       []string `json:"dns,omitempty"`
	IP        []string `json:"ip,omitempty"`
	Email     []string `json:"email,omitempty"`
	URI       []string `json:"uri,omitempty"`
	Wildcards []string `json:"wildcards,omitempty"`
	CNOnly    bool     `json:"cnOnly,omitempty"` // a CN and no subjectAltName: modern clients reject it
}

// PublicKey is the subject's key with its strengths.
type PublicKey struct {
	Algorithm  string        `json:"algorithm"`
	OID        string        `json:"oid"`
	Bits       int           `json:"bits,omitempty"`
	Curve      string        `json:"curve,omitempty"`
	Exponent   int           `json:"exponent,omitempty"`
	SPKISHA256 string        `json:"spkiSha256"`
	Strength   algo.Strength `json:"strength"`
	PQC        string        `json:"pqc,omitempty"`
}

// Signature is the issuer's signature on the certificate.
type Signature struct {
	Algorithm string        `json:"algorithm"`
	OID       string        `json:"oid"`
	Params    string        `json:"params,omitempty"` // RSASSA-PSS parameters in words
	Strength  algo.Strength `json:"strength"`
	PQC       string        `json:"pqc,omitempty"`
}

// Ext is one extension: what it is, whether it is critical, and its value. Values holds the
// decoded value, one entry per item; an extension this package does not decode has Hex instead.
type Ext struct {
	OID      string   `json:"oid"`
	Name     string   `json:"name"`
	Critical bool     `json:"critical"`
	Values   []string `json:"values,omitempty"`
	Hex      string   `json:"hex,omitempty"`
	Cut      bool     `json:"cut,omitempty"` // Hex shows only the first maxHex bytes
}

// Decode decodes a certificate. issuer, when known, is the certificate that signed it; its key
// rates the signature (a self-signed certificate is its own issuer).
func Decode(der []byte, issuer *x509.Certificate) (*View, error) {
	if len(der) == 0 {
		return nil, errors.New("no certificate")
	}
	if len(der) > MaxDER {
		return nil, fmt.Errorf("the certificate is %d bytes, more than the %d this decodes", len(der), MaxDER)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("not a certificate Go can parse: %w", err)
	}
	f := certinfo.Describe(c)
	s256 := sha256.Sum256(der)
	s1 := sha1.Sum(der) //nolint:gosec // identifier only
	v := &View{
		Version: c.Version, Serial: f.SerialHex, Subject: f.Subject, SubjectParts: nameParts(c.Subject.Names),
		Issuer: f.Issuer, IssuerParts: nameParts(c.Issuer.Names), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		LifetimeDays: f.LifetimeDays, IsCA: f.IsCA, SelfSigned: f.SelfSigned,
		Names:  Names{DNS: f.DNSNames, IP: f.IPAddresses, Email: c.EmailAddresses, Wildcards: f.Wildcards, CNOnly: f.CNOnly},
		SHA256: hex.EncodeToString(s256[:]), SHA1: hex.EncodeToString(s1[:]),
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	if f.PolicyClass != "" && f.PolicyClass != "unknown" {
		v.Validation = f.PolicyClass
	}
	for _, u := range c.URIs {
		v.Names.URI = append(v.Names.URI, u.String())
	}

	key := algo.KeyStrength(f.KeyAlgorithm, f.KeyBits, f.Curve)
	v.PublicKey = PublicKey{Algorithm: f.KeyAlgorithm, OID: f.KeyOID, Bits: f.KeyBits, Curve: f.Curve, Exponent: f.RSAExponent,
		SPKISHA256: f.SPKISHA256, Strength: key, PQC: pqcOf(keyFamily(f.KeyAlgorithm), f.KeyOID)}

	var signer *algo.Strength
	switch {
	case issuer != nil:
		fi := certinfo.Describe(issuer)
		st := algo.KeyStrength(fi.KeyAlgorithm, fi.KeyBits, fi.Curve)
		signer = &st
	case f.SelfSigned:
		signer = &key
	}
	sigPQC := ""
	if _, k, ok := algo.SignatureParts(f.SigName); ok {
		sigPQC = pqcOf(k, "")
	} else {
		sigPQC = pqcOf(f.SigName, f.SigOID)
	}
	v.Signature = Signature{Algorithm: f.SigName, OID: f.SigOID, Params: f.SigParams, Strength: algo.SignatureStrength(f.SigName, signer), PQC: sigPQC}

	for _, e := range c.Extensions {
		v.Extensions = append(v.Extensions, decodeExt(c, f, e.Id.String(), e.Critical, e.Value))
	}
	return v, nil
}

// DecodeBase64 decodes the base64 DER a scan report keeps.
func DecodeBase64(b64 string, issuer *x509.Certificate) (*View, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("the stored certificate is not base64: %w", err)
	}
	return Decode(der, issuer)
}

func keyFamily(alg string) string {
	switch alg {
	case "RSA", "RSASSA-PSS":
		return "RSA"
	case "ECDSA", "EC":
		return "ECDSA"
	}
	return alg
}

func pqcOf(name, oid string) string {
	if oid == "" {
		if a, ok := algo.Lookup(name); ok {
			oid = a.OID
		}
	}
	if c, ok := pqc.ClassOf(name, oid); ok {
		return string(c)
	}
	return ""
}

// dnTypes are the short names of the attributes a distinguished name usually carries (RFC 4514).
var dnTypes = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU",
	"2.5.4.5": "serialNumber", "2.5.4.17": "postalCode", "1.2.840.113549.1.9.1": "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC", "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC", "2.5.4.15": "businessCategory",
}

func nameParts(names []pkix.AttributeTypeAndValue) []NamePart {
	out := make([]NamePart, 0, len(names))
	for _, n := range names {
		t := n.Type.String()
		if short, ok := dnTypes[t]; ok {
			t = short
		}
		out = append(out, NamePart{Type: t, Value: fmt.Sprint(n.Value)})
	}
	return out
}

// extNames name the extensions people meet (RFC 5280 section 4.2, RFC 6962, RFC 7633, and the
// common CA ones). An extension not listed here is shown by its OID.
var extNames = map[string]string{
	"2.5.29.14": "Subject key identifier", "2.5.29.15": "Key usage", "2.5.29.17": "Subject alternative name",
	"2.5.29.18": "Issuer alternative name", "2.5.29.19": "Basic constraints", "2.5.29.30": "Name constraints",
	"2.5.29.31": "CRL distribution points", "2.5.29.32": "Certificate policies", "2.5.29.33": "Policy mappings",
	"2.5.29.35": "Authority key identifier", "2.5.29.36": "Policy constraints", "2.5.29.37": "Extended key usage",
	"2.5.29.46": "Freshest CRL", "2.5.29.54": "Inhibit anyPolicy", "1.3.6.1.5.5.7.1.1": "Authority information access",
	"1.3.6.1.5.5.7.1.11": "Subject information access", "1.3.6.1.4.1.11129.2.4.2": "Signed certificate timestamps",
	"1.3.6.1.4.1.11129.2.4.3": "Precertificate poison", "1.3.6.1.5.5.7.1.24": "TLS feature",
	"1.3.6.1.4.1.311.21.7": "Microsoft certificate template", "1.3.6.1.4.1.311.21.10": "Microsoft application policies",
	"2.16.840.1.113730.1.1": "Netscape certificate type", "2.16.840.1.113730.1.13": "Netscape comment",
}

// policyNames are the policy OIDs people recognise (CA/Browser Forum Baseline Requirements 7.1.6).
var policyNames = map[string]string{
	"2.23.140.1.2.1": "domain validated (DV)", "2.23.140.1.2.2": "organization validated (OV)",
	"2.23.140.1.2.3": "individual validated (IV)", "2.23.140.1.1": "extended validation (EV)", "2.5.29.32.0": "any policy",
}

func decodeExt(c *x509.Certificate, f certinfo.Facts, oid string, critical bool, value []byte) Ext {
	e := Ext{OID: oid, Name: extNames[oid], Critical: critical}
	if e.Name == "" {
		e.Name = oid
	}
	set := func(vs ...string) {
		for _, x := range vs {
			if x != "" {
				e.Values = append(e.Values, x)
			}
		}
	}
	switch oid {
	case "2.5.29.17":
		for _, n := range c.DNSNames {
			set("DNS: " + n)
		}
		for _, ip := range c.IPAddresses {
			set("IP: " + ip.String())
		}
		for _, m := range c.EmailAddresses {
			set("email: " + m)
		}
		for _, u := range c.URIs {
			set("URI: " + u.String())
		}
	case "2.5.29.15":
		set(f.KeyUsage...)
	case "2.5.29.37":
		set(f.ExtKeyUsage...)
	case "2.5.29.19":
		switch {
		case !c.BasicConstraintsValid:
			set("not set")
		case !c.IsCA:
			set("not a CA")
		case c.MaxPathLen == 0 && c.MaxPathLenZero:
			set("a CA; path length 0: it signs only end-entity certificates")
		case c.MaxPathLen > 0:
			set(fmt.Sprintf("a CA; path length %d: at most %d intermediate CAs below it", c.MaxPathLen, c.MaxPathLen))
		default:
			set("a CA; no limit on the path below it")
		}
	case "2.5.29.30":
		if nc := f.NameConstraints; nc != nil {
			for _, p := range nc.Permitted {
				set("permitted: " + p)
			}
			for _, x := range nc.Excluded {
				set("excluded: " + x)
			}
		}
	case "2.5.29.14":
		set(colonHex(c.SubjectKeyId))
	case "2.5.29.35":
		set(colonHex(c.AuthorityKeyId))
	case "1.3.6.1.5.5.7.1.1":
		for _, u := range c.OCSPServer {
			set("OCSP: " + u)
		}
		for _, u := range c.IssuingCertificateURL {
			set("CA issuers: " + u)
		}
	case "2.5.29.31":
		set(c.CRLDistributionPoints...)
	case "2.5.29.32":
		// Policies, not PolicyIdentifiers: it also holds OIDs with arcs too large for asn1.
		for _, p := range c.Policies {
			s := p.String()
			if n, ok := policyNames[s]; ok {
				s += " (" + n + ")"
			}
			set(s)
		}
	case "1.3.6.1.4.1.11129.2.4.2":
		scts, err := pki.EmbeddedSCTs(c)
		if err != nil {
			set("could not be decoded: " + err.Error())
			break
		}
		for _, s := range scts {
			log := base64.StdEncoding.EncodeToString(s.LogID[:])
			if l, ok := refdata.LookupCTLog(s.LogID[:]); ok {
				log = l.Name
				if l.Operator != "" {
					log += " (" + l.Operator + ")"
				}
			}
			set(fmt.Sprintf("%s, %s", log, s.Timestamp.UTC().Format("2006-01-02 15:04 UTC")))
		}
	case "1.3.6.1.5.5.7.1.24":
		var features []int
		if _, err := asn1.Unmarshal(value, &features); err == nil {
			for _, n := range features {
				if n == 5 {
					set("status_request (OCSP must-staple)")
				} else {
					set(fmt.Sprintf("TLS feature %d", n))
				}
			}
		}
	}
	if len(e.Values) == 0 {
		b := value
		if len(b) > maxHex {
			b, e.Cut = b[:maxHex], true
		}
		e.Hex = colonHex(b)
	}
	return e
}

// colonHex is bytes as AB:CD:EF, the way certificate tools print them.
func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}
