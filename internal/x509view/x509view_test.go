package x509view

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// sctList is a one-entry RFC 6962 SignedCertificateTimestampList for logID, wrapped as the
// X.509 extension carries it (an OCTET STRING).
func sctList(t testing.TB, logID []byte, at time.Time) []byte {
	t.Helper()
	sct := []byte{0} // v1
	sct = append(sct, logID...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(at.UnixMilli()))
	sct = append(sct, ts...)
	sct = append(sct, 0, 0)       // no extensions
	sct = append(sct, 4, 3, 0, 2) // SHA-256, ECDSA, a 2-byte signature
	sct = append(sct, 0xAB, 0xCD)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(sct)))
	list = append(list, sct...)
	inner := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	inner = append(inner, list...)
	b, err := asn1.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// richChain is an RSA-3072 CA and a leaf it signs (ECDSA P-256) that carries every extension
// this package decodes, plus one it does not.
func richChain(t testing.TB) (leafDER []byte, ca *x509.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Issuing CA", Organization: []string{"Example Corp"}, Country: []string{"GB"}},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains: []string{"example.test"}, ExcludedDNSDomains: []string{"secret.example.test"},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if ca, err = x509.ParseCertificate(caDER); err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID, _ := base64.StdEncoding.DecodeString("1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=") // Google Argon2026h2
	mustStaple, _ := asn1.Marshal([]int{5})
	u, _ := url.Parse("spiffe://example.test/web")
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234abcd), Subject: pkix.Name{CommonName: "www.example.test", Organization: []string{"Example Corp"}},
		NotBefore: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 12, 30, 0, 0, 0, 0, time.UTC),
		DNSNames: []string{"www.example.test", "*.api.example.test"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.7")},
		EmailAddresses: []string{"ops@example.test"}, URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, OCSPServer: []string{"http://ocsp.example.test"}, IssuingCertificateURL: []string{"http://ca.example.test/ca.crt"},
		CRLDistributionPoints: []string{"http://crl.example.test/ca.crl"},
		Policies:              []x509.OID{mustOID(t, 2, 23, 140, 1, 2, 2), mustOID(t, 1, 3, 6, 1, 4, 1, 99999, 7)},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: mustStaple},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: sctList(t, logID, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: false, Value: []byte{0x04, 0x02, 0xBE, 0xEF}},
		},
	}
	if leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey); err != nil {
		t.Fatal(err)
	}
	return leafDER, ca
}

// REQ-XV-1: every field and every extension, decoded; one this package does not know is OID and hex.
func TestX509DecodeShowsEveryExtension(t *testing.T) {
	der, ca := richChain(t)
	v, err := Decode(der, ca)
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != 3 || v.Serial != "1234abcd" || !strings.Contains(v.Subject, "CN=www.example.test") || !strings.Contains(v.Issuer, "CN=Example Issuing CA") {
		t.Errorf("identity: version %d serial %q subject %q issuer %q", v.Version, v.Serial, v.Subject, v.Issuer)
	}
	if len(v.SubjectParts) != 2 || v.SubjectParts[0].Type == "" {
		t.Errorf("subject parts: %+v", v.SubjectParts)
	}
	if v.Validation != "OV" || v.LifetimeDays != 91 {
		t.Errorf("validation %q lifetime %d", v.Validation, v.LifetimeDays)
	}
	if len(v.Names.DNS) != 2 || len(v.Names.IP) != 1 || len(v.Names.Email) != 1 || len(v.Names.URI) != 1 || len(v.Names.Wildcards) != 1 {
		t.Errorf("names: %+v", v.Names)
	}
	if v.PublicKey.Algorithm != "ECDSA" || v.PublicKey.Strength.Words() != "128 bits" || v.PublicKey.PQC != "quantum-vulnerable" || len(v.PublicKey.SPKISHA256) != 64 {
		t.Errorf("public key: %+v", v.PublicKey)
	}
	// Signed by an RSA-3072 key (128 bits) with SHA-256 (128 bits for collisions).
	if v.Signature.Algorithm != "SHA256-RSA" || v.Signature.Strength.Words() != "128 bits" || v.Signature.PQC != "quantum-vulnerable" {
		t.Errorf("signature: %+v", v.Signature)
	}
	sum := sha256.Sum256(der)
	if v.SHA256 != hex.EncodeToString(sum[:]) || len(v.SHA1) != 40 {
		t.Errorf("fingerprints %s %s", v.SHA256, v.SHA1)
	}

	byName := map[string]Ext{}
	for _, e := range v.Extensions {
		byName[e.Name] = e
	}
	want := map[string]string{
		"Subject alternative name":      "DNS: *.api.example.test",
		"Key usage":                     "digitalSignature",
		"Extended key usage":            "serverAuth",
		"Basic constraints":             "not a CA",
		"Authority key identifier":      "01:02:03:04",
		"Authority information access":  "OCSP: http://ocsp.example.test",
		"CRL distribution points":       "http://crl.example.test/ca.crl",
		"Certificate policies":          "2.23.140.1.2.2 (organization validated (OV))",
		"TLS feature":                   "status_request (OCSP must-staple)",
		"Signed certificate timestamps": "Google Argon2026h2 (Google), 2026-10-01 12:00 UTC",
	}
	for name, value := range want {
		e, ok := byName[name]
		if !ok {
			t.Errorf("%s is missing (have %v)", name, v.Extensions)
			continue
		}
		if !strings.Contains(strings.Join(e.Values, "\n"), value) {
			t.Errorf("%s = %q, want it to contain %q", name, e.Values, value)
		}
	}
	unknown, ok := byName["1.3.6.1.4.1.99999.1"]
	if !ok || unknown.Hex != "04:02:BE:EF" || len(unknown.Values) != 0 {
		t.Errorf("the unknown extension: %+v (ok %v)", unknown, ok)
	}
	if len(v.Extensions) != len(mustParse(t, der).Extensions) {
		t.Errorf("%d extensions shown, the certificate has %d", len(v.Extensions), len(mustParse(t, der).Extensions))
	}

	// The CA: path length 0 and its name constraints.
	cv, err := Decode(ca.Raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cv.Extensions {
		switch e.Name {
		case "Basic constraints":
			if !e.Critical || !strings.Contains(e.Values[0], "path length 0") {
				t.Errorf("CA basic constraints: %+v", e)
			}
		case "Name constraints":
			if got := strings.Join(e.Values, ";"); !strings.Contains(got, "permitted: DNS:example.test") && !strings.Contains(got, "example.test") {
				t.Errorf("name constraints: %q", got)
			}
		}
	}
	if !cv.SelfSigned || cv.Signature.Strength.Words() != "128 bits" {
		t.Errorf("a self-signed CA's signature is rated by its own key: %+v", cv.Signature)
	}
}

func mustOID(t testing.TB, arcs ...uint64) x509.OID {
	t.Helper()
	o, err := x509.OIDFromInts(arcs)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// REQ-XV-6: the PEM parses back to the same certificate.
func TestPEMRoundTrip(t *testing.T) {
	der, ca := richChain(t)
	v, err := Decode(der, ca)
	if err != nil {
		t.Fatal(err)
	}
	b, rest := pem.Decode([]byte(v.PEM))
	if b == nil || b.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("PEM: %q", v.PEM)
	}
	c := mustParse(t, b.Bytes)
	sum := sha256.Sum256(c.Raw)
	if hex.EncodeToString(sum[:]) != v.SHA256 {
		t.Error("the PEM is a different certificate")
	}
}

// REQ-XV-2 (with FuzzX509Decode): what is not a certificate is an error, never a panic.
func TestX509DecodeRefusesWhatIsNotACertificate(t *testing.T) {
	for _, der := range [][]byte{nil, {}, []byte("not der"), {0x30, 0x82, 0xff, 0xff}, make([]byte, MaxDER+1)} {
		if _, err := Decode(der, nil); err == nil {
			t.Errorf("Decode(%d bytes) gave no error", len(der))
		}
	}
	if _, err := DecodeBase64("%%%", nil); err == nil {
		t.Error("bad base64 gave no error")
	}
}

func FuzzX509Decode(f *testing.F) {
	der, ca := richChain(f)
	f.Add(der)
	f.Add(ca.Raw)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Decode(b, nil)
		if err == nil && v == nil {
			t.Fatal("no view and no error")
		}
	})
}
