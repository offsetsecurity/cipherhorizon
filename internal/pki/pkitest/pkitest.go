// Package pkitest builds small test PKIs at test time: a root, intermediates
// and leaf variants with exactly the properties a fixture needs. Keys are
// ECDSA P-256 (fast) unless a fixture asks for RSA. Test support only.
package pkitest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Epoch is a fixed reference time fixtures are built around, so tests pass
// their own "now" instead of reading the clock.
var Epoch = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

var serial atomic.Int64

// CA is a certificate authority that can issue.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// CAOpts shape a CA certificate.
type CAOpts struct {
	NotBefore, NotAfter time.Time // default Epoch-1y .. Epoch+10y
	PermittedDNS        []string
	EKU                 []x509.ExtKeyUsage
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func create(t testing.TB, tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("pkitest: create %s: %v", tmpl.Subject.CommonName, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("pkitest: parse %s: %v", tmpl.Subject.CommonName, err)
	}
	return c
}

func caTemplate(name string, o CAOpts) *x509.Certificate {
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = Epoch.AddDate(-1, 0, 0)
	}
	if na.IsZero() {
		na = Epoch.AddDate(10, 0, 0)
	}
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: name, Organization: []string{"pkitest"}},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, PermittedDNSDomains: o.PermittedDNS, ExtKeyUsage: o.EKU,
	}
}

// NewRoot makes a self-signed root.
func NewRoot(t testing.TB, name string, o CAOpts) *CA {
	t.Helper()
	k := newKey(t)
	tmpl := caTemplate(name, o)
	return &CA{Cert: create(t, tmpl, tmpl, &k.PublicKey, k), Key: k}
}

// Intermediate issues a subordinate CA.
func (ca *CA) Intermediate(t testing.TB, name string, o CAOpts) *CA {
	t.Helper()
	k := newKey(t)
	return &CA{Cert: create(t, caTemplate(name, o), ca.Cert, &k.PublicKey, ca.Key), Key: k}
}

// SCTSpec is one SCT to embed in a leaf.
type SCTSpec struct {
	LogID     [32]byte
	Timestamp time.Time
}

// LeafOpts shape a leaf certificate. The zero value is a valid serverAuth leaf
// for "leaf.test", issued a month before Epoch and valid 90 days.
type LeafOpts struct {
	CN                  string
	DNS                 []string
	IPs                 []net.IP
	NotBefore, NotAfter time.Time
	EKU                 []x509.ExtKeyUsage // default serverAuth
	NoEKU               bool
	MustStaple          bool
	OCSP, CRL, AIA      []string
	SCTs                []SCTSpec
	RSAExponent         int      // >0: an RSA-2048 key with this public exponent
	Policies            []string // dotted OIDs
}

// Leaf issues an end-entity certificate.
func (ca *CA) Leaf(t testing.TB, o LeafOpts) *x509.Certificate {
	t.Helper()
	c, _ := ca.LeafKey(t, o)
	return c
}

// TLS returns a leaf (with its key) and the given chain as a tls.Certificate a
// test server can present.
func (ca *CA) TLS(t testing.TB, o LeafOpts, chain ...*x509.Certificate) tls.Certificate {
	t.Helper()
	if o.RSAExponent > 0 {
		t.Fatal("pkitest: an RSA leaf with a custom exponent has no usable key")
	}
	leaf, key := ca.LeafKey(t, o)
	tc := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	return tc
}

// LeafKey is Leaf that also returns the private key (nil for RSAExponent).
func (ca *CA) LeafKey(t testing.TB, o LeafOpts) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	if o.CN == "" {
		o.CN = "leaf.test"
	}
	if o.DNS == nil && o.IPs == nil {
		o.DNS = []string{"leaf.test"}
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = Epoch.AddDate(0, -1, 0)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.AddDate(0, 0, 90)
	}
	if o.EKU == nil && !o.NoEKU {
		o.EKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: o.CN},
		NotBefore: o.NotBefore, NotAfter: o.NotAfter, DNSNames: o.DNS, IPAddresses: o.IPs,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: o.EKU, BasicConstraintsValid: true,
		OCSPServer: o.OCSP, CRLDistributionPoints: o.CRL, IssuingCertificateURL: o.AIA,
	}
	for _, p := range o.Policies {
		oid, err := x509.ParseOID(p)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.Policies = append(tmpl.Policies, oid)
	}
	if o.MustStaple {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05}})
	}
	if len(o.SCTs) > 0 {
		v, err := asn1.Marshal(SCTList(o.SCTs))
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: v})
	}
	var (
		pub any
		key crypto.Signer
	)
	if o.RSAExponent > 0 {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub = &rsa.PublicKey{N: k.N, E: o.RSAExponent}
	} else {
		k := newKey(t)
		pub, key = &k.PublicKey, k
	}
	return create(t, tmpl, ca.Cert, pub, ca.Key), key
}

// SCT returns one serialized SCT body (RFC 6962 §3.2) with a dummy signature.
func SCT(s SCTSpec) []byte {
	b := []byte{0}
	b = append(b, s.LogID[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(s.Timestamp.UnixMilli()))
	b = append(b, 0, 0)       // no extensions
	b = append(b, 4, 3, 0, 2) // SHA-256 / ECDSA, 2-byte signature
	return append(b, 0xde, 0xad)
}

// SCTList returns a TLS-encoded SignedCertificateTimestampList.
func SCTList(scts []SCTSpec) []byte {
	var body []byte
	for _, s := range scts {
		one := SCT(s)
		body = binary.BigEndian.AppendUint16(body, uint16(len(one))) //nolint:gosec // test data, far below 64 KiB
		body = append(body, one...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...) //nolint:gosec // test data, far below 64 KiB
}

// DER returns the raw encodings, in the given order.
func DER(certs ...*x509.Certificate) [][]byte {
	out := make([][]byte, len(certs))
	for i, c := range certs {
		out[i] = c.Raw
	}
	return out
}
