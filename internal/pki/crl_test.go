package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
)

// The CRL fixtures are made by OpenSSL (testing/pki/make-crl.sh): the producer
// is independent of the judgement under test.

func crlCert(t testing.TB, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "crl", name+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func crlFile(t *testing.T, name string) *x509.RevocationList {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "crl", name+".crl"))
	if err != nil {
		t.Fatal(err)
	}
	rl, err := x509.ParseRevocationList(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return rl
}

// crlAt is a time inside every fixture CRL's validity.
var crlAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

const (
	intURL  = "http://crl.pki.test/int.crl"
	rootURL = "http://crl.pki.test/root.crl"
)

func TestJudgeCRLAgainstOpenSSLFixtures(t *testing.T) {
	root, inter, leaf, other := crlCert(t, "root"), crlCert(t, "int"), crlCert(t, "leaf"), crlCert(t, "other")
	cases := []struct {
		name               string
		crl, url           string
		subject, issuer    *x509.Certificate
		status, sig        string
		reason, problemHas string
	}{
		{"leaf revoked", "int-revoked", intURL, leaf, inter, pki.CRLRevoked, pki.CRLSigValid, "keyCompromise", ""},
		{"other leaf not listed", "int-revoked", intURL, other, inter, pki.CRLGood, pki.CRLSigValid, "", ""},
		{"empty CRL", "int-empty", intURL, leaf, inter, pki.CRLGood, pki.CRLSigValid, "", ""},
		{"intermediate revoked by the root", "root-revoked", rootURL, inter, root, pki.CRLRevoked, pki.CRLSigValid, "cACompromise", ""},
		{"user-only CRL does not cover a CA", "int-empty", intURL, inter, root, pki.CRLUnknown, "", "", "not by the certificate's issuer"},
		{"CA-only CRL does not cover a leaf", "root-revoked", rootURL, leaf, inter, pki.CRLUnknown, "", "", "not by the certificate's issuer"},
		{"another partition", "int-partition", intURL, leaf, inter, pki.CRLUnknown, pki.CRLSigValid, "", "the partition for http://crl.pki.test/int-2.crl"},
		{"delta CRL", "int-delta", intURL, leaf, inter, pki.CRLUnknown, pki.CRLSigValid, "", "delta CRL"},
		{"right name, wrong key", "bad", intURL, leaf, inter, pki.CRLUnknown, pki.CRLSigInvalid, "", "does not verify"},
		{"issuer not available", "int-revoked", intURL, leaf, nil, pki.CRLUnknown, pki.CRLSigNoIssuer, "", "cannot be checked"},
	}
	for _, c := range cases {
		r := pki.JudgeCRL(crlFile(t, c.crl), c.url, c.subject, c.issuer, crlAt)
		if r.Status != c.status || r.Signature != c.sig || r.Reason != c.reason || (c.problemHas != "" && !strings.Contains(r.Problem, c.problemHas)) {
			t.Errorf("%s: %+v", c.name, r)
		}
		if c.status != pki.CRLUnknown && (r.ThisUpdate.IsZero() || r.NextUpdate.IsZero() || r.Number == "" || r.Issuer != pki.Fingerprint(c.issuer)) {
			t.Errorf("%s: missing CRL facts %+v", c.name, r)
		}
	}
	// Scope by certificate type, with the right issuer: the CA-only root CRL
	// judged for a leaf the root signed directly would be refused by IDP.
	r := pki.JudgeCRL(crlFile(t, "root-revoked"), rootURL, rootSignedLeaf(t, root), root, crlAt)
	if r.Status != pki.CRLUnknown || !strings.Contains(r.Problem, "only CA certificates") {
		t.Errorf("CA-only CRL for an end-entity certificate: %+v", r)
	}
	// The user-only int CRL for a CA int issued (int has pathlen 0, so build the subject by hand).
	if r := pki.JudgeCRL(crlFile(t, "int-empty"), intURL, asCA(leaf), inter, crlAt); r.Status != pki.CRLUnknown || !strings.Contains(r.Problem, "only end-entity") {
		t.Errorf("user-only CRL for a CA certificate: %+v", r)
	}
	// Not yet issued.
	if r := pki.JudgeCRL(crlFile(t, "int-empty"), intURL, leaf, inter, time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC)); r.Status != pki.CRLUnknown || !strings.Contains(r.Problem, "in the future") {
		t.Errorf("future CRL: %+v", r)
	}
}

// TestRevokedEntriesMatchOpenSSL compares serials, dates and reasons with
// `openssl crl -text`.
func TestRevokedEntriesMatchOpenSSL(t *testing.T) {
	inter, leaf := crlCert(t, "int"), crlCert(t, "leaf")
	root := crlCert(t, "root")
	for _, c := range []struct {
		crl     string
		subject *x509.Certificate
		issuer  *x509.Certificate
		url     string
	}{{"int-revoked", leaf, inter, intURL}, {"root-revoked", inter, root, rootURL}} {
		txt, err := os.ReadFile(filepath.Join("testdata", "crl", c.crl+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`Serial Number: ([0-9A-F]+)\s+Revocation Date: ([A-Za-z]+ +\d+ [\d:]+ \d+) GMT`).FindStringSubmatch(string(txt))
		if m == nil {
			t.Fatalf("%s: no revoked entry in the OpenSSL text", c.crl)
		}
		at, err := time.Parse("Jan _2 15:04:05 2006", m[2])
		if err != nil {
			t.Fatal(err)
		}
		r := pki.JudgeCRL(crlFile(t, c.crl), c.url, c.subject, c.issuer, crlAt)
		if !strings.EqualFold(c.subject.SerialNumber.Text(16), strings.TrimLeft(m[1], "0")) || !r.RevokedAt.Equal(at) {
			t.Errorf("%s: OpenSSL says %s at %s, we say %s at %s", c.crl, m[1], at, c.subject.SerialNumber.Text(16), r.RevokedAt)
		}
	}
}

// rootSignedLeaf is a copy of an end-entity certificate presented as if the
// root issued it: only the name fields JudgeCRL reads are changed.
func rootSignedLeaf(t *testing.T, root *x509.Certificate) *x509.Certificate {
	t.Helper()
	c := *crlCert(t, "other")
	c.RawIssuer = root.RawSubject
	return &c
}

func asCA(c *x509.Certificate) *x509.Certificate {
	cp := *c
	cp.IsCA = true
	return &cp
}
