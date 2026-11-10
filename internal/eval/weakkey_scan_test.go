package eval_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// smallKeyCertificate is a self-signed certificate whose ECDSA private key is the number d.
func smallKeyCertificate(t *testing.T, d int64) tls.Certificate {
	t.Helper()
	raw := make([]byte, 32)
	big.NewInt(d).FillBytes(raw)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "small-key.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A server whose certificate key is 4 (the shape of the 2026 eMudhra CA keys) is scanned like any
// other, and the evaluation says the key can be found and states it. Nothing else about the scan
// changes: the finding sits beside the usual ones.
func TestScanFindsASmallPrivateKey(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{Chain: []tls.Certificate{smallKeyCertificate(t, 4)}})
	rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: srv.Host, Port: srv.Port, SNI: "localhost"}, tlsprobe.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := eval.Evaluate(rep, time.Now())
	var got *eval.Finding
	for i := range ev.Findings {
		if ev.Findings[i].ID == "KEY.EC-SMALL-SCALAR" {
			got = &ev.Findings[i]
		}
	}
	if got == nil {
		t.Fatalf("no KEY.EC-SMALL-SCALAR finding; findings: %v", ids(ev))
	}
	if got.Severity != eval.Critical || !strings.Contains(got.Detail, "the private key is 4") || !strings.Contains(got.Detail, "small-key.test") {
		t.Errorf("finding: %s %q", got.Severity, got.Detail)
	}
	for _, c := range ev.Checks {
		if strings.HasPrefix(c.ID, "KEY.RSA-") && c.Result != "not-found" {
			t.Errorf("%s on a chain with no RSA key: %s", c.ID, c.Result)
		}
	}
}
