package pki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
)

// hugeRSACert is a self-issued dummy certificate whose subject key is an RSA modulus of the given
// size (not a real key) and whose RSA signature is a random value as long as that modulus, so that
// checking it really runs the RSA operation with the oversized key.
func hugeRSACert(t *testing.T, bits int) *x509.Certificate {
	t.Helper()
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "oversized key"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), SignatureAlgorithm: x509.SHA256WithRSA,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsa.PublicKey{N: n, E: 65537}, signer)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, (bits+7)/8)
	_, _ = rand.Read(sig)
	sig[0] = 0x01 // below the modulus
	outer.Sig = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	if der, err = asn1.Marshal(outer); err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A served certificate with an RSA key larger than crypto/tls accepts is never used to check a
// signature, so it cannot make chain analysis slow.
func TestOversizedRSAKeyIsNotUsedToCheckSignatures(t *testing.T) {
	big := hugeRSACert(t, 1<<19)
	start := time.Now()
	if pki.SelfSigned(big) || pki.Issued(big, big) {
		t.Error("an oversized key verified a signature")
	}
	if _, err := pki.AnalyzeServed([][]byte{big.Raw, big.Raw}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Errorf("checking signatures against an oversized RSA key took %v", took)
	}
}
