package tlscbom_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// AUDIT-TLS-CBOM-001 Phase C: end to end through the real scanner, against TLS servers on loopback
// presenting certificates made here, so the CBOM is compared with what an independent encoder
// (crypto/x509) wrote and what crypto/tls served: an RSASSA-PSS certificate, an Ed25519 one, and a
// served two-certificate chain whose leaf carries an extension this program does not know.
func TestEndToEndCertificatesReachTheCBOMAsServed(t *testing.T) {
	if testing.Short() {
		t.Skip("starts TLS servers")
	}
	scanOne := func(t *testing.T, chain []tls.Certificate) []collector.CryptoAsset {
		t.Helper()
		srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: chain})
		rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: srv.Host, Port: srv.Port},
			tlsprobe.Options{Timeout: 3 * time.Second, Concurrency: 8})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		assets := tlscbom.FromTLSReport(rep)
		encode17(t, assets) // valid against the 1.7 schema
		return assets
	}
	certOf := func(c *x509.Certificate, key any) tls.Certificate {
		return tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: key, Leaf: c}
	}
	sha := func(c *x509.Certificate) string { return tlsprobe.DescribeCertificate(c).SHA256 }

	t.Run("RSASSA-PSS", func(t *testing.T) {
		tmpl := baseTemplate("127.0.0.1", 21)
		tmpl.SignatureAlgorithm = x509.SHA384WithRSAPSS
		c := makeCert(t, tmpl, nil, &rsaKey.PublicKey, rsaKey)
		assets := scanOne(t, []tls.Certificate{certOf(c, rsaKey)})
		cert := findComponent(assets, "crypto/certificate/"+sha(c))
		if cert == nil {
			t.Fatal("the served certificate is not in the CBOM")
		}
		if ref := string(cert.Component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef); ref != "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10" {
			t.Errorf("signature ref %q", ref)
		}
		if p := props(t, assets, cert.Component.BOMRef)["signature-parameters"]; !strings.HasPrefix(p, "hash SHA-384") || !strings.Contains(p, "salt length 48") {
			t.Errorf("signature-parameters %q", p)
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		c := makeCert(t, baseTemplate("127.0.0.1", 22), nil, pub, priv)
		assets := scanOne(t, []tls.Certificate{certOf(c, priv)})
		cert := findComponent(assets, "crypto/certificate/"+sha(c))
		if cert == nil {
			t.Fatal("the served certificate is not in the CBOM")
		}
		if ref := string(cert.Component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef); ref != "crypto/algorithm/ed25519@1.3.101.112" {
			t.Errorf("signature ref %q", ref)
		}
		key := findComponent(assets, string(cert.Component.CryptoProperties.CertificateProperties.SubjectPublicKeyRef))
		if key == nil || string(key.Component.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef) != "crypto/algorithm/ed25519@1.3.101.112" {
			t.Errorf("key %+v", key)
		}
	})

	t.Run("served chain with an unknown extension", func(t *testing.T) {
		caTmpl := baseTemplate("Audit Test CA", 23)
		caTmpl.IsCA, caTmpl.BasicConstraintsValid, caTmpl.KeyUsage = true, true, x509.KeyUsageCertSign
		ca := makeCert(t, caTmpl, nil, &rsaKey.PublicKey, rsaKey)
		leafTmpl := baseTemplate("leaf.audit.test", 24)
		leafTmpl.IPAddresses = nil
		leafTmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 9}, Value: []byte{5, 0}}}
		leaf := makeCert(t, leafTmpl, ca, &rsaKey.PublicKey, rsaKey)
		served := tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Raw}, PrivateKey: rsaKey, Leaf: leaf}
		assets := scanOne(t, []tls.Certificate{served})
		lp := props(t, assets, "crypto/certificate/"+sha(leaf))
		if lp["issued-by"] != "crypto/certificate/"+sha(ca) {
			t.Errorf("issued-by %q", lp["issued-by"])
		}
		if !strings.Contains(lp["seen-in"], "tls-default") {
			t.Errorf("seen-in %q", lp["seen-in"])
		}
		doc := encode17(t, assets)
		if !strings.Contains(doc, `"customExtensionName": "1.3.6.1.4.1.99999.9"`) {
			t.Error("the unknown extension is not listed by its OID")
		}
		if !strings.Contains(doc, `"commonExtensionName": "authorityKeyIdentifier"`) {
			t.Error("the leaf's authorityKeyIdentifier is missing")
		}
	})
}
