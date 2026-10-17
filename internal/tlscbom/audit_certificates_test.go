package tlscbom_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// AUDIT-TLS-CBOM-001 §3, priorities 3 and 4: signature parameters, key identity, extensions, the
// served chain and where each certificate was seen. Certificates are made here with crypto/x509, so
// the CBOM is compared with what an independent encoder wrote.

var rsaKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func makeCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, pub any, priv any) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func baseTemplate(cn string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func reportWith(chains ...tlsprobe.CertResult) *tlsprobe.Report {
	r := sampleReport()
	r.Certificates = chains
	return r
}

func props(t *testing.T, assets []collector.CryptoAsset, ref string) map[string]string {
	t.Helper()
	c := findComponent(assets, ref)
	if c == nil {
		t.Fatalf("no component %s", ref)
	}
	out := map[string]string{}
	if c.Component.Properties != nil {
		for _, p := range *c.Component.Properties {
			out[strings.TrimPrefix(p.Name, "cipherhorizon:")] = p.Value
		}
	}
	return out
}

// A-3: RSASSA-PSS parameters are decoded, per certificate, as the certificate states them.
func TestRSASSAPSSParametersAreDecoded(t *testing.T) {
	for alg, want := range map[x509.SignatureAlgorithm]string{
		x509.SHA256WithRSAPSS: "hash SHA-256 (2.16.840.1.101.3.4.2.1); mask generation MGF1 with SHA-256; salt length 32; trailer field 1 (default)",
		x509.SHA384WithRSAPSS: "hash SHA-384 (2.16.840.1.101.3.4.2.2); mask generation MGF1 with SHA-384; salt length 48; trailer field 1 (default)",
		x509.SHA512WithRSAPSS: "hash SHA-512 (2.16.840.1.101.3.4.2.3); mask generation MGF1 with SHA-512; salt length 64; trailer field 1 (default)",
	} {
		tmpl := baseTemplate("pss.example", 7)
		tmpl.SignatureAlgorithm = alg
		ci := tlsprobe.DescribeCertificate(makeCert(t, tmpl, nil, &rsaKey.PublicKey, rsaKey))
		assets := tlscbom.FromTLSReport(reportWith(tlsprobe.CertResult{Source: "tls-default", Chain: []tlsprobe.CertInfo{ci}}))
		p := props(t, assets, "crypto/certificate/"+ci.SHA256)
		if p["signature-parameters"] != want {
			t.Errorf("%v: signature-parameters = %q, want %q", alg, p["signature-parameters"], want)
		}
		cert := findComponent(assets, "crypto/certificate/"+ci.SHA256)
		if ref := string(cert.Component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef); ref != "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10" {
			t.Errorf("%v: signature ref %q", alg, ref)
		}
	}
	// A certificate that is not PSS states no parameters.
	tmpl := baseTemplate("plain.example", 8)
	ci := tlsprobe.DescribeCertificate(makeCert(t, tmpl, nil, &rsaKey.PublicKey, rsaKey))
	if ci.SignatureParams != "" {
		t.Errorf("a PKCS #1 v1.5 certificate has signature parameters %q", ci.SignatureParams)
	}
}

// A-7, A-8, A-12: every extension the certificate carries reaches the 1.7 document, by its common
// name or, failing one, by its OID; the key carries its fingerprint and exponent.
func TestCertificateExtensionsCarryEveryRecordedFact(t *testing.T) {
	tmpl := baseTemplate("ext.example", 9)
	tmpl.DNSNames = []string{"ext.example", "www.ext.example"}
	tmpl.OCSPServer = []string{"http://ocsp.ext.example"}
	tmpl.IssuingCertificateURL = []string{"http://ca.ext.example/ca.crt"}
	tmpl.CRLDistributionPoints = []string{"http://crl.ext.example/ca.crl"}
	tmpl.SubjectKeyId = []byte{1, 2, 3, 4}
	tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}, Critical: true, Value: []byte{5, 0}}}
	ci := tlsprobe.DescribeCertificate(makeCert(t, tmpl, nil, &rsaKey.PublicKey, rsaKey))
	assets := tlscbom.FromTLSReport(reportWith(tlsprobe.CertResult{Source: "tls-default", Chain: []tlsprobe.CertInfo{ci}}))
	doc := encode17(t, assets)
	for _, want := range []string{
		`"commonExtensionName": "subjectAlternativeName"`, `"commonExtensionValue": "DNS:ext.example, DNS:www.ext.example"`,
		`"commonExtensionName": "authorityInformationAccess"`, `OCSP - URI:http://ocsp.ext.example`, `CA Issuers - URI:http://ca.ext.example/ca.crt`,
		`"commonExtensionName": "crlDistributionPoints"`, `URI:http://crl.ext.example/ca.crl`,
		`"commonExtensionName": "subjectKeyIdentifier"`, `"commonExtensionValue": "01020304"`,
		`"customExtensionName": "1.3.6.1.4.1.99999.7"`, `"customExtensionValue": "not decoded; critical"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the 1.7 document lacks %s", want)
		}
	}
	// The key: its SPKI SHA-256 as the 1.7 fingerprint, and the RSA exponent.
	var bom struct {
		Components []struct {
			BOMRef     string `json:"bom-ref"`
			Properties []struct{ Name, Value string }
			Crypto     struct {
				RCM *struct {
					Fingerprint struct{ Alg, Content string }
				} `json:"relatedCryptoMaterialProperties"`
			} `json:"cryptoProperties"`
		}
	}
	if err := json.Unmarshal([]byte(doc), &bom); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range bom.Components {
		if c.Crypto.RCM == nil {
			continue
		}
		found = true
		if c.Crypto.RCM.Fingerprint.Alg != "SHA-256" || c.Crypto.RCM.Fingerprint.Content != ci.SPKISHA256 {
			t.Errorf("key fingerprint = %+v, want SHA-256 %s", c.Crypto.RCM.Fingerprint, ci.SPKISHA256)
		}
		exp := ""
		for _, p := range c.Properties {
			if p.Name == "cipherhorizon:rsa-exponent" {
				exp = p.Value
			}
		}
		if exp != "65537" {
			t.Errorf("rsa-exponent = %q, want 65537", exp)
		}
	}
	if !found {
		t.Fatal("no key component")
	}
}

// A-9, A-10: a certificate says which handshakes returned it; within a chain as served, a
// certificate names the one after it that issued it; a no-SNI-only certificate says so.
func TestServedChainIsLinkedAndEachCertificateSaysWhereItWasSeen(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := baseTemplate("Test Issuing CA", 1)
	caTmpl.IsCA, caTmpl.BasicConstraintsValid = true, true
	caTmpl.KeyUsage = x509.KeyUsageCertSign
	ca := makeCert(t, caTmpl, nil, &caKey.PublicKey, caKey)
	leaf := makeCert(t, baseTemplate("leaf.example", 2), ca, &rsaKey.PublicKey, caKey)
	other := makeCert(t, baseTemplate("default.example", 3), ca, &rsaKey.PublicKey, caKey)
	l, c, o := tlsprobe.DescribeCertificate(leaf), tlsprobe.DescribeCertificate(ca), tlsprobe.DescribeCertificate(other)
	assets := tlscbom.FromTLSReport(reportWith(
		tlsprobe.CertResult{Source: "tls-default", Chain: []tlsprobe.CertInfo{l, c}},
		tlsprobe.CertResult{Source: "tls1.2-rsa", Chain: []tlsprobe.CertInfo{l, c}},
		tlsprobe.CertResult{Source: "tls-default", NoSNI: true, Chain: []tlsprobe.CertInfo{o}},
	))
	lp, cp, op := props(t, assets, "crypto/certificate/"+l.SHA256), props(t, assets, "crypto/certificate/"+c.SHA256), props(t, assets, "crypto/certificate/"+o.SHA256)
	if lp["issued-by"] != "crypto/certificate/"+c.SHA256 {
		t.Errorf("leaf issued-by = %q", lp["issued-by"])
	}
	if cp["issued-by"] != "" {
		t.Errorf("the CA names an issuer the server did not send: %q", cp["issued-by"])
	}
	if lp["seen-in"] != "tls-default, tls1.2-rsa" || lp["no-sni"] != "" {
		t.Errorf("leaf seen-in %q, no-sni %q", lp["seen-in"], lp["no-sni"])
	}
	if op["seen-in"] != "tls-default (no SNI)" || op["no-sni"] != "true" {
		t.Errorf("no-SNI certificate seen-in %q, no-sni %q", op["seen-in"], op["no-sni"])
	}
}

// A-11: a suite references its MAC, or, for an AEAD suite, the hash its name carries.
func TestSuiteReferencesItsMACOrHash(t *testing.T) {
	assets := tlscbom.FromTLSReport(sampleReport())
	for proto, want := range map[string]map[string]string{
		"protocol/tls/1.3": {"TLS_AES_128_GCM_SHA256": "crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1"},
		"protocol/tls/1.2": {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1"},
	} {
		suites := suitesOf(t, assets, proto)
		for name, ref := range want {
			if !containsRef(suites[name], ref) {
				t.Errorf("%s lists %v, want %s", name, suites[name], ref)
			}
		}
	}
	legacy := suitesOf(t, tlscbom.FromTLSReport(legacyReport()), "protocol/tls/3.0")
	if !containsRef(legacy["TLS_RSA_WITH_3DES_EDE_CBC_SHA"], "crypto/algorithm/hmac-sha-1@1.2.840.113549.2.7") {
		t.Errorf("3DES suite lists %v, want HMAC-SHA-1", legacy["TLS_RSA_WITH_3DES_EDE_CBC_SHA"])
	}
}
