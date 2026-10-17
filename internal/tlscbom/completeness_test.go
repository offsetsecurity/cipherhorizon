package tlscbom_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// The CBOM completeness fixes of CBOM-REVIEW-002 (PRD-009 REQ-CBM-1 to REQ-CBM-6).

// legacyReport is the SSLv3 demo target: static-RSA suites with 3DES, RC4 (also export
// 40-bit), NULL, and an anonymous DH suite.
func legacyReport() *tlsprobe.Report {
	suite := func(id uint16, name, kx, auth, cipher string, bits int, mode string) tlsprobe.SuiteResult {
		return tlsprobe.SuiteResult{Version: "SSLv3", ID: id, Name: name, Kx: kx, Auth: auth, Cipher: cipher, KeyBits: bits, Mode: mode, MAC: "SHA1"}
	}
	return &tlsprobe.Report{
		SchemaVersion: tlsprobe.SchemaVersion,
		Target:        tlsprobe.Target{Host: "legacy.example", Port: 443},
		Protocols:     []tlsprobe.ProtocolResult{{Version: "SSLv3", Supported: true, Evidence: tlsprobe.EvidenceServerHello}},
		Suites: []tlsprobe.SuiteResult{
			suite(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", 168, "CBC"),
			suite(0x0005, "TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4", 128, "STREAM"),
			suite(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", "RSA", "RC4", 40, "STREAM"),
			suite(0x0009, "TLS_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", "DES", 56, "CBC"),
			suite(0x0001, "TLS_RSA_WITH_NULL_MD5", "RSA", "RSA", "NULL", 0, "NULL"),
			suite(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", "DH", "", "RC4", 128, "STREAM"),
		},
	}
}

func suitesOf(t *testing.T, assets []collector.CryptoAsset, ref string) map[string][]string {
	t.Helper()
	p := findComponent(assets, ref)
	if p == nil || p.Component.CryptoProperties.ProtocolProperties.CipherSuites == nil {
		t.Fatalf("no protocol %s with suites", ref)
	}
	out := map[string][]string{}
	for _, s := range *p.Component.CryptoProperties.ProtocolProperties.CipherSuites {
		var refs []string
		if s.Algorithms != nil {
			for _, r := range *s.Algorithms {
				refs = append(refs, string(r))
			}
		}
		out[s.Name] = refs
	}
	return out
}

func TestLegacySuiteCiphersAreAssets(t *testing.T) {
	assets := tlscbom.FromTLSReport(legacyReport())
	suites := suitesOf(t, assets, "protocol/tls/3.0")
	for name, want := range map[string]string{
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":  "crypto/algorithm/3des",
		"TLS_RSA_WITH_RC4_128_SHA":       "crypto/algorithm/rc4",
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5": "crypto/algorithm/rc4",
		"TLS_RSA_WITH_DES_CBC_SHA":       "crypto/algorithm/des",
		"TLS_DH_anon_WITH_RC4_128_MD5":   "crypto/algorithm/rc4",
	} {
		if !containsRef(suites[name], want) {
			t.Errorf("%s lists %v, want %s among them", name, suites[name], want)
		}
	}
	// NULL is no cipher: the suite keeps only its key exchange.
	if got := suites["TLS_RSA_WITH_NULL_MD5"]; len(got) != 1 {
		t.Errorf("the NULL suite lists %v, want only RSA", got)
	}
	for _, ref := range []string{"crypto/algorithm/3des", "crypto/algorithm/rc4", "crypto/algorithm/des"} {
		c := findComponent(assets, ref)
		if c == nil {
			t.Errorf("%s is not an asset of the document", ref)
			continue
		}
		if v, ok := property(c, "classical-status"); !ok || v == "" {
			t.Errorf("%s carries no cited classical status", ref)
		}
	}
}

func TestSuiteAlgorithmsAreUnique(t *testing.T) {
	assets := tlscbom.FromTLSReport(legacyReport())
	for name, refs := range suitesOf(t, assets, "protocol/tls/3.0") {
		seen := map[string]bool{}
		for _, r := range refs {
			if seen[r] {
				t.Errorf("%s lists %s twice: %v", name, r, refs)
			}
			seen[r] = true
		}
	}
}

func TestNISTCurveGroupsAreAssets(t *testing.T) {
	rep := sampleReport()
	rep.Groups = append(rep.Groups,
		tlsprobe.GroupResult{Version: "TLSv1.3", ID: 23, Name: "secp256r1", IANARecommended: "Y"},
		tlsprobe.GroupResult{Version: "TLSv1.3", ID: 24, Name: "secp384r1", IANARecommended: "Y"},
		tlsprobe.GroupResult{Version: "TLSv1.3", ID: 25, Name: "secp521r1", IANARecommended: "N"},
		tlsprobe.GroupResult{Version: "TLSv1.3", ID: 30, Name: "x448", IANARecommended: "Y"})
	assets := tlscbom.FromTLSReport(rep)
	tls13 := findComponent(assets, "protocol/tls/1.3")
	for ref, curve := range map[string]string{
		"crypto/algorithm/ecdh-p256@1.3.132.1.12": "secp256r1",
		"crypto/algorithm/ecdh-p384@1.3.132.1.12": "secp384r1",
		"crypto/algorithm/ecdh-p521@1.3.132.1.12": "secp521r1",
		"crypto/algorithm/x448@1.3.101.111":       "",
	} {
		c := findComponent(assets, ref)
		if c == nil {
			t.Errorf("no asset %s", ref)
			continue
		}
		if got := c.Component.CryptoProperties.AlgorithmProperties.Curve; got != curve {
			t.Errorf("%s curve = %q, want %q", ref, got, curve)
		}
		if !containsRef(tls13.DependsOn, ref) {
			t.Errorf("TLS 1.3 does not depend on %s", ref)
		}
	}
	// TLS 1.2 accepts secp256r1 in the sample report.
	if !containsRef(findComponent(assets, "protocol/tls/1.2").DependsOn, "crypto/algorithm/ecdh-p256@1.3.132.1.12") {
		t.Error("TLS 1.2 does not depend on ECDH-P256")
	}

	// In 1.7 the curve is the registry's name, and the document validates.
	doc := encode17(t, assets)
	if !strings.Contains(doc, `"ellipticCurve": "secg/secp256r1"`) || !strings.Contains(doc, `"ellipticCurve": "other/Curve448"`) {
		t.Error("the 1.7 document does not name the curves by registry name")
	}
}

func TestCertificateSignatureVariantHasOID(t *testing.T) {
	for goName, want := range map[string]string{
		"ECDSA-SHA256":  "crypto/algorithm/ecdsa-with-sha256@1.2.840.10045.4.3.2",
		"ECDSA-SHA384":  "crypto/algorithm/ecdsa-with-sha384@1.2.840.10045.4.3.3",
		"SHA256-RSA":    "crypto/algorithm/sha256withrsaencryption@1.2.840.113549.1.1.11",
		"SHA512-RSA":    "crypto/algorithm/sha512withrsaencryption@1.2.840.113549.1.1.13",
		"SHA256-RSAPSS": "crypto/algorithm/rsassa-pss@1.2.840.113549.1.1.10",
		// No variant: the family, as before.
		"DSA-SHA256": "crypto/algorithm/dsa@1.2.840.10040.4.1",
	} {
		rep := sampleReport()
		rep.Certificates[0].Chain[0].SignatureAlg = tlsprobe.AlgInfo{Name: goName}
		assets := tlscbom.FromTLSReport(rep)
		cert := findComponent(assets, "crypto/certificate/"+rep.Certificates[0].Chain[0].SHA256)
		if got := string(cert.Component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef); got != want {
			t.Errorf("%s: signatureAlgorithmRef = %q, want %q", goName, got, want)
		}
		if findComponent(assets, want) == nil {
			t.Errorf("%s: %s is referenced but not in the document", goName, want)
		}
	}
}

func TestCertificateSerialAndFingerprintIn17(t *testing.T) {
	rep := sampleReport()
	rep.Certificates[0].Chain[0].SHA256 = strings.Repeat("ab", 32)
	assets := tlscbom.FromTLSReport(rep)
	doc := encode17(t, assets)
	var bom struct {
		Components []struct {
			BOMRef           string         `json:"bom-ref"`
			Properties       []cdx.Property `json:"properties"`
			CryptoProperties struct {
				CertificateProperties *struct {
					SerialNumber string   `json:"serialNumber"`
					Fingerprint  cdx.Hash `json:"fingerprint"`
				} `json:"certificateProperties"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(doc), &bom); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range bom.Components {
		cp := c.CryptoProperties.CertificateProperties
		if cp == nil {
			continue
		}
		found = true
		if cp.SerialNumber != "01A2B3" {
			t.Errorf("serialNumber = %q, want 01A2B3", cp.SerialNumber)
		}
		if cp.Fingerprint.Algorithm != cdx.HashAlgoSHA256 || cp.Fingerprint.Value != strings.Repeat("ab", 32) {
			t.Errorf("fingerprint = %+v", cp.Fingerprint)
		}
		for _, p := range c.Properties {
			if p.Name == cbom.PropertyNamespace+":cert-serial" {
				t.Error("the 1.7 document still carries the cert-serial property beside serialNumber")
			}
		}
	}
	if !found {
		t.Fatal("no certificate in the document")
	}
	// 1.6 keeps the property and has neither field.
	var buf bytes.Buffer
	if err := cbom.EncodeSpec(&buf, build(t, assets), cbom.Spec16, true); err != nil {
		t.Fatal(err)
	}
	if s := buf.String(); strings.Contains(s, `"serialNumber": "01A2B3"`) || !strings.Contains(s, `cipherhorizon:cert-serial`) {
		t.Error("the 1.6 document should carry the serial as a property only")
	}
}

func build(t *testing.T, assets []collector.CryptoAsset) *cdx.BOM {
	t.Helper()
	bom, warnings := cbom.Build(assets, cbom.Options{
		Tool: cbom.Tool{Name: "cipherhorizon", Version: "test"}, Endpoint: "endpoint.example:443",
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
	})
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	return bom
}

// encode17 builds and encodes a 1.7 document, validating it against the vendored schema.
func encode17(t *testing.T, assets []collector.CryptoAsset) string {
	t.Helper()
	var buf bytes.Buffer
	if err := cbom.EncodeSpec(&buf, build(t, assets), cbom.Spec17, true); err != nil {
		t.Fatal(err)
	}
	schematest.Validate(t, buf.Bytes())
	return buf.String()
}
