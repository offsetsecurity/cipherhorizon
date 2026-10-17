package tlscbom_test

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// AUDIT-TLS-CBOM-001 §3, priority 1: no identifier the scanner read is lost.

// A-1 and A-2: a signature or key algorithm the catalogue does not know keeps the OID read from
// the certificate, as an algorithm named by that OID, marked unrecognised, with no family guessed.
func TestUnknownCertificateSignatureOIDIsKept(t *testing.T) {
	const sigOID, keyOID = "1.3.6.1.4.1.99999.1.1", "1.3.6.1.4.1.99999.1.2"
	rep := sampleReport()
	ci := &rep.Certificates[0].Chain[0]
	ci.SignatureAlg = tlsprobe.AlgInfo{Name: "unknown (" + sigOID + ")", OID: sigOID}
	ci.PublicKey = tlsprobe.KeyInfo{Algorithm: "unknown", OID: keyOID}
	assets := tlscbom.FromTLSReport(rep)
	cert := findComponent(assets, "crypto/certificate/"+ci.SHA256)
	cp := cert.Component.CryptoProperties.CertificateProperties
	for _, c := range []struct{ what, ref, oid string }{
		{"signature", string(cp.SignatureAlgorithmRef), sigOID},
		{"key", keyAlgorithmRef(t, assets, string(cp.SubjectPublicKeyRef)), keyOID},
	} {
		if c.ref != "crypto/algorithm/oid-"+c.oid+"@"+c.oid {
			t.Errorf("%s: ref %q, want the OID kept", c.what, c.ref)
			continue
		}
		a := findComponent(assets, c.ref)
		if a == nil || a.Component.Name != c.oid || a.Component.CryptoProperties.OID != c.oid {
			t.Errorf("%s: component %+v", c.what, a)
			continue
		}
		if v, _ := property(a, "identifier-status"); v != cbom.UnrecognisedStatus {
			t.Errorf("%s: identifier-status = %q", c.what, v)
		}
		if a.Component.CryptoProperties.AlgorithmProperties.AlgorithmFamily != "" {
			t.Errorf("%s: a family was guessed", c.what)
		}
	}
	encode17(t, assets) // valid against the 1.7 schema
}

func TestUnknownKeyAlgorithmIsKept(t *testing.T) {
	// Covered with the signature above; this case checks that a junk OID never becomes a name.
	rep := sampleReport()
	ci := &rep.Certificates[0].Chain[0]
	ci.PublicKey = tlsprobe.KeyInfo{Algorithm: "unknown", OID: "<script>"}
	cert := findComponent(tlscbom.FromTLSReport(rep), "crypto/certificate/"+ci.SHA256)
	if cert.Component.CryptoProperties.CertificateProperties.SubjectPublicKeyRef != "" {
		t.Error("a key whose OID is not an OID was given a component")
	}
}

func keyAlgorithmRef(t *testing.T, assets []collector.CryptoAsset, keyRef string) string {
	t.Helper()
	k := findComponent(assets, keyRef)
	if k == nil {
		t.Fatalf("no key component %q", keyRef)
	}
	return string(k.Component.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef)
}

// A-4: every accepted group keeps its name and IANA code point, modelled or not.
func TestUnknownGroupsKeepTheirIdentifier(t *testing.T) {
	rep := sampleReport()
	rep.Groups = append(rep.Groups,
		tlsprobe.GroupResult{Version: "TLSv1.3", ID: 0x001F, Name: "brainpoolP256r1tls13"},
		tlsprobe.GroupResult{Version: "TLSv1.3", ID: 0x0022, Name: "GC256A"})
	proto := findComponent(tlscbom.FromTLSReport(rep), "protocol/tls/1.3")
	got, _ := property(proto, "accepted-groups")
	for _, want := range []string{"X25519MLKEM768 (0x11EC)", "x25519 (0x001D)", "brainpoolP256r1tls13 (0x001F)", "GC256A (0x0022)"} {
		if !strings.Contains(got, want) {
			t.Errorf("accepted-groups %q lacks %s", got, want)
		}
	}
}

// A-13: the TLS 1.3 signature schemes carry their code points, apart from certificate signatures.
func TestSignatureSchemesCarryTheirCodePoints(t *testing.T) {
	assets := tlscbom.FromTLSReport(withSignatures(tlsprobe.SigRefused, "mldsa65", "ecdsa_secp256r1_sha256"))
	got, _ := property(findComponent(assets, "protocol/tls/1.3"), "accepted-signature-schemes-iana")
	if got != "mldsa65 (0x0905), ecdsa_secp256r1_sha256 (0x0403)" {
		t.Errorf("accepted-signature-schemes-iana = %q", got)
	}
}
