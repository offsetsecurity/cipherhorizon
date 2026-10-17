package algo_test

import (
	"regexp"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
)

var oidRE = regexp.MustCompile(`^[0-2](\.(0|[1-9][0-9]*))+$`)

func TestCatalogueIsWellFormed(t *testing.T) {
	seenRef := map[string]string{}
	for _, a := range algo.All() {
		if a.ID == "" || a.ID != strings.TrimSpace(a.ID) {
			t.Errorf("bad ID %q", a.ID)
		}
		if a.Primitive == "" {
			t.Errorf("%s: no primitive (omit-not-guess applies to fields, not to the primitive of a catalogued algorithm)", a.ID)
		}
		if a.OID != "" && !oidRE.MatchString(a.OID) {
			t.Errorf("%s: malformed OID %q", a.ID, a.OID)
		}
		if a.QuantumLevel < 0 || a.QuantumLevel > 5 {
			t.Errorf("%s: QuantumLevel %d outside 0..5", a.ID, a.QuantumLevel)
		}
		if other, dup := seenRef[a.BOMRef()]; dup {
			t.Errorf("%s and %s share bom-ref %s", a.ID, other, a.BOMRef())
		}
		seenRef[a.BOMRef()] = a.ID
	}
}

// An OID names one catalogue entry, with one exception RFC 5480 defines: ECDH on a named curve
// is id-ecDH with the curve as a parameter, so a curve variant shares its family's OID. The
// family must sort first, so that a lookup by OID (certinfo, an imported CBOM) finds the family.
func TestOIDsAreUnique(t *testing.T) {
	seen := map[string]algo.Algorithm{}
	for _, a := range algo.All() {
		if a.OID == "" {
			continue
		}
		if other, dup := seen[a.OID]; dup {
			if a.Curve == "" || other.Curve != "" || !strings.HasPrefix(a.ID, other.ID+"-") {
				t.Errorf("OID %s used by both %s and %s", a.OID, a.ID, other.ID)
			}
			continue
		}
		seen[a.OID] = a
	}
}

func TestComponentShape(t *testing.T) {
	c := algo.MustGet("ML-KEM-768").Component()
	if c.Type != cdx.ComponentTypeCryptographicAsset {
		t.Errorf("type = %q", c.Type)
	}
	if c.BOMRef != "crypto/algorithm/ml-kem-768@2.16.840.1.101.3.4.4.2" {
		t.Errorf("bom-ref = %q", c.BOMRef)
	}
	cp := c.CryptoProperties
	if cp == nil || cp.AssetType != cdx.CryptoAssetTypeAlgorithm || cp.OID != "2.16.840.1.101.3.4.4.2" {
		t.Fatalf("cryptoProperties = %+v", cp)
	}
	if cp.AlgorithmProperties.Primitive != cdx.CryptoPrimitiveKEM {
		t.Errorf("primitive = %q", cp.AlgorithmProperties.Primitive)
	}
	if got := cp.AlgorithmProperties.NistQuantumSecurityLevel; got == nil || *got != 3 {
		t.Errorf("nistQuantumSecurityLevel = %v, want 3 (FIPS 203)", got)
	}
}

// Unset means omitted: no value may be invented where a standard does not give one.
func TestUnsetFieldsAreOmitted(t *testing.T) {
	rsa := algo.MustGet("RSA").Component().CryptoProperties
	if rsa.AlgorithmProperties.NistQuantumSecurityLevel != nil {
		t.Error("RSA must not carry a nistQuantumSecurityLevel")
	}
	ecdsa := algo.MustGet("ECDSA").Component()
	if ecdsa.CryptoProperties.OID != "" || strings.Contains(ecdsa.BOMRef, "@") {
		t.Error("ECDSA has no single authoritative OID; none may be emitted")
	}
	// The closed 1.7 registry fields are never populated: no lookup table backs them yet.
	for _, a := range algo.All() {
		p := a.Component().CryptoProperties.AlgorithmProperties
		if p.AlgorithmFamily != "" || p.EllipticCurve != "" {
			t.Errorf("%s sets a 1.7 registry field without an authoritative table", a.ID)
		}
	}
}

func TestLookup(t *testing.T) {
	if _, ok := algo.Lookup("Rot13"); ok {
		t.Error("Lookup invented an algorithm")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustGet of an unknown ID did not panic")
		}
	}()
	algo.MustGet("Rot13")
}

// A legacy statement is a citation, not an opinion: it must name its source.
func TestLegacyStatementsAreCited(t *testing.T) {
	var n int
	for _, a := range algo.All() {
		if a.Legacy == nil {
			continue
		}
		n++
		if a.Legacy.Summary == "" || a.Legacy.Citation == "" || !strings.HasPrefix(a.Legacy.URL, "https://") {
			t.Errorf("%s: incomplete legacy statement %+v", a.ID, *a.Legacy)
		}
		if a.NoPQCVerdict == "" {
			t.Errorf("%s: a legacy algorithm has a classical question, so it must record why it has no post-quantum verdict", a.ID)
		}
	}
	if n == 0 {
		t.Error("no legacy entries found")
	}
}

func TestLegacyAndUnclassifiedShowUpAsProperties(t *testing.T) {
	c := algo.MustGet("MD5").Component()
	got := map[string]string{}
	if c.Properties != nil {
		for _, p := range *c.Properties {
			got[p.Name] = p.Value
		}
	}
	for _, name := range []string{"cipherhorizon:classical-status", "cipherhorizon:classical-basis", "cipherhorizon:pqc:unclassified-reason"} {
		if got[name] == "" {
			t.Errorf("MD5 component lacks %s: %v", name, got)
		}
	}
	if p := algo.MustGet("AES").Component().Properties; p != nil {
		t.Errorf("an ordinary algorithm gained properties: %v", *p)
	}
}

// TestCatalogueOIDsAreCited pins the OIDs CBOM-REVIEW-002 checked against their primary
// sources, so a later edit cannot drift from what the RFC says.
func TestCatalogueOIDsAreCited(t *testing.T) {
	for id, want := range map[string]string{
		"ChaCha20-Poly1305": "1.2.840.113549.1.9.16.3.18", // RFC 8103 section 3
		"ECDH":              "1.3.132.1.12",               // RFC 5480 section 2.1.2
		"ECDH-P256":         "1.3.132.1.12",
		"ECDH-P384":         "1.3.132.1.12",
		"ECDH-P521":         "1.3.132.1.12",
		"X25519":            "1.3.101.110", // RFC 8410 section 3
		"X448":              "1.3.101.111",
		"Ed25519":           "1.3.101.112",
		"Ed448":             "1.3.101.113",
		"RSA":               "1.2.840.113549.1.1.1", // RFC 8017 appendix A.1
	} {
		a, ok := algo.Lookup(id)
		if !ok {
			t.Errorf("%s is not in the catalogue", id)
			continue
		}
		if a.OID != want {
			t.Errorf("%s OID = %q, want %q", id, a.OID, want)
		}
	}
	for id, curve := range map[string]string{"ECDH-P256": "secp256r1", "ECDH-P384": "secp384r1", "ECDH-P521": "secp521r1"} {
		if a := algo.MustGet(id); a.Curve != curve {
			t.Errorf("%s curve = %q, want %q", id, a.Curve, curve)
		}
	}
}
