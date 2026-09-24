package algo_test

import (
	"regexp"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/algo"
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

func TestOIDsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, a := range algo.All() {
		if a.OID == "" {
			continue
		}
		if other, dup := seen[a.OID]; dup {
			t.Errorf("OID %s used by both %s and %s", a.OID, a.ID, other)
		}
		seen[a.OID] = a.ID
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
