package cbom_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cbom-scan/internal/algo"
	"github.com/example/cbom-scan/internal/cbom"
	"github.com/example/cbom-scan/internal/collector"
	"github.com/example/cbom-scan/internal/schematest"
)

func fixed() cbom.Options {
	return cbom.Options{
		Tool:      cbom.Tool{Name: "cbom-scan", Version: "test"},
		HostName:  "testhost",
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
	}
}

func lib(ref string, provides ...string) collector.CryptoAsset {
	return collector.CryptoAsset{
		Component: cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeLibrary, Name: ref, Version: "1"},
		Provides:  provides,
	}
}

func encode(t *testing.T, bom *cdx.BOM) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBuildProducesSchemaValidCBOM(t *testing.T) {
	rsa, mlkem := algo.MustGet("RSA"), algo.MustGet("ML-KEM-768")
	bom, warnings := cbom.Build([]collector.CryptoAsset{
		lib("pkg:deb/debian/libssl3@3.5.1", rsa.BOMRef(), mlkem.BOMRef()),
		rsa.Asset(),
		mlkem.Asset(),
	}, fixed())
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	doc := encode(t, bom)
	schematest.Validate(t, doc)

	var got struct {
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Dependencies []struct {
			Ref      string   `json:"ref"`
			Provides []string `json:"provides"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatal(err)
	}
	if got.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", got.SpecVersion)
	}
	if len(got.Dependencies) != 1 || len(got.Dependencies[0].Provides) != 2 {
		t.Errorf("dependencies = %+v, want one entry providing two algorithms", got.Dependencies)
	}
}

// cyclonedx-go v0.12.0's EncodeVersion rewrites "cryptographic-asset" to
// "application" for every spec version. The result is schema-valid, so schema
// validation cannot catch it: assert the type in the encoded JSON directly.
func TestEncodeKeepsCryptographicAssetType(t *testing.T) {
	rsa := algo.MustGet("RSA")
	bom, _ := cbom.Build([]collector.CryptoAsset{lib("l", rsa.BOMRef()), rsa.Asset()}, fixed())

	var doc struct {
		Schema     string `json:"$schema"`
		Components []struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Crypt *struct {
				AssetType string `json:"assetType"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(encode(t, bom), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "http://cyclonedx.org/schema/bom-1.6.schema.json" {
		t.Errorf("$schema = %q", doc.Schema)
	}
	for _, c := range doc.Components {
		switch c.Name {
		case "RSA":
			if c.Type != "cryptographic-asset" || c.Crypt == nil || c.Crypt.AssetType != "algorithm" {
				t.Errorf("RSA encoded as type %q, cryptoProperties %+v; want cryptographic-asset/algorithm", c.Type, c.Crypt)
			}
		case "l":
			if c.Type != "library" {
				t.Errorf("library encoded as %q", c.Type)
			}
		}
	}
	if bom.SpecVersion == cdx.SpecVersion1_6 {
		t.Error("Encode mutated the caller's BOM")
	}
}

// Guards the guard: the schema validator must actually reject an invalid
// document, or every "is valid" assertion in this repo is vacuous.
func TestSchemaValidatorRejectsInvalidDocument(t *testing.T) {
	bad := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
	  {"type":"cryptographic-asset","name":"x","bom-ref":"x","cryptoProperties":
	    {"assetType":"algorithm","algorithmProperties":{"primitive":"teleport"}}}]}`
	if err := schematest.ValidateErr([]byte(bad)); err == nil {
		t.Fatal("validator accepted an out-of-vocabulary primitive")
	}
	worse := strings.Replace(bad, `"primitive":"teleport"`, `"algorithmFamily":"RSA"`, 1)
	if err := schematest.ValidateErr([]byte(worse)); err == nil {
		t.Fatal("validator accepted a 1.7-only field under 1.6")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	rsa, aes := algo.MustGet("RSA"), algo.MustGet("AES")
	a := []collector.CryptoAsset{lib("b", rsa.BOMRef(), aes.BOMRef()), lib("a", aes.BOMRef()), rsa.Asset(), aes.Asset()}
	b := []collector.CryptoAsset{aes.Asset(), rsa.Asset(), lib("a", aes.BOMRef()), lib("b", aes.BOMRef(), rsa.BOMRef())}

	bomA, _ := cbom.Build(a, fixed())
	bomB, _ := cbom.Build(b, fixed())
	if !bytes.Equal(encode(t, bomA), encode(t, bomB)) {
		t.Error("output depends on input order")
	}
}

func TestBuildMergesIdenticalDuplicates(t *testing.T) {
	rsa := algo.MustGet("RSA")
	bom, warnings := cbom.Build([]collector.CryptoAsset{rsa.Asset(), rsa.Asset(), lib("l1", rsa.BOMRef()), lib("l2", rsa.BOMRef())}, fixed())
	if len(warnings) != 0 {
		t.Errorf("identical duplicates warned: %v", warnings)
	}
	if n := len(*bom.Components); n != 3 {
		t.Errorf("got %d components, want 3 (one RSA, two libs)", n)
	}
}

func TestBuildRejectsConflictingDuplicates(t *testing.T) {
	a := lib("same")
	b := lib("same")
	b.Component.Version = "2"
	bom, warnings := cbom.Build([]collector.CryptoAsset{a, b}, fixed())
	if len(warnings) != 1 || !strings.Contains(warnings[0], "conflicting") {
		t.Fatalf("warnings = %v, want one 'conflicting'", warnings)
	}
	if v := (*bom.Components)[0].Version; v != "1" {
		t.Errorf("kept version %q, want the first (1)", v)
	}
}

func TestBuildDropsDanglingEdgesAndInvalidAssets(t *testing.T) {
	bom, warnings := cbom.Build([]collector.CryptoAsset{
		lib("l", "crypto/algorithm/nonexistent"),
		{Component: cdx.Component{Name: "no-ref", Type: cdx.ComponentTypeLibrary}},
	}, fixed())

	if len(*bom.Components) != 1 {
		t.Errorf("components = %d, want 1", len(*bom.Components))
	}
	if bom.Dependencies != nil {
		t.Errorf("dangling edge emitted: %+v", *bom.Dependencies)
	}
	if len(warnings) != 2 {
		t.Errorf("warnings = %v, want 2 (dangling edge, invalid asset)", warnings)
	}
	schematest.Validate(t, encode(t, bom))
}

func TestBuildNeverEmitsUnvettedVocabulary(t *testing.T) {
	bad := algo.MustGet("RSA").Component()
	bad.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitiveKeyWrap // 1.7-only
	bad.CryptoProperties.AlgorithmProperties.AlgorithmFamily = "RSA"

	bom, warnings := cbom.Build([]collector.CryptoAsset{{Component: bad}}, fixed())
	if len(warnings) != 2 {
		t.Errorf("warnings = %v, want 2", warnings)
	}
	schematest.Validate(t, encode(t, bom))
}

func TestBuildEmptyInput(t *testing.T) {
	bom, warnings := cbom.Build(nil, fixed())
	if len(warnings) != 0 || bom.Components != nil {
		t.Errorf("empty build: components=%v warnings=%v", bom.Components, warnings)
	}
	schematest.Validate(t, encode(t, bom))
}
