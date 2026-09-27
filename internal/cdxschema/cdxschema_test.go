package cdxschema_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/cdxschema"
)

const minimal16 = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
  {"type":"cryptographic-asset","name":"AES-256-GCM","bom-ref":"a","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"ae"}}}]}`

func TestOurOwnGoldenCBOMsValidateAgainstTheEmbeddedSchema(t *testing.T) {
	files, _ := filepath.Glob("../../testing/golden/*.cbom.json") // the 1.6 baselines; the 1.7 ones are validated by the app tests
	if len(files) == 0 {
		t.Skip("no golden CBOMs")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		probs, err := cdxschema.Validate(b, "1.6", 5)
		if err != nil || len(probs) != 0 {
			t.Errorf("%s: %v %v", filepath.Base(f), probs, err)
		}
	}
}

func TestValidAndInvalidDocuments(t *testing.T) {
	if p, err := cdxschema.Validate([]byte(minimal16), "1.6", 5); err != nil || len(p) != 0 {
		t.Errorf("a valid 1.6 document: %v %v", p, err)
	}
	// The same content is a valid 1.7 document once it says so.
	v17 := strings.Replace(minimal16, `"specVersion":"1.6"`, `"specVersion":"1.7"`, 1)
	if p, err := cdxschema.Validate([]byte(v17), "1.7", 5); err != nil || len(p) != 0 {
		t.Errorf("a valid 1.7 document: %v %v", p, err)
	}
	for name, doc := range map[string]string{
		"an unknown asset type":    strings.Replace(minimal16, `"assetType":"algorithm"`, `"assetType":"widget"`, 1),
		"wrong bomFormat":          strings.Replace(minimal16, `"CycloneDX"`, `"SPDX"`, 1),
		"a string for version":     strings.Replace(minimal16, `"version":1`, `"version":"one"`, 1),
		"a component with no type": `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"name":"x"}]}`,
		"not JSON":                 `{not json`,
	} {
		p, err := cdxschema.Validate([]byte(doc), "1.6", 3)
		if err != nil || len(p) == 0 {
			t.Errorf("%s: accepted (%v, %v)", name, p, err)
		}
		if len(p) > 3 {
			t.Errorf("%s: %d problems, want at most 3", name, len(p))
		}
		for _, x := range p {
			if len(x.Message) > 310 {
				t.Errorf("%s: a problem message is %d bytes", name, len(x.Message))
			}
		}
	}
	// 1.7 knows things 1.6 does not: an algorithmFamily from the registry is fine in 1.7.
	fam := strings.Replace(strings.Replace(minimal16, `"specVersion":"1.6"`, `"specVersion":"1.7"`, 1), `"primitive":"ae"`, `"primitive":"ae","algorithmFamily":"AES"`, 1)
	if p, err := cdxschema.Validate([]byte(fam), "1.7", 5); err != nil || len(p) != 0 {
		t.Errorf("algorithmFamily AES in 1.7: %v %v", p, err)
	}
	bad := strings.Replace(fam, `"algorithmFamily":"AES"`, `"algorithmFamily":"NOT-A-REGISTERED-FAMILY"`, 1)
	if p, _ := cdxschema.Validate([]byte(bad), "1.7", 5); len(p) == 0 {
		t.Error("an algorithm family outside the registry was accepted by the 1.7 schema")
	}
}

func TestUnsupportedVersionsAreRefused(t *testing.T) {
	for _, v := range []string{"1.5", "1.4", "2.0", "", "1.6 ", "../1.6"} {
		if cdxschema.IsSupported(v) {
			t.Errorf("%q reported as supported", v)
		}
		if _, err := cdxschema.Validate([]byte(minimal16), v, 3); err == nil {
			t.Errorf("Validate accepted version %q", v)
		}
	}
}

// Real third-party documents, if the developer has them (CIPHERHORIZON_INTEROP_DIR): not part
// of the shipped repository, because their licences are not all verified (PRD-003 OQ-5).
func TestRealThirdPartyDocumentsValidate(t *testing.T) {
	dir := os.Getenv("CIPHERHORIZON_INTEROP_DIR")
	if dir == "" {
		t.Skip("CIPHERHORIZON_INTEROP_DIR is not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		spec := "1.6"
		if strings.Contains(string(b[:min(len(b), 400)]), `"specVersion": "1.7"`) || strings.Contains(string(b[:min(len(b), 400)]), `"specVersion":"1.7"`) {
			spec = "1.7"
		}
		start := time.Now()
		probs, err := cdxschema.Validate(b, spec, 5)
		t.Logf("%s (%d bytes, %s): %d problems, %v in %s", filepath.Base(f), len(b), spec, len(probs), err, time.Since(start).Round(time.Millisecond))
		for _, p := range probs {
			t.Logf("  %s: %s", p.Path, p.Message)
		}
	}
}

// One copy of the 1.6 schema in production and one in the test support: they must not drift.
func TestTheProductionAndTestSchemasAreTheSameBytes(t *testing.T) {
	a, err := os.ReadFile("schemas/bom-1.6.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../testing/schema/bom-1.6.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("internal/cdxschema/schemas/bom-1.6.schema.json differs from testing/schema/bom-1.6.schema.json")
	}
}
