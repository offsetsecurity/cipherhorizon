package cbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cbom-scan/internal/schematest"
)

// schemaEnum reads an enumeration out of the vendored bom-1.6 schema.
func schemaEnum(t *testing.T, path ...string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(schematest.SchemaDir(), "bom-1.6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		t.Fatal(err)
	}
	for _, p := range path {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("schema path %v: %q parent is not an object", path, p)
		}
		if node, ok = m[p]; !ok {
			t.Fatalf("schema path %v: no %q", path, p)
		}
	}
	list, ok := node.([]any)
	if !ok {
		t.Fatalf("schema path %v is not an array", path)
	}
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = v.(string)
	}
	sort.Strings(out)
	return out
}

func keys[T ~string](set map[T]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The vocabulary sets in vocab.go must be exactly the enumerations of the 1.6
// schema (assetType is deliberately a strict subset: only algorithm assets are
// supported so far).
func TestVocabularyMatchesSchema(t *testing.T) {
	algo := []string{"definitions", "cryptoProperties", "properties", "algorithmProperties", "properties"}
	at := func(name string, more ...string) []string {
		return schemaEnum(t, append(append(append([]string{}, algo...), name), more...)...)
	}

	for name, tc := range map[string]struct{ got, want []string }{
		"primitive":              {keys(primitives), at("primitive", "enum")},
		"mode":                   {keys(modes), at("mode", "enum")},
		"padding":                {keys(paddings), at("padding", "enum")},
		"executionEnvironment":   {keys(execEnvironments), at("executionEnvironment", "enum")},
		"implementationPlatform": {keys(platforms), at("implementationPlatform", "enum")},
		"certificationLevel":     {keys(certLevels), at("certificationLevel", "items", "enum")},
		"cryptoFunctions":        {keys(functions), at("cryptoFunctions", "items", "enum")},
	} {
		if !equal(tc.got, tc.want) {
			t.Errorf("%s vocabulary drifted from the 1.6 schema\n code:   %v\n schema: %v", name, tc.got, tc.want)
		}
	}

	schemaAssetTypes := map[string]bool{}
	for _, v := range schemaEnum(t, "definitions", "cryptoProperties", "properties", "assetType", "enum") {
		schemaAssetTypes[v] = true
	}
	for _, v := range keys(assetTypes) {
		if !schemaAssetTypes[v] {
			t.Errorf("assetType %q supported in code but absent from the 1.6 schema", v)
		}
	}
}

func TestSanitizeOmitsOutOfVocabulary(t *testing.T) {
	level := 9
	c := cdx.Component{
		BOMRef: "x", Name: "x", Type: cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			OID:       "not-an-oid",
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:                cdx.CryptoPrimitiveKeyWrap, // valid in 1.7, not in 1.6
				Mode:                     "quantum-mode",
				Padding:                  cdx.CryptoPadding("oaep"), // valid: must survive
				CryptoFunctions:          &[]cdx.CryptoFunction{cdx.CryptoFunctionSign, "teleport"},
				AlgorithmFamily:          "RSA",       // 1.7 registry field
				EllipticCurve:            "secp256r1", // 1.7 registry field
				NistQuantumSecurityLevel: &level,
			},
		},
	}
	warnings := sanitize(&c)

	ap := c.CryptoProperties.AlgorithmProperties
	switch {
	case c.CryptoProperties.OID != "":
		t.Errorf("malformed OID kept: %q", c.CryptoProperties.OID)
	case ap.Primitive != "":
		t.Errorf("out-of-vocabulary primitive kept: %q", ap.Primitive)
	case ap.Mode != "":
		t.Errorf("out-of-vocabulary mode kept: %q", ap.Mode)
	case ap.Padding != "oaep":
		t.Errorf("valid padding lost: %q", ap.Padding)
	case ap.AlgorithmFamily != "" || ap.EllipticCurve != "":
		t.Errorf("1.7 registry fields kept: %q %q", ap.AlgorithmFamily, ap.EllipticCurve)
	case ap.NistQuantumSecurityLevel != nil:
		t.Error("out-of-range nistQuantumSecurityLevel kept")
	case ap.CryptoFunctions == nil || len(*ap.CryptoFunctions) != 1 || (*ap.CryptoFunctions)[0] != cdx.CryptoFunctionSign:
		t.Errorf("cryptoFunctions = %v, want only [sign]", ap.CryptoFunctions)
	}
	if len(warnings) != 7 {
		t.Errorf("got %d warnings, want 7 (one per omission): %v", len(warnings), warnings)
	}
}

func TestSanitizeFailsClosedOnUnsupportedAssetTypes(t *testing.T) {
	c := cdx.Component{
		BOMRef: "cert", Name: "cert", Type: cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeCertificate},
	}
	if w := sanitize(&c); len(w) != 1 || c.CryptoProperties != nil {
		t.Errorf("certificate asset not rejected: warnings=%v cryptoProperties=%v", w, c.CryptoProperties)
	}
}
