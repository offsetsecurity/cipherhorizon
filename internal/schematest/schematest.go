// Package schematest validates CycloneDX JSON documents against the specification's
// schema for the version the document declares (1.6 or 1.7), using the schemas embedded
// in internal/cdxschema. It is test support only: nothing in the shipped binary imports it.
package schematest

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/example/cipherhorizon/internal/cdxschema"
)

// Validate fails t if doc is not a valid CycloneDX JSON document of the version it declares.
func Validate(t testing.TB, doc []byte) {
	t.Helper()
	if err := ValidateErr(doc); err != nil {
		t.Errorf("document is not valid CycloneDX:\n%v", err)
	}
}

// ValidateErr is Validate for callers that want the error.
func ValidateErr(doc []byte) error {
	var head struct {
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(doc, &head); err != nil {
		return err
	}
	if head.SpecVersion == "" {
		head.SpecVersion = "1.6"
	}
	problems, err := cdxschema.Validate(doc, head.SpecVersion, 10)
	if err != nil {
		return err
	}
	if len(problems) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "not valid CycloneDX %s:", head.SpecVersion)
	for _, p := range problems {
		fmt.Fprintf(&b, "\n  at %s: %s", p.Path, p.Message)
	}
	return fmt.Errorf("%s", b.String())
}

// SchemaDir returns the directory holding the vendored 1.6 schema used to pin the closed
// vocabularies in code (internal/cbom/vocab_test.go), independent of the test's working directory.
func SchemaDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testing", "schema")
}
