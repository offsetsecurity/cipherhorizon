// Package schematest validates JSON documents against the CycloneDX 1.6 schema
// vendored under testing/schema. It is test support only: nothing in the
// shipped binary imports it.
package schematest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const bomSchemaID = "http://cyclonedx.org/schema/bom-1.6.schema.json"

// schemaFiles maps each vendored file to the $id other schemas reference it by.
var schemaFiles = map[string]string{
	"bom-1.6.schema.json":   bomSchemaID,
	"spdx.schema.json":      "http://cyclonedx.org/schema/spdx.schema.json",
	"jsf-0.82.schemax.json": "http://cyclonedx.org/schema/jsf-0.82.schema.json",
}

// SchemaDir returns the directory holding the vendored schemas, independent of
// the test's working directory.
func SchemaDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testing", "schema")
}

// Validate fails t if doc is not a valid CycloneDX 1.6 JSON document.
func Validate(t testing.TB, doc []byte) {
	t.Helper()
	if err := ValidateErr(doc); err != nil {
		t.Errorf("document is not valid CycloneDX 1.6:\n%v", err)
	}
}

// ValidateErr is Validate for callers that want the error.
func ValidateErr(doc []byte) error {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for file, id := range schemaFiles {
		f, err := os.Open(filepath.Join(SchemaDir(), file))
		if err != nil {
			return err
		}
		schemaDoc, err := jsonschema.UnmarshalJSON(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		if err := c.AddResource(id, schemaDoc); err != nil {
			return err
		}
	}
	sch, err := c.Compile(bomSchemaID)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}
