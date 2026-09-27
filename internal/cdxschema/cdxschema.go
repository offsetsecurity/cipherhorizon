// Package cdxschema validates CycloneDX JSON documents against the specification's own
// schemas, embedded in the binary so validation needs no network and no files.
//
// It serves the import path (PRD-003 REQ-ING-2): a third-party document is checked against
// the schema of the version it declares before anything is stored. Versions 1.6 and 1.7 are
// accepted, because earlier versions have no cryptographic assets. The schemas are the
// specification's, unmodified, with their provenance and checksums in schemas/MANIFEST.md.
package cdxschema

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// printer renders the library's messages in English.
var printer = message.NewPrinter(language.English)

//go:embed schemas/*.json
var files embed.FS

// Supported lists the specification versions a document may declare.
var Supported = []string{"1.6", "1.7"}

// resources maps each embedded file to the $id other schemas refer to it by.
var resources = map[string]string{
	"schemas/spdx.schema.json":              "http://cyclonedx.org/schema/spdx.schema.json",
	"schemas/jsf-0.82.schema.json":          "http://cyclonedx.org/schema/jsf-0.82.schema.json",
	"schemas/cryptography-defs.schema.json": "http://cyclonedx.org/schema/cryptography-defs.schema.json",
	"schemas/bom-1.6.schema.json":           "http://cyclonedx.org/schema/bom-1.6.schema.json",
	"schemas/bom-1.7.schema.json":           "http://cyclonedx.org/schema/bom-1.7.schema.json",
}

var (
	mu       sync.Mutex
	compiled = map[string]*jsonschema.Schema{}
)

// IsSupported reports whether specVersion may be imported.
func IsSupported(specVersion string) bool {
	for _, v := range Supported {
		if v == specVersion {
			return true
		}
	}
	return false
}

func compile(specVersion string) (*jsonschema.Schema, error) {
	mu.Lock()
	defer mu.Unlock()
	if s, ok := compiled[specVersion]; ok {
		return s, nil
	}
	if !IsSupported(specVersion) {
		return nil, fmt.Errorf("CycloneDX %s is not supported (supported: %s)", specVersion, strings.Join(Supported, ", "))
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	names := make([]string, 0, len(resources))
	for n := range resources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := files.ReadFile(n)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		if err := c.AddResource(resources[n], doc); err != nil {
			return nil, err
		}
	}
	s, err := c.Compile("http://cyclonedx.org/schema/bom-" + specVersion + ".schema.json")
	if err != nil {
		return nil, err
	}
	compiled[specVersion] = s
	return s, nil
}

// Problem is one reason a document is not valid, short enough to show to a person.
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Validate checks doc against the schema for specVersion. It returns at most max problems
// (the first in document order), each bounded, so a hostile document cannot make the error
// itself large. A nil result means the document is valid.
func Validate(doc []byte, specVersion string, max int) ([]Problem, error) {
	sch, err := compile(specVersion)
	if err != nil {
		return nil, err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return []Problem{{Path: "", Message: "not valid JSON: " + clip(err.Error(), 200)}}, nil
	}
	verr := sch.Validate(inst)
	if verr == nil {
		return nil, nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(verr, &ve) {
		return []Problem{{Message: clip(verr.Error(), 300)}}, nil
	}
	var out []Problem
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(out) >= max {
			return
		}
		if len(e.Causes) == 0 {
			out = append(out, Problem{Path: "/" + strings.Join(e.InstanceLocation, "/"), Message: clip(e.ErrorKind.LocalizedString(printer), 300)})
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	if len(out) == 0 {
		out = append(out, Problem{Message: "the document does not match the schema"})
	}
	return out, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// registry is the part of cryptography-defs.schema.json the program checks its tables against.
type registry struct {
	Definitions struct {
		Families struct {
			Enum []string `json:"enum"`
		} `json:"algorithmFamiliesEnum"`
		Curves struct {
			Enum []string `json:"enum"`
		} `json:"ellipticCurvesEnum"`
	} `json:"definitions"`
}

func loadRegistry() registry {
	var r registry
	b, err := files.ReadFile("schemas/cryptography-defs.schema.json")
	if err == nil {
		_ = json.Unmarshal(b, &r)
	}
	return r
}

// Families lists the algorithm families of the 1.7 cryptography registry.
func Families() []string { return loadRegistry().Definitions.Families.Enum }

// Curves lists the elliptic curve identifiers of the 1.7 cryptography registry.
func Curves() []string { return loadRegistry().Definitions.Curves.Enum }
