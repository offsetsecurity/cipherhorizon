// Package importer turns an untrusted third-party CycloneDX document into something the
// estate graph can hold, in four layers that are applied in a fixed order and tested
// separately (ENG-HANDOFF-002 D9):
//
//  1. limits: size, nesting depth, node count and string length, checked on a token stream
//     before anything is built in memory (SECARCH-001 SR-01);
//  2. schema: the document is validated against the specification's schema for the version it
//     declares, 1.6 or 1.7 (ADR-0017);
//  3. producer profile: which tool the document says made it, used only to choose how far its
//     content may be read (a label for the person, never a trust input, SR-03);
//  4. projection: observations on the imported stream (internal/estate).
//
// Nothing here decides which system a document describes. The document's own claim about its
// subject is returned so it can be shown; the operator assigns the subject (SR-04).
package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/cdxschema"
	"github.com/example/cipherhorizon/internal/estate"
)

// Limits bound what a document may make the server do.
type Limits struct {
	MaxBytes      int // total size
	MaxDepth      int // nesting of arrays and objects
	MaxNodes      int // JSON values in total
	MaxString     int // bytes in one string
	MaxComponents int // components, counting nested ones
}

// DefaultLimits are generous for real documents (the largest sample seen, a source scan of
// Keycloak, is 60 KB) and small enough that a hostile one cannot exhaust memory.
var DefaultLimits = Limits{MaxBytes: 32 << 20, MaxDepth: 64, MaxNodes: 1_000_000, MaxString: 1 << 20, MaxComponents: 200_000}

// Error is a document refusal that is safe to show to the person who uploaded it.
type Error struct {
	Stage    string // limits | format | schema
	Message  string
	Problems []cdxschema.Problem
}

func (e *Error) Error() string { return e.Stage + ": " + e.Message }

// Profile names the producer a document says made it, and how its content is read.
type Profile struct {
	ID    string
	Label string
	Kind  estate.ImportKind
}

// The profiles. Detection is by the tool names a document records; an unrecognised producer is
// Generic and is read at the weakest level.
var (
	ProfileCBOMkit  = Profile{"cbomkit", "IBM CBOMkit (source scan)", estate.ImportSource}
	ProfileCdxgen   = Profile{"cdxgen", "cdxgen (source scan)", estate.ImportSource}
	ProfileLens     = Profile{"cbom-lens", "CBOM-Lens (host and network scan)", estate.ImportHost}
	ProfileTheia    = Profile{"cbomkit-theia", "CBOMkit Theia (filesystem and image scan)", estate.ImportHost}
	ProfileOwn      = Profile{"cipherhorizon", "CipherHorizon", estate.ImportHost}
	ProfileGeneric  = Profile{"generic", "Unrecognised producer", estate.ImportGeneric}
	profileMatchers = []struct {
		needles []string
		p       Profile
	}{
		{[]string{"cipherhorizon"}, ProfileOwn},
		{[]string{"cbom-lens"}, ProfileLens},
		{[]string{"cbomkit-theia", "theia"}, ProfileTheia},
		{[]string{"sonar-cryptography", "hyperion", "cbomkit"}, ProfileCBOMkit},
		{[]string{"cdxgen"}, ProfileCdxgen},
	}
)

// Doc is a document that passed the first three layers.
type Doc struct {
	Raw         []byte
	SHA256      string
	SpecVersion string
	BOM         *cdx.BOM
	Profile     Profile
	// ToolName and ToolVersion are what the document says made it: a claim, shown and recorded.
	ToolName, ToolVersion string
	// SubjectClaim is what the document says it describes: a claim, never used for placement.
	SubjectClaim string
	Components   int
}

// CheckLimits applies only the limits layer: size, nesting depth, value count and string
// length, walking the token stream without building the document. Run it before decoding any
// untrusted JSON into a CycloneDX BOM.
func CheckLimits(raw []byte, lim Limits) error {
	if len(raw) > lim.MaxBytes {
		return &Error{Stage: "limits", Message: fmt.Sprintf("the document is %d bytes; the limit is %d", len(raw), lim.MaxBytes)}
	}
	return scan(raw, lim)
}

// Parse applies the limits, schema and profile layers.
func Parse(raw []byte, lim Limits) (*Doc, error) {
	if err := CheckLimits(raw, lim); err != nil {
		return nil, err
	}
	var head struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, &Error{Stage: "format", Message: "the document is not a JSON object"}
	}
	if head.BOMFormat != "CycloneDX" {
		return nil, &Error{Stage: "format", Message: "not a CycloneDX document (bomFormat is not CycloneDX)"}
	}
	if !cdxschema.IsSupported(head.SpecVersion) {
		msg := fmt.Sprintf("CycloneDX %q is not supported: only %s can be imported", clip(head.SpecVersion, 20), strings.Join(cdxschema.Supported, " and "))
		if head.SpecVersion == "1.5" || head.SpecVersion == "1.4" || head.SpecVersion == "1.3" {
			msg += "; versions before 1.6 have no cryptographic assets"
		}
		return nil, &Error{Stage: "format", Message: msg}
	}
	problems, err := cdxschema.Validate(raw, head.SpecVersion, 5)
	if err != nil {
		return nil, &Error{Stage: "schema", Message: clip(err.Error(), 300)}
	}
	if len(problems) > 0 {
		return nil, &Error{Stage: "schema", Message: fmt.Sprintf("the document is not valid CycloneDX %s", head.SpecVersion), Problems: problems}
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, &Error{Stage: "format", Message: "the document could not be read: " + clip(err.Error(), 200)}
	}
	n := countComponents(bom.Components)
	if n > lim.MaxComponents {
		return nil, &Error{Stage: "limits", Message: fmt.Sprintf("the document has %d components; the limit is %d", n, lim.MaxComponents)}
	}
	d := &Doc{Raw: raw, SHA256: estate.SHA256Hex(raw), SpecVersion: head.SpecVersion, BOM: &bom, Components: n}
	d.ToolName, d.ToolVersion, d.SubjectClaim = claims(&bom)
	d.Profile = detect(&bom, d.ToolName)
	return d, nil
}

func countComponents(cs *[]cdx.Component) int {
	if cs == nil {
		return 0
	}
	n := 0
	for _, c := range *cs {
		n += 1 + countComponents(c.Components)
	}
	return n
}

// scan walks the token stream and enforces depth, node count and string length without
// building the document.
func scan(raw []byte, lim Limits) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	depth, nodes := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &Error{Stage: "format", Message: "not valid JSON: " + clip(err.Error(), 120)}
		}
		nodes++
		if nodes > lim.MaxNodes {
			return &Error{Stage: "limits", Message: fmt.Sprintf("the document has more than %d values", lim.MaxNodes)}
		}
		switch t := tok.(type) {
		case json.Delim:
			if t == '{' || t == '[' {
				depth++
				if depth > lim.MaxDepth {
					return &Error{Stage: "limits", Message: fmt.Sprintf("the document is nested more than %d levels deep", lim.MaxDepth)}
				}
			} else {
				depth--
			}
		case string:
			if len(t) > lim.MaxString {
				return &Error{Stage: "limits", Message: fmt.Sprintf("a string in the document is longer than %d bytes", lim.MaxString)}
			}
		}
	}
	if depth != 0 {
		return &Error{Stage: "format", Message: "not valid JSON: unbalanced brackets"}
	}
	return nil
}

// claims reads what the document says about its producer and its subject.
func claims(bom *cdx.BOM) (tool, version, subject string) {
	if bom.Metadata == nil {
		return "", "", ""
	}
	if t := bom.Metadata.Tools; t != nil {
		switch {
		case t.Components != nil && len(*t.Components) > 0:
			c := (*t.Components)[0]
			tool, version = c.Name, c.Version
		case t.Services != nil && len(*t.Services) > 0:
			s := (*t.Services)[0]
			tool, version = s.Name, s.Version
		}
	}
	if c := bom.Metadata.Component; c != nil {
		subject = c.Name
		if tool == "" {
			// CBOM-Lens names itself as the metadata component; that is the tool, not the subject,
			// and the operator decides the subject either way.
			tool = c.Name
			version = c.Version
		}
	}
	return clean(tool, 100), clean(version, 50), clean(subject, 200)
}

func detect(bom *cdx.BOM, tool string) Profile {
	hay := strings.ToLower(tool)
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		hay += " " + strings.ToLower(bom.Metadata.Component.Name)
	}
	if bom.Metadata != nil && bom.Metadata.Tools != nil && bom.Metadata.Tools.Components != nil {
		for _, c := range *bom.Metadata.Tools.Components {
			hay += " " + strings.ToLower(c.Name)
		}
	}
	for _, m := range profileMatchers {
		for _, n := range m.needles {
			if strings.Contains(hay, n) {
				return m.p
			}
		}
	}
	// CBOMkit's source scans record where the code came from rather than a tool name.
	if bom.Metadata != nil && bom.Metadata.Properties != nil {
		names := map[string]bool{}
		for _, p := range *bom.Metadata.Properties {
			names[p.Name] = true
		}
		if names["gitUrl"] && names["revision"] {
			return ProfileCBOMkit
		}
	}
	return ProfileGeneric
}

func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(strings.TrimSpace(s), "?") {
		if b.Len()+4 > n {
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func clip(s string, n int) string {
	return clean(s, n)
}

// Project is layer four: the observations an import contributes.
func (d *Doc) Project() estate.Result { return estate.FromImportedCBOM(d.BOM, d.Profile.Kind) }
