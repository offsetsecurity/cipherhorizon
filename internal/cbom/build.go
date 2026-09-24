// Package cbom assembles collector findings into a CycloneDX 1.6 CBOM.
//
// It builds on github.com/CycloneDX/cyclonedx-go rather than hand-rolling the
// document model, and adds what the SDK does not provide: closed-vocabulary
// enforcement, de-duplication and edge integrity, and deterministic output.
package cbom

import (
	"crypto/rand"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/collector"
)

// SpecVersion is the CycloneDX version emitted. 1.7 is a later, opt-in step.
const SpecVersion = cdx.SpecVersion1_6

// PropertyNamespace prefixes every custom property this program adds, as the
// CycloneDX property taxonomy asks of non-CycloneDX property names.
const PropertyNamespace = "cipherhorizon"

// Property returns a namespaced custom property, e.g. Property("collector","apt").
func Property(name, value string) cdx.Property {
	return cdx.Property{Name: PropertyNamespace + ":" + name, Value: value}
}

// Tool identifies this program in the CBOM's metadata.
type Tool struct {
	Name    string
	Version string
}

// Options configures Build. The zero value is usable.
type Options struct {
	Tool Tool

	// The CBOM's subject: set exactly one, or neither for a document with no
	// metadata.component. HostName is a host inventory's subject (bom-ref
	// "host:<name>", type device). Endpoint is a TLS scan's subject, "host:port"
	// (bom-ref "endpoint:<host:port>", type device: a network endpoint, not
	// necessarily the machine running this program).
	HostName string
	Endpoint string

	// MetadataProperties are extra namespaced properties written on metadata: what
	// the run was allowed to see, the privilege it ran with, and what it could not see.
	MetadataProperties []cdx.Property

	// Now and NewSerial exist so tests can make output byte-for-byte reproducible.
	Now       func() time.Time
	NewSerial func() string // must return a "urn:uuid:..." value
}

// Build assembles assets into a BOM. Problems with individual assets never fail
// the build: the offending asset (or field, or edge) is omitted and reported in
// the returned warnings, so one bad plugin cannot take down an inventory.
//
// Output is deterministic for a given input: components are sorted by bom-ref,
// as are all edges.
func Build(assets []collector.CryptoAsset, opts Options) (*cdx.BOM, []string) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewSerial == nil {
		opts.NewSerial = randomSerial
	}

	var warnings []string
	components := map[string]cdx.Component{}
	provides := map[string]map[string]struct{}{}
	dependsOn := map[string]map[string]struct{}{}

	for _, a := range assets {
		if err := a.Validate(); err != nil {
			warnings = append(warnings, err.Error()+"; asset skipped")
			continue
		}
		c := a.Component
		warnings = append(warnings, sanitize(&c)...)

		ref := c.BOMRef
		if prev, seen := components[ref]; seen {
			if !reflect.DeepEqual(prev, c) {
				warnings = append(warnings, fmt.Sprintf("%s: conflicting duplicate component; first one kept", ref))
				continue
			}
		} else {
			components[ref] = c
		}
		addEdges(provides, ref, a.Provides)
		addEdges(dependsOn, ref, a.DependsOn)
	}

	provides, w := pruneDangling(provides, "provides", components)
	warnings = append(warnings, w...)
	dependsOn, w = pruneDangling(dependsOn, "dependsOn", components)
	warnings = append(warnings, w...)

	// An endpoint CBOM says where the cryptography is used: the endpoint itself
	// depends on the protocols it serves and the certificates it presents, and
	// everything else hangs below those.
	if opts.Endpoint != "" {
		used := map[string]bool{}
		for _, targets := range dependsOn {
			for t := range targets {
				used[t] = true
			}
		}
		var roots []string
		for ref, c := range components {
			if used[ref] || c.CryptoProperties == nil {
				continue
			}
			if at := c.CryptoProperties.AssetType; at == cdx.CryptoAssetTypeProtocol || at == cdx.CryptoAssetTypeCertificate {
				roots = append(roots, ref)
			}
		}
		addEdges(dependsOn, "endpoint:"+opts.Endpoint, roots)
	}

	bom := cdx.NewBOM()
	bom.SerialNumber = opts.NewSerial()
	bom.Metadata = metadata(opts)
	if len(opts.MetadataProperties) > 0 {
		props := append([]cdx.Property(nil), opts.MetadataProperties...)
		if bom.Metadata.Properties != nil {
			props = append(*bom.Metadata.Properties, props...)
		}
		bom.Metadata.Properties = &props
	}

	refs := sortedKeys(components)
	if len(refs) > 0 {
		cs := make([]cdx.Component, len(refs))
		for i, r := range refs {
			cs[i] = components[r]
		}
		bom.Components = &cs
	}

	var deps []cdx.Dependency
	for _, ref := range sortedUnion(provides, dependsOn) {
		d := cdx.Dependency{Ref: ref}
		if s := sortedKeys(dependsOn[ref]); len(s) > 0 {
			d.Dependencies = &s
		}
		if s := sortedKeys(provides[ref]); len(s) > 0 {
			d.Provides = &s
		}
		deps = append(deps, d)
	}
	if len(deps) > 0 {
		bom.Dependencies = &deps
	}
	return bom, warnings
}

// schemaURL is the JSON Schema id CycloneDX 1.6 documents declare in "$schema".
const schemaURL = "http://cyclonedx.org/schema/bom-1.6.schema.json"

// Encode writes bom as CycloneDX 1.6 JSON.
//
// It deliberately uses the SDK's plain Encode, not EncodeVersion. As of
// cyclonedx-go v0.12.0, EncodeVersion's downgrade pass does not know the
// "cryptographic-asset" component type in ANY spec version, and silently
// rewrites every crypto component to "application": schema-valid, but no longer
// a CBOM. Skipping the pass is safe here because Build targets 1.6 natively:
// vocab.go already omits the 1.7-only crypto fields, and the schema-validation
// tests would fail on any other 1.7-only field. TestEncodeKeepsCryptographicAssetType
// guards this; revisit when the SDK is fixed.
func Encode(w io.Writer, bom *cdx.BOM, pretty bool) error {
	out := *bom // do not mutate the caller's BOM
	out.SpecVersion = SpecVersion
	out.JSONSchema = schemaURL
	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(pretty).SetEscapeHTML(false).Encode(&out)
}

func metadata(opts Options) *cdx.Metadata {
	m := &cdx.Metadata{
		Timestamp:  opts.Now().UTC().Format(time.RFC3339),
		Lifecycles: &[]cdx.Lifecycle{{Phase: cdx.LifecyclePhaseOperations}},
	}
	if opts.Tool.Name != "" {
		m.Tools = &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type:    cdx.ComponentTypeApplication,
			Name:    opts.Tool.Name,
			Version: opts.Tool.Version,
		}}}
	}
	switch {
	case opts.HostName != "":
		m.Component = &cdx.Component{
			BOMRef: "host:" + opts.HostName,
			Type:   cdx.ComponentTypeDevice,
			Name:   opts.HostName,
		}
	case opts.Endpoint != "":
		m.Component = &cdx.Component{
			BOMRef: "endpoint:" + opts.Endpoint,
			Type:   cdx.ComponentTypeDevice,
			Name:   opts.Endpoint,
		}
		// State once, in the document, what the graph's edges and flags mean, since
		// a reader cannot tell from the edges alone whether the endpoint uses a
		// thing or merely accepts it.
		m.Properties = &[]cdx.Property{Property("tls-graph",
			"Edges below a protocol list what the endpoint accepts, as observed by enumerating it. "+
				"Components flagged cipherhorizon:negotiated=true are what a current Go TLS client actually "+
				"negotiated in one handshake: nothing else is claimed to be in use.")}
	}
	return m
}

func addEdges(dst map[string]map[string]struct{}, from string, to []string) {
	if len(to) == 0 {
		return
	}
	if dst[from] == nil {
		dst[from] = map[string]struct{}{}
	}
	for _, t := range to {
		dst[from][t] = struct{}{}
	}
}

// pruneDangling drops edges whose target is not a component, so the emitted
// dependency graph never references something absent from the document.
func pruneDangling(edges map[string]map[string]struct{}, kind string, components map[string]cdx.Component) (map[string]map[string]struct{}, []string) {
	var warnings []string
	out := map[string]map[string]struct{}{}
	for from, targets := range edges {
		if _, ok := components[from]; !ok {
			continue // its asset was skipped
		}
		for _, t := range sortedKeys(targets) {
			if _, ok := components[t]; !ok {
				warnings = append(warnings, fmt.Sprintf("%s: %s target %q is not in the CBOM; edge dropped", from, kind, t))
				continue
			}
			addEdges(out, from, []string{t})
		}
	}
	return out, warnings
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedUnion(a, b map[string]map[string]struct{}) []string {
	seen := map[string]struct{}{}
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	return sortedKeys(seen)
}

// randomSerial returns a random (version 4) UUID as a "urn:uuid:..." value: the CycloneDX
// serial number. It uses crypto/rand directly rather than a UUID library, because the usual
// one links the network package (to read MAC addresses) into a program that must not have it.
func randomSerial() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("cbom: no randomness available: " + err.Error()) // crypto/rand does not fail on supported platforms
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
