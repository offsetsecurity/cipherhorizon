// Package algo is the catalogue of cryptographic algorithms the program is
// allowed to put in a CBOM: a total lookup table from a canonical algorithm ID
// to its CycloneDX representation.
//
// CycloneDX enumerations are closed, and a single out-of-vocabulary value
// invalidates the whole document. So plugins never hand-write algorithm
// components: they ask this package for one by ID. An algorithm that is not in
// the catalogue cannot be emitted, and every field that has no authoritative
// source for an entry is left unset (and therefore omitted from the output).
package algo

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/collector"
)

// Algorithm is one catalogue entry.
type Algorithm struct {
	// ID is the canonical name; it becomes the component name, e.g. "ML-KEM-768".
	ID string

	// Primitive is the CycloneDX cryptographic primitive.
	Primitive cdx.CryptoPrimitive

	// OID is the dotted object identifier, or "" when no single authoritative
	// OID identifies this algorithm (e.g. ECDSA and AES have none of their own).
	OID string

	// ParameterSet is the CycloneDX parameterSetIdentifier: the key or parameter
	// size that distinguishes one variant of a family from another ("128" for
	// AES-128-GCM). Empty for an entry that is a whole family.
	ParameterSet string

	// Mode is the block-cipher / AEAD mode of operation, when the entry names one.
	Mode cdx.CryptoAlgorithmMode

	// QuantumLevel is the NIST PQC security category (1-5) that the algorithm's
	// defining standard assigns to it, or 0 when no standard asserts one. It is
	// never inferred: 0 means "omit nistQuantumSecurityLevel".
	QuantumLevel int

	// NoPQCVerdict, when set, is the reason this algorithm is deliberately given no
	// post-quantum verdict (the question is not a quantum one, or no citation supports
	// one). Every other algorithm MUST match a rule in internal/pqc, and a test enforces
	// both directions, so forgetting a verdict fails and choosing none is written down.
	NoPQCVerdict string

	// Legacy, when set, says the algorithm is retired or broken for CLASSICAL
	// reasons, with the source. It is separate from the post-quantum verdict: a broken
	// hash is not "quantum-vulnerable", it is unsafe against today's computers.
	Legacy *Legacy
}

// Legacy is a cited statement that an algorithm is retired or broken, with the
// citation. Only what the cited source itself says may be put in Summary.
type Legacy struct {
	Summary  string
	Citation string // title of the source
	URL      string
}

// BOMRef returns the stable bom-ref of the algorithm component. It follows the
// CycloneDX CBOM convention crypto/algorithm/<name>[@<oid>].
func (a Algorithm) BOMRef() string {
	ref := "crypto/algorithm/" + strings.ToLower(a.ID)
	if a.OID != "" {
		ref += "@" + a.OID
	}
	return ref
}

// Component renders the algorithm as a CycloneDX cryptographic-asset component.
func (a Algorithm) Component() cdx.Component {
	props := &cdx.CryptoAlgorithmProperties{Primitive: a.Primitive, ParameterSetIdentifier: a.ParameterSet, Mode: a.Mode}
	if a.QuantumLevel != 0 {
		lvl := a.QuantumLevel
		props.NistQuantumSecurityLevel = &lvl
	}
	c := cdx.Component{
		BOMRef: a.BOMRef(),
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   a.ID,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: props,
			OID:                 a.OID,
		},
	}
	// The namespace is written out because this package sits below cbom, which owns it.
	var props2 []cdx.Property
	if a.Legacy != nil {
		props2 = append(props2,
			cdx.Property{Name: "cipherhorizon:classical-status", Value: a.Legacy.Summary},
			cdx.Property{Name: "cipherhorizon:classical-basis", Value: a.Legacy.Citation + " (" + a.Legacy.URL + ")"})
	}
	if a.NoPQCVerdict != "" {
		props2 = append(props2, cdx.Property{Name: "cipherhorizon:pqc:unclassified-reason", Value: a.NoPQCVerdict})
	}
	if len(props2) > 0 {
		c.Properties = &props2
	}
	return c
}

// Asset renders the algorithm as a finding a collector can return.
func (a Algorithm) Asset() collector.CryptoAsset {
	return collector.CryptoAsset{Component: a.Component()}
}

var byID = func() map[string]Algorithm {
	m := make(map[string]Algorithm, len(catalogue))
	for _, a := range catalogue {
		if _, dup := m[a.ID]; dup {
			panic("algo: duplicate catalogue ID " + a.ID)
		}
		m[a.ID] = a
	}
	return m
}()

// Lookup returns the catalogue entry for id.
func Lookup(id string) (Algorithm, bool) {
	a, ok := byID[id]
	return a, ok
}

// MustGet is Lookup for IDs that are compile-time constants in plugin tables;
// an unknown ID is a programming error.
func MustGet(id string) Algorithm {
	a, ok := Lookup(id)
	if !ok {
		panic(fmt.Sprintf("algo: %q is not in the catalogue", id))
	}
	return a
}

// All returns every catalogue entry, sorted by ID.
func All() []Algorithm {
	out := make([]Algorithm, 0, len(catalogue))
	out = append(out, catalogue...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
