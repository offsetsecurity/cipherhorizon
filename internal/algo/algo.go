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

	"github.com/example/cbom-scan/internal/collector"
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

	// QuantumLevel is the NIST PQC security category (1-5) that the algorithm's
	// defining standard assigns to it, or 0 when no standard asserts one. It is
	// never inferred: 0 means "omit nistQuantumSecurityLevel".
	QuantumLevel int
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
	props := &cdx.CryptoAlgorithmProperties{Primitive: a.Primitive}
	if a.QuantumLevel != 0 {
		lvl := a.QuantumLevel
		props.NistQuantumSecurityLevel = &lvl
	}
	return cdx.Component{
		BOMRef: a.BOMRef(),
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   a.ID,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: props,
			OID:                 a.OID,
		},
	}
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
