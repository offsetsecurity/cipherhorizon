// Package collector defines CryptoAsset, the finished CycloneDX component (plus its
// edges) that the CBOM builders exchange.
//
// It used to also define the plugin contract host collectors implemented. That
// contract is now internal/sense: sensors return evidence (observations and
// coverage), never finished components, because a component that already carries a
// capability edge cannot say which parts were seen and which were inferred
// (docs/decisions/ADR-0001, ADR-0010). CryptoAsset stays because the CBOM builders
// (host projection, TLS endpoint builder) produce and consume it.
package collector

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CryptoAsset is one finding: a CycloneDX component plus the edges connecting
// it to other findings.
//
// Builders create algorithm components through the algo package rather than by
// hand, so that closed-vocabulary fields are always in-vocabulary. The same
// component (same BOMRef) may be produced more than once; the CBOM builder merges
// identical duplicates and rejects conflicting ones.
type CryptoAsset struct {
	// Component must have Type, Name and BOMRef set. BOMRef must be stable
	// across scans of an unchanged host.
	Component cdx.Component

	// Provides lists BOMRefs of assets this one makes available, e.g. a
	// library providing algorithm implementations. It expresses capability,
	// NOT observed use.
	Provides []string

	// DependsOn lists BOMRefs of assets this one relies on.
	DependsOn []string
}

// Validate checks the structural fields every asset needs. It deliberately does
// not check CycloneDX vocabularies; the cbom package owns that.
func (a CryptoAsset) Validate() error {
	switch {
	case a.Component.BOMRef == "":
		return fmt.Errorf("asset %q: empty bom-ref", a.Component.Name)
	case a.Component.Name == "":
		return fmt.Errorf("asset %q: empty name", a.Component.BOMRef)
	case a.Component.Type == "":
		return fmt.Errorf("asset %q: empty component type", a.Component.BOMRef)
	}
	return nil
}
