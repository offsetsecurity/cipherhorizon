// Package collector defines the contract every cryptographic-asset collector
// (plugin) implements, and the registry plugins self-register into.
//
// The core of the program knows only this package. It never contains
// collector logic: an apt collector, a JVM-provider collector and a
// certificate-store collector are all just Collector values.
package collector

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Collector inventories one ecosystem (a package manager, a language runtime,
// a crypto provider, a certificate store, ...) on the local host.
//
// One-shot CLI mode and daemon/timer mode drive collectors through exactly the
// same calls; only the trigger differs. Implementations must:
//
//   - be read-only: never modify the host;
//   - honour ctx cancellation, since a daemon must be able to bound a scan;
//   - be repeatable: Detect and Collect may be called many times on one value;
//   - not assume concurrent use. The runner calls a Collector sequentially.
type Collector interface {
	// Metadata identifies the plugin. It must be cheap, side-effect free and
	// return the same value every time.
	Metadata() PluginInfo

	// Detect reports whether this ecosystem is present on the host.
	//
	//	(true,  nil)  present: Collect will be called.
	//	(false, nil)  absent: the plugin is skipped silently. This is the normal
	//	              outcome of e.g. the apt plugin running on an RPM host.
	//	(false, err)  presence could not be determined; recorded as a failure.
	Detect(ctx context.Context) (bool, error)

	// Collect returns the findings, in CycloneDX component shape.
	//
	// A non-nil error means the inventory is INCOMPLETE. Any assets returned
	// alongside the error are still valid and are kept, so that a partial
	// inventory beats none; the error is reported per plugin rather than
	// silently dropped. Order is not significant; the core sorts.
	Collect(ctx context.Context) ([]CryptoAsset, error)
}

// SourceType classifies what kind of ecosystem a plugin reads.
type SourceType string

// The source types. Add a value here only together with a plugin that needs it.
const (
	SourceOSPackage SourceType = "os-package" // apt, rpm, apk, ...
	SourceRuntime   SourceType = "runtime"    // language runtimes and their package managers
	SourceProvider  SourceType = "provider"   // crypto providers, e.g. JVM security providers
	SourceCertStore SourceType = "cert-store" // certificate and key stores
)

// Valid reports whether s is a known source type.
func (s SourceType) Valid() bool {
	switch s {
	case SourceOSPackage, SourceRuntime, SourceProvider, SourceCertStore:
		return true
	}
	return false
}

// PluginInfo describes a plugin.
type PluginInfo struct {
	// Name is the registry key and the name used in configuration: lowercase
	// kebab-case, e.g. "apt".
	Name string
	// Version is the plugin's own version (semver).
	Version string
	// SourceType is the kind of ecosystem the plugin reads.
	SourceType SourceType
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// Validate reports whether the info is well formed.
func (p PluginInfo) Validate() error {
	if !nameRE.MatchString(p.Name) {
		return fmt.Errorf("plugin name %q must be lowercase kebab-case", p.Name)
	}
	if p.Version == "" {
		return fmt.Errorf("plugin %q: version is empty", p.Name)
	}
	if !p.SourceType.Valid() {
		return fmt.Errorf("plugin %q: unknown source type %q", p.Name, p.SourceType)
	}
	return nil
}

// CryptoAsset is one finding: a CycloneDX component plus the edges connecting
// it to other findings.
//
// Plugins build algorithm components through the algo package rather than by
// hand, so that closed-vocabulary fields are always in-vocabulary. The same
// component (same BOMRef) may be emitted by several plugins; the CBOM builder
// merges identical duplicates and rejects conflicting ones.
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

// Host describes the machine being inventoried.
type Host struct {
	// FS is the host's root filesystem, addressed with unrooted slash-separated
	// paths ("var/lib/dpkg/status"). Natively it is os.DirFS("/"); in a
	// container with the host mounted at /host it is os.DirFS("/host"); in tests
	// it is an fstest.MapFS. Plugins must read the host only through it.
	FS fs.FS
}

// Factory constructs a Collector for a host. Constructors must be cheap and
// side-effect free: all I/O belongs in Detect and Collect.
type Factory func(Host) (Collector, error)
