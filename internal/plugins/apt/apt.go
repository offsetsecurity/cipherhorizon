// Package apt is the collector for Debian-family hosts (Debian, Ubuntu and
// derivatives). It reads the dpkg database directly, in pure Go, so it needs no
// subprocess, no root, and works unchanged against a host filesystem mounted
// into a container.
package apt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/collector"
)

const (
	// Name is the plugin's registry name.
	Name = "apt"

	// PluginVersion is the version of this plugin's rules and behaviour.
	PluginVersion = "0.1.0"

	statusPath = "var/lib/dpkg/status" // fs.FS-style: unrooted
	statusLoc  = "/var/lib/dpkg/status"
)

func init() {
	collector.Register(Name, func(h collector.Host) (collector.Collector, error) {
		if h.FS == nil {
			return nil, errors.New("apt: host filesystem is nil")
		}
		return New(h.FS), nil
	})
}

// Collector implements collector.Collector for dpkg-managed hosts.
type Collector struct {
	fsys fs.FS
}

var _ collector.Collector = (*Collector)(nil)

// New returns an apt collector reading the host filesystem fsys.
func New(fsys fs.FS) *Collector { return &Collector{fsys: fsys} }

// Metadata implements collector.Collector.
func (*Collector) Metadata() collector.PluginInfo {
	return collector.PluginInfo{Name: Name, Version: PluginVersion, SourceType: collector.SourceOSPackage}
}

// Detect reports whether a dpkg database exists on the host.
func (c *Collector) Detect(context.Context) (bool, error) {
	_, err := fs.Stat(c.fsys, statusPath)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("apt: probing %s: %w", statusLoc, err)
	}
}

// Collect inventories installed crypto packages. Each becomes a library or
// application component; families with a curated capability mapping also get
// `provides` edges to algorithm assets.
func (c *Collector) Collect(ctx context.Context) ([]collector.CryptoAsset, error) {
	f, err := c.fsys.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("apt: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only

	osr := readOSRelease(c.fsys)

	var (
		assets []collector.CryptoAsset
		algos  = map[string]struct{}{}
	)
	parseErr := parseStatus(ctx, f, func(p pkg) {
		if !p.installed() {
			return
		}
		r := match(p.Name)
		if r == nil {
			return
		}
		asset, ids := assetFor(p, r, osr)
		assets = append(assets, asset)
		for _, id := range ids {
			algos[id] = struct{}{}
		}
	})

	ids := make([]string, 0, len(algos))
	for id := range algos {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		assets = append(assets, algo.MustGet(id).Asset())
	}

	if parseErr != nil {
		// Everything parsed before the failure is kept; the error marks it incomplete.
		return assets, fmt.Errorf("apt: reading %s: %w", statusLoc, parseErr)
	}
	return assets, nil
}

// assetFor builds the component for one installed package and returns the
// catalogue IDs of the algorithms it provides.
func assetFor(p pkg, r *rule, osr osRelease) (collector.CryptoAsset, []string) {
	purl := purlFor(p, osr)
	ref := purl
	if ref == "" {
		ref = fmt.Sprintf("apt/%s@%s/%s", p.Name, p.Version, p.Arch)
	}

	comp := cdx.Component{
		BOMRef:     ref,
		Type:       r.typeFor(p.Name),
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: purl,
		Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: statusLoc},
		}},
	}
	props := []cdx.Property{
		cbom.Property("collector", Name),
		cbom.Property("package-family", r.family),
	}

	ids := capabilitiesFor(r, p.Version)
	var provides []string
	if len(ids) > 0 {
		// Capability, not observed use: see the rule type's documentation.
		props = append(props, cbom.Property("evidence", "installed-package-capability"))
		for _, b := range r.basis {
			props = append(props, cbom.Property("capability-basis", b))
		}
		for _, id := range ids {
			provides = append(provides, algo.MustGet(id).BOMRef())
		}
	}
	comp.Properties = &props

	return collector.CryptoAsset{Component: comp, Provides: provides}, ids
}

// capabilitiesFor returns the algorithm IDs a package at debVersion provides.
// Gated capabilities need a parseable version; if it cannot be read they are
// omitted, never assumed.
func capabilitiesFor(r *rule, debVersion string) []string {
	v, known := upstream(debVersion)
	var ids []string
	for _, c := range r.caps {
		if c.min != (version{}) && (!known || !v.atLeast(c.min)) {
			continue
		}
		ids = append(ids, c.algos...)
	}
	return ids
}

// purlFor builds a Package URL for a Debian package, or "" when the vendor
// cannot be established (the purl deb type requires one).
func purlFor(p pkg, osr osRelease) string {
	if osr.ID == "" || p.Version == "" {
		return ""
	}
	q := map[string]string{}
	if p.Arch != "" {
		q["arch"] = p.Arch
	}
	if osr.VersionID != "" {
		q["distro"] = osr.ID + "-" + osr.VersionID
	}
	return packageurl.NewPackageURL(packageurl.TypeDebian, osr.ID, p.Name, p.Version,
		packageurl.QualifiersFromMap(q), "").ToString()
}
