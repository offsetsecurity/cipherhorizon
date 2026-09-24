package cbom

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/collector"
	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/knowledge"
)

// HostOptions carries what the projection cannot read from the graph.
type HostOptions struct {
	// PrivilegeNote is the warning shown when the run had less than the highest
	// privilege tier ("results may be incomplete; Administrator/root may reveal
	// more"). It is written into the document so a reader sees it too (ADR-0009).
	PrivilegeNote string
}

// FromHostGraph projects a host's evidence graph into CBOM assets and metadata
// properties. It is a projection, not a store: it contains nothing the graph does
// not, and it refuses to project a graph that breaks the contract. In particular
// every `provides` edge it writes comes from a derived, cited `capable (mapped)`
// fact, and the component carries the claim so a consumer cannot mistake "can
// provide" for "uses" (CycloneDX's own guide: "a component that implements another
// component does not imply that the implementation is in use").
func FromHostGraph(g *evidence.Graph, opts HostOptions) ([]collector.CryptoAsset, []cdx.Property, error) {
	if err := g.Check(); err != nil {
		return nil, nil, fmt.Errorf("cbom: refusing to project an invalid evidence graph: %w", err)
	}

	// algorithm ID -> providers, and provider key -> algorithm IDs, from derived facts.
	provides := map[string][]string{}
	citations := map[string][]string{} // in the knowledge table's order, which is the order readers see
	algosUsed := map[string]bool{}
	for _, n := range g.Nodes() {
		if n.Subject.Kind != evidence.KindAlgorithm {
			continue
		}
		for _, o := range n.Derived() {
			if o.Claim.Rung != evidence.RungCapable {
				continue
			}
			if o.Knowledge == nil || len(o.Relations) == 0 {
				return nil, nil, fmt.Errorf("cbom: derived capability %s has no knowledge reference or provider", o.ID)
			}
			for _, r := range o.Relations {
				if r.Kind != "provided-by" {
					continue
				}
				provides[r.To] = append(provides[r.To], n.Subject.Name)
				algosUsed[n.Subject.Name] = true
				if len(citations[r.To]) == 0 {
					citations[r.To] = o.Knowledge.Citations
				}
			}
		}
	}

	var assets []collector.CryptoAsset
	for _, n := range g.Nodes() {
		if n.Subject.Kind != evidence.KindPackage && n.Subject.Kind != evidence.KindArtefact {
			continue
		}
		if len(n.Present()) == 0 {
			continue
		}
		asset, err := hostComponent(g, n, provides[n.Subject.Key], citations[n.Subject.Key])
		if err != nil {
			return nil, nil, err
		}
		assets = append(assets, asset)
	}

	ids := make([]string, 0, len(algosUsed))
	for id := range algosUsed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a, ok := algo.Lookup(id)
		if !ok {
			return nil, nil, fmt.Errorf("cbom: derived capability names %q, which is not in the algorithm catalogue", id)
		}
		assets = append(assets, a.Asset())
	}
	return assets, hostMetadata(g, opts), nil
}

func hostComponent(g *evidence.Graph, n *evidence.Node, algos []string, cites []string) (collector.CryptoAsset, error) {
	present := n.Present()
	best, bestQuality := present[0], evidence.Quality("")
	for _, o := range present {
		q, err := evidence.QualityOf(*o)
		if err != nil {
			return collector.CryptoAsset{}, fmt.Errorf("cbom: %w", err)
		}
		if bestQuality == "" || rankQuality(q) > rankQuality(bestQuality) {
			best, bestQuality = o, q
		}
	}
	method, _ := evidence.LookupMethod(best.Method)

	s := n.Subject
	ctype := cdx.ComponentTypeLibrary
	if s.Attrs["kind"] == knowledge.KindApplication {
		ctype = cdx.ComponentTypeApplication
	}
	comp := cdx.Component{BOMRef: s.Key, Type: ctype, Name: s.Name}
	if s.Kind == evidence.KindPackage {
		comp.Name = s.Attrs["name"]
		comp.Version = s.Attrs["version"]
		if strings.HasPrefix(s.Key, "pkg:") {
			comp.PackageURL = s.Key
		}
	} else {
		comp.Version = s.Attrs["fileVersion"]
	}

	// Where it was found, and by which methods (a closed technique list).
	seenLoc := map[string]bool{}
	var locations []string
	methodIDs := map[string]bool{}
	for _, o := range present {
		loc := o.Source.Location
		if g.Host.OSFamily != "windows" {
			loc = "/" + loc // host-relative paths on Unix are absolute from the host root
		}
		if !seenLoc[loc] {
			seenLoc[loc] = true
			locations = append(locations, loc)
		}
		methodIDs[o.Method] = true
	}
	sort.Strings(locations)
	occ := make([]cdx.EvidenceOccurrence, len(locations))
	for i, l := range locations {
		occ[i] = cdx.EvidenceOccurrence{Location: l}
	}
	comp.Evidence = &cdx.Evidence{Occurrences: &occ, Identity: identityEvidence(s, methodIDs)}

	props := []cdx.Property{
		Property("collector", method.Sensor),
		Property("package-family", s.Attrs["family"]),
	}
	if len(algos) > 0 {
		// Capability, not observed use: see the claim properties below.
		if s.Kind == evidence.KindPackage {
			props = append(props, Property("evidence", "installed-package-capability"))
		} else {
			props = append(props, Property("evidence", "file-capability"))
		}
		for _, b := range cites {
			props = append(props, Property("capability-basis", b))
		}
	}
	// Where the version came from. A file's version is what the file claims (its
	// version resource): for a library bundled inside an application it can be the
	// application's version, not the library's, so a reader must be able to tell.
	if comp.Version != "" {
		if s.Kind == evidence.KindPackage {
			props = append(props, Property("version-source", "package-database"))
		} else {
			props = append(props, Property("version-source", "file-version-resource"))
		}
	}
	props = append(props,
		Property("claim", string(evidence.RungPresent)),
		Property("method", best.Method),
		Property("method-quality", string(bestQuality)),
		Property("privilege", best.Privilege),
	)
	if len(algos) > 0 {
		// The provides edges below are a mapped capability, never observed use.
		props = append(props, Property("provides-claim", "capable-mapped"))
	}
	if s.Kind == evidence.KindArtefact {
		if v := s.Attrs["productName"]; v != "" {
			props = append(props, Property("product-name", v))
		}
		if v := s.Attrs["arch"]; v != "" {
			props = append(props, Property("file-arch", v))
		}
		if v := s.Attrs["peValid"]; v != "" {
			props = append(props, Property("pe-valid", v))
		}
	}
	comp.Properties = &props

	var provRefs []string
	for _, id := range algos {
		a, ok := algo.Lookup(id)
		if !ok {
			return collector.CryptoAsset{}, fmt.Errorf("cbom: %s provides %q, which is not in the algorithm catalogue", s.Key, id)
		}
		provRefs = append(provRefs, a.BOMRef())
	}
	sort.Strings(provRefs)
	return collector.CryptoAsset{Component: comp, Provides: provRefs}, nil
}

func rankQuality(q evidence.Quality) int {
	switch q {
	case evidence.QualityAuthoritative:
		return 3
	case evidence.QualityParsed:
		return 2
	case evidence.QualityHeuristic:
		return 1
	}
	return 0
}

// identityEvidence records how the component was identified, in CycloneDX's closed
// technique list. CycloneDX 1.6 requires a numeric confidence on every identity
// method, and only an authoritative method has a value we can honestly give (1.0);
// nothing else has been calibrated (ADR-0002). So the block is written for the
// authoritative methods only, and the component's method and quality properties
// carry the rest. The result is nil when no authoritative method found it.
func identityEvidence(s evidence.Subject, methodIDs map[string]bool) *cdx.EvidenceIdentityChoice {
	ids := make([]string, 0, len(methodIDs))
	for id := range methodIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var methods []cdx.EvidenceIdentityMethod
	for _, id := range ids {
		m, ok := evidence.LookupMethod(id)
		if !ok || m.Quality != evidence.QualityAuthoritative {
			continue
		}
		one := float32(1.0)
		methods = append(methods, cdx.EvidenceIdentityMethod{Technique: cdx.EvidenceIdentityTechnique(m.Technique), Value: m.ID, Confidence: &one})
	}
	if len(methods) == 0 {
		return nil
	}
	field := cdx.EvidenceIdentityFieldTypeName
	if strings.HasPrefix(s.Key, "pkg:") {
		field = cdx.EvidenceIdentityFieldTypePURL
	}
	return &cdx.EvidenceIdentityChoice{Identities: &[]cdx.EvidenceIdentity{{Field: field, Methods: &methods}}}
}

// hostMetadata is what the document says about the run itself: the privilege it
// had, what each sensor covered, and what none of them could see. Blind spots are
// data, not a footnote (ADR-0008).
func hostMetadata(g *evidence.Graph, opts HostOptions) []cdx.Property {
	var props []cdx.Property
	h := g.Host
	if h.PrivilegeTier != "" {
		props = append(props, Property("privilege-tier", h.PrivilegeTier))
	}
	if h.OSFamily != "" {
		props = append(props, Property("host-os", strings.TrimSpace(h.OSFamily+" "+h.OSVersion)))
	}
	if h.ID != "" {
		props = append(props, Property("host-id", h.ID))
	}
	if opts.PrivilegeNote != "" {
		props = append(props, Property("coverage-note", opts.PrivilegeNote))
	}
	seen := map[string]bool{}
	var unseen []string
	for _, c := range g.Coverage {
		v := fmt.Sprintf("sensor=%s status=%s", c.Sensor, c.Status)
		if c.Reason != "" {
			v += " reason=" + c.Reason
		}
		if c.Denied > 0 {
			v += fmt.Sprintf(" denied=%d", c.Denied)
		}
		if c.Scope != "" {
			v += " scope=" + c.Scope
		}
		props = append(props, Property("coverage", v))
		for _, u := range c.Unseen {
			if !seen[u] {
				seen[u] = true
				unseen = append(unseen, u)
			}
		}
	}
	sort.Strings(unseen)
	for _, u := range unseen {
		props = append(props, Property("not-seen", u))
	}
	return props
}
