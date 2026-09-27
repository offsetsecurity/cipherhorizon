package cbom

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

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

	// provider key -> algorithm IDs. Two kinds of fact make a `provides` edge, and each
	// keeps its own claim: a DERIVED, cited `capable (mapped)` (knowledge applied to a
	// present file) and an OBSERVED `capable (probed)` (the operating system was asked).
	provides := map[string][]string{}
	citations := map[string][]string{} // in the knowledge table's order, which is the order readers see
	probedBy := map[string]bool{}      // providers whose edges came from asking the system
	algosUsed := map[string]bool{}
	for _, n := range g.Nodes() {
		if n.Subject.Kind != evidence.KindAlgorithm {
			continue
		}
		for _, o := range n.Observations {
			if o.Claim.Rung != evidence.RungCapable {
				continue
			}
			switch o.Origin {
			case evidence.OriginDerived:
				if o.Knowledge == nil || len(o.Relations) == 0 {
					return nil, nil, fmt.Errorf("cbom: derived capability %s has no knowledge reference or provider", o.ID)
				}
			case evidence.OriginObserved:
				if o.Claim.Capable != evidence.CapableProbed || len(o.Relations) == 0 {
					return nil, nil, fmt.Errorf("cbom: observed capability %s is not a probed capability with a provider", o.ID)
				}
			}
			for _, r := range o.Relations {
				if r.Kind != "provided-by" {
					continue
				}
				provides[r.To] = appendUnique(provides[r.To], n.Subject.Name)
				algosUsed[n.Subject.Name] = true
				if o.Origin == evidence.OriginObserved {
					probedBy[r.To] = true
				} else if len(citations[r.To]) == 0 {
					citations[r.To] = o.Knowledge.Citations
				}
			}
		}
	}

	var assets []collector.CryptoAsset
	// Algorithms a certificate references: a catalogue entry is added at the end with the
	// others; one this document derives itself (RSA-2048, ECDSA-P256) is kept here by bom-ref.
	derived := map[string]collector.CryptoAsset{}
	emitCatalogue := func(id string) (string, bool) {
		a, ok := algo.Lookup(id)
		if !ok {
			return "", false
		}
		algosUsed[id] = true
		return a.BOMRef(), true
	}
	emitDerived := func(a collector.CryptoAsset) string {
		if _, ok := derived[a.Component.BOMRef]; !ok {
			a.Component.Evidence = nil
			derived[a.Component.BOMRef] = a
		}
		return a.Component.BOMRef
	}
	for _, n := range g.Nodes() {
		if n.Subject.Kind == evidence.KindCertificate {
			cert, key, err := certificateComponents(g, n, emitCatalogue, emitDerived)
			if err != nil {
				return nil, nil, err
			}
			if cert != nil {
				assets = append(assets, *cert)
				if key != nil {
					assets = append(assets, *key)
				}
			}
			continue
		}
		if n.Subject.Kind != evidence.KindPackage && n.Subject.Kind != evidence.KindArtefact && n.Subject.Kind != evidence.KindProvider {
			continue
		}
		if len(n.Present()) == 0 {
			continue
		}
		if n.Subject.Kind == evidence.KindProvider {
			asset, err := providerComponent(n, provides[n.Subject.Key], probedBy[n.Subject.Key])
			if err != nil {
				return nil, nil, err
			}
			assets = append(assets, asset)
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
	refs := make([]string, 0, len(derived))
	for ref := range derived {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		assets = append(assets, derived[ref])
	}
	return assets, hostMetadata(g, opts), nil
}

// certificateComponents projects a certificate the host holds: the certificate, and the
// public key it certifies with its size, in the standard's shape (shared with the TLS
// inventory through CertificateAsset). Only public metadata is in the graph, so only public
// metadata can be here. A certificate node with no provisioned observation is not projected.
func certificateComponents(g *evidence.Graph, n *evidence.Node, emit func(string) (string, bool), emitAsset func(collector.CryptoAsset) string) (*collector.CryptoAsset, *collector.CryptoAsset, error) {
	var obs []*evidence.Observation
	for _, o := range n.Observations {
		if o.Origin == evidence.OriginObserved && o.Claim.Rung == evidence.RungProvisioned && o.Outcome == evidence.OutcomeObserved {
			obs = append(obs, o)
		}
	}
	if len(obs) == 0 {
		return nil, nil, nil
	}
	s := n.Subject
	a := s.Attrs
	notBefore, _ := time.Parse("2006-01-02T15:04:05Z", a["notBefore"])
	notAfter, _ := time.Parse("2006-01-02T15:04:05Z", a["notAfter"])
	bits, _ := strconv.Atoi(a["keyBits"])
	cert, key := CertificateAsset(CertFacts{
		Subject: a["subject"], Issuer: a["issuer"], SerialHex: a["serial"], SHA256: a["sha256"],
		NotBefore: notBefore, NotAfter: notAfter,
		KeyAlgorithm: a["keyAlg"], KeyBits: bits, Curve: a["curve"], SigName: a["sigAlg"],
	}, emit, emitAsset)
	if cert.Component.Name == "" {
		cert.Component.Name = s.Name
	}

	// Best method, and every place it was found. A place says whether a private key is stored
	// beside the certificate there, in the occurrence's additionalContext (the standard's slot
	// for context about one occurrence).
	best, bestQuality := obs[0], evidence.Quality("")
	type place struct{ privateKey string }
	places := map[string]place{}
	var locations []string
	methodIDs := map[string]bool{}
	anyKey := false
	for _, o := range obs {
		q, err := evidence.QualityOf(*o)
		if err != nil {
			return nil, nil, fmt.Errorf("cbom: %w", err)
		}
		if bestQuality == "" || rankQuality(q) > rankQuality(bestQuality) {
			best, bestQuality = o, q
		}
		loc := o.Source.Location
		if g.Host.OSFamily != "windows" && !strings.HasPrefix(loc, "cert-store:") {
			loc = "/" + loc // host-relative paths on Unix are absolute from the host root
		}
		if _, dup := places[loc]; !dup {
			locations = append(locations, loc)
		}
		pk := o.Source.Attrs["privateKey"]
		if pk == "yes" {
			anyKey = true
		}
		if prev, ok := places[loc]; !ok || pk == "yes" || prev.privateKey == "" {
			places[loc] = place{privateKey: pk}
		}
		methodIDs[o.Method] = true
	}
	sort.Strings(locations)
	occ := make([]cdx.EvidenceOccurrence, len(locations))
	for i, l := range locations {
		occ[i] = cdx.EvidenceOccurrence{Location: l}
		if pk := places[l].privateKey; pk != "" {
			occ[i].AdditionalContext = "privateKey=" + pk
		}
	}
	method, _ := evidence.LookupMethod(best.Method)
	cert.Component.Evidence = &cdx.Evidence{Occurrences: &occ, Identity: identityEvidence(s, methodIDs)}
	if sha := a["sha256"]; sha != "" {
		cert.Component.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: sha}}
	}

	props := []cdx.Property{
		Property("collector", method.Sensor),
		Property("evidence", "certificate-metadata"),
		Property("claim", string(evidence.RungProvisioned)),
		Property("method", best.Method),
		Property("method-quality", string(bestQuality)),
		Property("privilege", best.Privilege),
	}
	for _, p := range []struct{ prop, attr string }{
		{"cert:key-algorithm", "keyAlg"}, {"cert:key-bits", "keyBits"}, {"cert:curve", "curve"}, {"cert:signature-algorithm", "sigAlg"},
		{"cert:is-ca", "isCA"}, {"cert:self-signed", "selfSigned"}, {"cert:key-usage", "keyUsage"}, {"cert:san", "dnsNames"},
	} {
		if v := a[p.attr]; v != "" {
			props = append(props, Property(p.prop, v))
		}
	}
	if v := a["serial"]; v != "" {
		props = append(props, Property("cert:serial", v))
	}
	// Summary over all places; the per-place answer is in each occurrence's additionalContext.
	if anyKey {
		props = append(props, Property("cert:private-key", "yes"))
	}
	cert.Component.Properties = &props
	if key != nil {
		key.Component.Evidence = &cdx.Evidence{Occurrences: &occ}
	}
	return &cert, key, nil
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
		if sha := s.Attrs["sha256"]; sha != "" {
			comp.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: sha}}
		}
		comp.PackageURL = filePURL(s)
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
		if comp.PackageURL != "" {
			// A file identity, not an upstream product identifier: it says which exact
			// file this is, and must not be used to look the product up in a
			// vulnerability database as if it were the upstream release.
			props = append(props, Property("identifier-basis", "file identity (name, file version, SHA-256); not an upstream product identifier"))
		}
		if fam, ok := knowledge.ByID(s.Attrs["family"]); ok {
			if role := fam.RoleForFile(strings.ToLower(s.Name)); role != "" {
				props = append(props, Property("role", role))
				if role == knowledge.RoleConsumer && fam.ConsumerBasis != "" {
					props = append(props, Property("role-basis", fam.ConsumerBasis))
				}
			}
		}
		if v := s.Attrs["imports"]; v != "" {
			props = append(props, Property("static-imports", v))
		}
	}
	dependsOn := boundTargets(n)
	if len(dependsOn) > 0 {
		props = append(props, Property("dependency-basis",
			"static import table (parsed); the target is the recognised library in the same directory, the Windows loader search order was not evaluated; could use, not observed use"))
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
	return collector.CryptoAsset{Component: comp, Provides: provRefs, DependsOn: dependsOn}, nil
}

// boundTargets are the subjects this node is bound to by a static import, sorted.
// They come from observed `bound` claims, so an edge here is a link a sensor
// proved, and is never stronger than "could use".
func boundTargets(n *evidence.Node) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range n.Observations {
		if o.Origin != evidence.OriginObserved || o.Claim.Rung != evidence.RungBound {
			continue
		}
		for _, r := range o.Relations {
			if r.Claim.Rung == evidence.RungBound && !seen[r.To] {
				seen[r.To] = true
				out = append(out, r.To)
			}
		}
	}
	sort.Strings(out)
	return out
}

// filePURL identifies a loose file by name, file version and (when known) SHA-256
// as a generic package URL. It is empty when the version is unknown: a name alone
// is not an identifier worth emitting.
func filePURL(s evidence.Subject) string {
	if s.Name == "" || s.Attrs["fileVersion"] == "" {
		return ""
	}
	var q packageurl.Qualifiers
	if sha := s.Attrs["sha256"]; sha != "" {
		q = packageurl.Qualifiers{{Key: "checksum", Value: "sha256:" + sha}}
	}
	return packageurl.NewPackageURL("generic", "", s.Name, s.Attrs["fileVersion"], q, "").ToString()
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
		// What the sensor counted or bounded (files it did not open, certificates it could not
		// parse, budgets it hit), one property each, so a reader sees how much was left out and
		// not only that something was.
		limitKeys := make([]string, 0, len(c.Limits))
		for k := range c.Limits {
			limitKeys = append(limitKeys, k)
		}
		sort.Strings(limitKeys)
		for _, k := range limitKeys {
			props = append(props, Property("coverage-limit", fmt.Sprintf("sensor=%s %s=%s", c.Sensor, k, c.Limits[k])))
		}
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

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// providerComponent projects a cryptographic provider the operating system registers
// (a CNG or key storage provider, or a legacy CSP). It is a library that PROVIDES
// algorithms because the system was asked (`capable (probed)`): the component says so,
// and that a provider offers an algorithm is not evidence that anything uses it.
func providerComponent(n *evidence.Node, algos []string, probed bool) (collector.CryptoAsset, error) {
	present := n.Present()
	best, bestQuality := present[0], evidence.Quality("")
	methodIDs := map[string]bool{}
	seenLoc := map[string]bool{}
	var locations []string
	for _, o := range present {
		q, err := evidence.QualityOf(*o)
		if err != nil {
			return collector.CryptoAsset{}, fmt.Errorf("cbom: %w", err)
		}
		if bestQuality == "" || rankQuality(q) > rankQuality(bestQuality) {
			best, bestQuality = o, q
		}
		methodIDs[o.Method] = true
		if !seenLoc[o.Source.Location] {
			seenLoc[o.Source.Location] = true
			locations = append(locations, o.Source.Location)
		}
	}
	method, _ := evidence.LookupMethod(best.Method)
	s := n.Subject
	sort.Strings(locations)
	occ := make([]cdx.EvidenceOccurrence, len(locations))
	for i, l := range locations {
		occ[i] = cdx.EvidenceOccurrence{Location: l}
	}
	comp := cdx.Component{
		BOMRef: s.Key, Type: cdx.ComponentTypeLibrary, Name: s.Name,
		Evidence: &cdx.Evidence{Occurrences: &occ, Identity: identityEvidence(s, methodIDs)},
	}
	props := []cdx.Property{
		Property("collector", method.Sensor),
		Property("provider-kind", s.Attrs["providerKind"]),
		Property("evidence", "os-enumeration"),
		Property("claim", string(evidence.RungPresent)),
		Property("method", best.Method),
		Property("method-quality", string(bestQuality)),
		Property("privilege", best.Privilege),
	}
	if len(algos) > 0 && probed {
		// The operating system was asked; this is a probed capability, not observed use.
		props = append(props, Property("provides-claim", "capable-probed"))
	}
	if v := s.Attrs["cspType"]; v != "" {
		props = append(props, Property("csp-type", v))
		if num, err := strconv.ParseUint(v, 10, 32); err == nil {
			if name, ok := knowledge.CSPTypeNames[uint32(num)]; ok {
				props = append(props, Property("csp-type-name", name))
			}
		}
	}
	if v := s.Attrs["opened"]; v != "" {
		props = append(props, Property("opened", v))
		if v == "false" {
			props = append(props, Property("opened-note", "listed by name only: opening a provider loads its code, so its algorithms were not enumerated"))
		}
	}
	if v := s.Attrs["comment"]; v != "" {
		props = append(props, Property("provider-comment", v))
	}
	if v := s.Attrs["algorithms"]; v != "" {
		props = append(props, Property("native-algorithms", v))
	}
	comp.Properties = &props

	provRefs := make([]string, 0, len(algos))
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
