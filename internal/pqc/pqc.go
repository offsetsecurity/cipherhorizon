// Package pqc classifies the algorithms in a CBOM as quantum-vulnerable or
// quantum-safe, citing the standard or OID basis for every verdict.
//
// It is a plain function over a finished CBOM, not a plugin: it neither
// collects anything nor depends on which collector produced the document.
//
// The classification is evidence-based, not heuristic. A verdict exists only
// where a rule (rules.go) has a rationale and citations, and matching is by OID
// or by exact catalogue name. An algorithm that no rule covers is reported as
// unclassified and left unlabelled; nothing is inferred from a name that merely
// looks like RSA.
//
// A verdict is about the ALGORITHM. Whether a host actually uses it is a separate
// question that a package inventory cannot answer; see Finding.ProvidedBy.
package pqc

import (
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/cbom"
)

// Finding is the verdict on one algorithm component.
type Finding struct {
	Ref       string // the component's bom-ref
	Name      string
	OID       string
	Class     Class
	Rationale string
	Basis     []Reference
	// MatchedBy says how the rule was found, e.g. `OID 1.2.840.113549.1.1.1`,
	// `OID under arc 1.2.840.113549.1.1` or `name "RSA"`.
	MatchedBy string
	// ProvidedBy lists the bom-refs of components that `provide` this algorithm.
	// That is capability: the package can do this, which is not the same as the
	// host doing it.
	ProvidedBy []string
}

// Report is the outcome of classifying a CBOM.
type Report struct {
	Findings []Finding // sorted by Ref
	// Unclassified lists algorithm components no rule covers, by bom-ref.
	Unclassified []string
}

// Count returns how many findings have the given class.
func (r Report) Count(c Class) int {
	n := 0
	for _, f := range r.Findings {
		if f.Class == c {
			n++
		}
	}
	return n
}

// Analyze classifies every algorithm component in bom. It does not modify bom.
func Analyze(bom *cdx.BOM) Report {
	var rep Report
	if bom == nil || bom.Components == nil {
		return rep
	}

	providers := map[string][]string{}
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if d.Provides == nil {
				continue
			}
			for _, target := range *d.Provides {
				providers[target] = append(providers[target], d.Ref)
			}
		}
	}

	for _, c := range *bom.Components {
		cp := c.CryptoProperties
		if cp == nil || cp.AssetType != cdx.CryptoAssetTypeAlgorithm {
			continue
		}
		r, how := classify(c.Name, cp.OID)
		if r == nil {
			rep.Unclassified = append(rep.Unclassified, c.BOMRef)
			continue
		}
		by := append([]string(nil), providers[c.BOMRef]...)
		sort.Strings(by)
		rep.Findings = append(rep.Findings, Finding{
			Ref: c.BOMRef, Name: c.Name, OID: cp.OID,
			Class: r.class, Rationale: r.rationale, Basis: r.basis,
			MatchedBy: how, ProvidedBy: by,
		})
	}
	sort.Slice(rep.Findings, func(i, j int) bool { return rep.Findings[i].Ref < rep.Findings[j].Ref })
	sort.Strings(rep.Unclassified)
	return rep
}

// annotationPrefix is the property-name prefix Annotate owns.
var annotationPrefix = cbom.PropertyNamespace + ":pqc:"

// Annotate writes each finding onto its component as namespaced properties
// (status, rationale, matched-by, and one basis entry per citation), replacing
// any earlier annotation so the call is idempotent. Components without a finding
// are left exactly as they were.
func Annotate(bom *cdx.BOM, rep Report) {
	if bom == nil || bom.Components == nil {
		return
	}
	byRef := make(map[string]Finding, len(rep.Findings))
	for _, f := range rep.Findings {
		byRef[f.Ref] = f
	}
	comps := *bom.Components
	for i := range comps {
		f, ok := byRef[comps[i].BOMRef]
		if !ok {
			continue
		}
		var props []cdx.Property
		if comps[i].Properties != nil {
			for _, p := range *comps[i].Properties {
				if !strings.HasPrefix(p.Name, annotationPrefix) {
					props = append(props, p)
				}
			}
		}
		props = append(props,
			cbom.Property("pqc:status", string(f.Class)),
			cbom.Property("pqc:rationale", f.Rationale),
			cbom.Property("pqc:matched-by", f.MatchedBy),
		)
		for _, b := range f.Basis {
			props = append(props, cbom.Property("pqc:basis", b.Title+" <"+b.URL+">"))
		}
		comps[i].Properties = &props
	}
}

// Summary renders a short human-readable digest of the report for the operator.
func (r Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "PQC: %d algorithms classified: %d quantum-vulnerable, %d quantum-safe",
		len(r.Findings), r.Count(Vulnerable), r.Count(Safe))
	if n := len(r.Unclassified); n > 0 {
		fmt.Fprintf(&b, "; %d unclassified (no evidence-backed rule)", n)
	}
	b.WriteByte('\n')
	for _, f := range r.Findings {
		if f.Class != Vulnerable {
			continue
		}
		fmt.Fprintf(&b, "  quantum-vulnerable: %s", f.Name)
		if len(f.ProvidedBy) > 0 {
			fmt.Fprintf(&b, " (available via %d component(s))", len(f.ProvidedBy))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// classify finds the rule for an algorithm by OID, then by OID arc, then by
// exact catalogue name, and says how it matched. nil means unclassified.
func classify(name, oid string) (*rule, string) {
	if oid != "" {
		if r, ok := idx.byOID[oid]; ok {
			return r, "OID " + oid
		}
		for _, a := range idx.arcs {
			if underArc(oid, a.arc) {
				return a.rule, "OID under arc " + a.arc
			}
		}
	}
	if r, ok := idx.byName[strings.ToLower(name)]; ok {
		return r, fmt.Sprintf("name %q", name)
	}
	return nil, ""
}

// underArc reports whether oid is arc or lies beneath it. It compares whole
// components, so 1.2.840.10045 does not match 1.2.840.100451.
func underArc(oid, arc string) bool {
	return oid == arc || strings.HasPrefix(oid, arc+".")
}

type arcRule struct {
	arc  string
	rule *rule
}

var idx = buildIndex()

type index struct {
	byOID  map[string]*rule
	byName map[string]*rule
	arcs   []arcRule
}

func buildIndex() index {
	ix := index{byOID: map[string]*rule{}, byName: map[string]*rule{}}
	for i := range rules {
		r := &rules[i]
		for _, id := range r.algos {
			a := algo.MustGet(id) // a rule naming an unknown algorithm is a programming error
			ix.byName[strings.ToLower(a.ID)] = r
			if a.OID != "" {
				ix.byOID[a.OID] = r
			}
		}
		for _, o := range r.oids {
			ix.byOID[o] = r
		}
		for _, a := range r.arcs {
			ix.arcs = append(ix.arcs, arcRule{arc: a, rule: r})
		}
	}
	// Longest arc first, so the most specific subtree wins.
	sort.SliceStable(ix.arcs, func(i, j int) bool { return len(ix.arcs[i].arc) > len(ix.arcs[j].arc) })
	return ix
}

// ClassOf returns the cited verdict for an algorithm by OID and name, or false when no rule
// matches (unclassified, never a guess).
func ClassOf(name, oid string) (Class, bool) {
	if r, _ := classify(name, oid); r != nil {
		return r.class, true
	}
	return "", false
}
