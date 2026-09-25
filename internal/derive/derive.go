// Package derive turns present artefacts into capability, by applying cited
// knowledge. It is where "this package is installed" becomes "this package can
// perform these algorithms": a statement about the software, from a citation, not
// something the host was seen to do.
//
// Every derived fact names the observation it rests on and the knowledge that
// produced it, and is checked by evidence.Graph.Add, which rejects a derived claim
// stronger than its inputs. This package imports no platform code and no CycloneDX.
package derive

import (
	"fmt"
	"path"
	"strings"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/knowledge"
)

// RelProvidedBy is the relation kind a derived capability uses to point back at the
// artefact that provides it.
const RelProvidedBy = "provided-by"

// Capabilities adds a derived `capable (mapped)` observation to g for every
// algorithm each recognised artefact provides.
//
// A node qualifies only if its `present` evidence is at least parsed quality:
// authoritative (a package database row) or parsed (a PE version resource). A name
// match alone never qualifies (ADR-0002), so a decoy file named like a crypto
// library is listed as present and never credited with capabilities.
//
// Version-gated capabilities need a readable version; when it cannot be read they
// are omitted, never assumed.
func Capabilities(g *evidence.Graph) error {
	for _, n := range g.Nodes() {
		if n.Subject.Kind != evidence.KindPackage && n.Subject.Kind != evidence.KindArtefact {
			continue
		}
		famID := n.Subject.Attrs["family"]
		if famID == "" {
			continue
		}
		fam, ok := knowledge.ByID(famID)
		if !ok || len(fam.Caps) == 0 {
			continue
		}
		if n.Subject.Kind == evidence.KindArtefact && fam.IsConsumerFile(strings.ToLower(path.Base(n.Subject.Attrs["path"]))) {
			// A file that only uses the family's implementation (libssl, the openssl
			// command) is present and linked to its provider; it is not credited with
			// the provider's algorithms.
			continue
		}
		base := strongestPresent(n)
		if base == nil {
			continue // only a name match (or nothing): not enough evidence to derive capability
		}

		ver, known := versionOf(n.Subject)
		mapping, citations := fam.Mapping()
		for _, id := range fam.Capabilities(ver, known) {
			o := evidence.Observation{
				Stream: evidence.StreamHost, Origin: evidence.OriginDerived,
				Subject: evidence.Subject{Kind: evidence.KindAlgorithm, Key: evidence.AlgorithmKey(id), Name: id},
				Claim:   evidence.Claim{Rung: evidence.RungCapable, Capable: evidence.CapableMapped}, Outcome: evidence.OutcomeObserved,
				Relations: []evidence.Relation{{
					Kind: RelProvidedBy, To: n.Subject.Key,
					Claim: evidence.Claim{Rung: evidence.RungCapable, Capable: evidence.CapableMapped},
				}},
				Method:    evidence.MethodKnowledge,
				Privilege: base.Privilege,
				BasedOn:   []string{base.ID},
				Knowledge: &evidence.KnowledgeRef{ID: mapping, Version: knowledge.KBVersion, Citations: citations},
			}
			evidence.Finish(&o)
			if err := g.Add(o); err != nil {
				return fmt.Errorf("derive: %w", err)
			}
		}
	}
	return nil
}

// strongestPresent returns the node's best `present` observation if its method
// quality is sufficient to support a capability, else nil. Ties go to the lowest ID
// so the choice is deterministic.
func strongestPresent(n *evidence.Node) *evidence.Observation {
	var best *evidence.Observation
	bestRank := -1
	for _, o := range n.Present() {
		q, err := evidence.QualityOf(*o)
		if err != nil || !q.Sufficient() {
			continue
		}
		rank := 1
		if q == evidence.QualityAuthoritative {
			rank = 2
		}
		if rank > bestRank || (rank == bestRank && o.ID < best.ID) {
			best, bestRank = o, rank
		}
	}
	return best
}

// versionOf reads the version an artefact reports: a Debian version for a package,
// a file version for a loose artefact.
func versionOf(s evidence.Subject) (knowledge.Version, bool) {
	switch s.Kind {
	case evidence.KindPackage:
		return knowledge.ParseDebian(s.Attrs["version"])
	default:
		return knowledge.ParseFile(s.Attrs["fileVersion"])
	}
}
