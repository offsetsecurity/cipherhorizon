package estate

import (
	"fmt"
	"sort"
	"strings"
)

// Correlation joins a TLS endpoint (something a scan saw from outside) to the system that owns
// the machine behind it (something a collector or an import saw from inside). It is a proposal
// engine, not a merge: every result is a candidate the store keeps as a reviewable link with the
// exact values that matched (PRD-003 REQ-COR-1..6, ADR-0006: the join is a labelled assessment).
//
// It is a pure function of a snapshot, so the same inputs always give the same candidates in the
// same order (REQ-COR-8), and it can be tested against golden fixtures.

// Rule IDs, exactly the rules of RESEARCH-003 section 4.2. There is no fuzzy or similarity rule.
const (
	RuleCertificate = "J1-certificate-fingerprint" // the endpoint's leaf certificate is held on a host
	RuleName        = "J2-endpoint-name"           // the endpoint's host name is the machine's name
	RuleSAN         = "J3-san-covers-name"         // the leaf certificate names the machine
	RuleManual      = "manual"                     // a person said so
)

// Strength is a fixed label from a fixed table, never a computed score.
type Strength string

// The strengths.
const (
	StrengthStrong Strength = "strong"
	StrengthMedium Strength = "medium"
	StrengthWeak   Strength = "weak"
)

// WidelySharedCap is how many systems may hold one certificate before it is treated as shared
// infrastructure (a wildcard, a load-balanced certificate) and joins nothing (SR-15).
const WidelySharedCap = 25

// AssetInfo is what correlation needs to know about an asset.
type AssetInfo struct {
	ID       int64
	SystemID int64
	Kind     string // "tls-endpoint" or "host"
	Name     string
	Host     string // the address host of an endpoint, or the machine name of a host
	// FirstParty is true when this product's own scanner (for an endpoint) or collector (for a
	// host) is a current source of the asset, so its name is not just an uploaded label.
	FirstParty bool
}

// CertSighting is one current sighting of an end-entity certificate.
type CertSighting struct {
	Fingerprint string
	SystemID    int64
	AssetID     int64 // 0 for an import, which belongs to a system directly
	Stream      Stream
	Class       SourceClass
	Leaf        bool     // a presented certificate in leaf position
	DNSNames    []string // the certificate's names, lower-case
	Where       string   // a short, bounded description for the explanation
}

// Snapshot is everything Correlate reads.
type Snapshot struct {
	Assets    []AssetInfo
	Sightings []CertSighting
	// KeepSameSystem includes pairs whose asset already belongs to the candidate system. The store
	// sets it to learn whether a confirmed link is still supported after the join itself made the
	// two share a system; it never proposes such a pair as a new link.
	KeepSameSystem bool
}

// RuleHit is one rule that fired and the values that made it fire.
type RuleHit struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// Candidate proposes that an endpoint asset belongs to a system.
type Candidate struct {
	AssetID  int64
	SystemID int64 // the system that would receive the asset
	Strength Strength
	Rules    []RuleHit
	// AutoConfirm is true only for a strong, unambiguous candidate every datum of which came from
	// this product's own scanner and collector (REQ-COR-4).
	AutoConfirm bool
	// Ambiguous is true when the same evidence points at several systems: nothing is joined
	// automatically and each candidate says how many others it competes with.
	Ambiguous bool
	Note      string

	untrusted bool // some datum behind it did not come from this product's own scanner or collector
}

// Correlate proposes joins between endpoints and systems.
func Correlate(sn Snapshot) []Candidate {
	assets := map[int64]AssetInfo{}
	for _, a := range sn.Assets {
		assets[a.ID] = a
	}
	// hosts by lower-case machine name, for J2 and J3
	hostsByName := map[string][]AssetInfo{}
	for _, a := range sn.Assets {
		if a.Kind == "host" {
			n := strings.ToLower(strings.TrimSpace(a.Host))
			if n == "" {
				n = strings.ToLower(strings.TrimSpace(a.Name))
			}
			hostsByName[n] = append(hostsByName[n], a)
		}
	}

	// certificate holdings: fingerprint -> systems, split by trust
	type holding struct {
		firstParty map[int64]CertSighting
		other      map[int64]CertSighting
	}
	holdings := map[string]*holding{}
	for _, s := range sn.Sightings {
		if s.Leaf || s.Stream == StreamNetwork {
			continue // endpoints present certificates; holders hold them
		}
		h := holdings[s.Fingerprint]
		if h == nil {
			h = &holding{firstParty: map[int64]CertSighting{}, other: map[int64]CertSighting{}}
			holdings[s.Fingerprint] = h
		}
		if s.Class.FirstParty() {
			if _, ok := h.firstParty[s.SystemID]; !ok {
				h.firstParty[s.SystemID] = s
			}
		} else if _, ok := h.other[s.SystemID]; !ok {
			h.other[s.SystemID] = s
		}
	}

	type key struct{ asset, system int64 }
	cands := map[key]*Candidate{}
	get := func(a, sys int64) *Candidate {
		k := key{a, sys}
		if c := cands[k]; c != nil {
			return c
		}
		c := &Candidate{AssetID: a, SystemID: sys}
		cands[k] = c
		return c
	}

	// Every endpoint's presented leaf certificates.
	for _, s := range sn.Sightings {
		if !s.Leaf || s.Stream != StreamNetwork || s.AssetID == 0 {
			continue
		}
		ep, ok := assets[s.AssetID]
		if !ok || ep.Kind != "tls-endpoint" {
			continue
		}
		h := holdings[s.Fingerprint]
		if h != nil {
			total := len(h.firstParty) + len(h.other)
			if total > WidelySharedCap {
				continue // shared infrastructure: joins nothing
			}
			// A candidate for every system holding it, except the endpoint's own.
			addJ1 := func(holder CertSighting, firstPartyHolder bool) {
				if holder.SystemID == ep.SystemID && !sn.KeepSameSystem {
					return
				}
				c := get(ep.ID, holder.SystemID)
				c.Rules = append(c.Rules, RuleHit{RuleCertificate, fmt.Sprintf("sha-256 %s is the leaf certificate of %s and is also held: %s", shortFP(s.Fingerprint), clipDesc(ep.Name), holder.Where)})
				if !firstPartyHolder || !s.Class.FirstParty() {
					c.untrusted = true
				}
			}
			for _, sys := range sortedInts(h.firstParty) {
				addJ1(h.firstParty[sys], true)
			}
			for _, sys := range sortedInts(h.other) {
				if _, also := h.firstParty[sys]; also {
					continue // a first-party sighting of the same certificate on the same system already speaks
				}
				addJ1(h.other[sys], false)
			}
			// Ambiguity is judged among first-party holders only, so an imported document cannot
			// make a legitimate join ambiguous (or hijack it): it can only add a proposal of its own.
			ambiguousFirstParty := len(h.firstParty) > 1
			for _, sys := range sortedInts(h.firstParty) {
				if c := cands[key{ep.ID, sys}]; c != nil && ambiguousFirstParty {
					c.Ambiguous = true
					c.Note = fmt.Sprintf("the same certificate is held by %d systems", len(h.firstParty))
				}
			}
		}
		// J3: the certificate's own names include a host's name.
		for _, name := range s.DNSNames {
			for _, hst := range hostsByName[strings.ToLower(name)] {
				if hst.SystemID == ep.SystemID && !sn.KeepSameSystem {
					continue
				}
				c := get(ep.ID, hst.SystemID)
				c.Rules = append(c.Rules, RuleHit{RuleSAN, fmt.Sprintf("the leaf certificate of %s names %q, the name of host %s", clipDesc(ep.Name), clipDesc(name), clipDesc(hst.Name))})
				if !hst.FirstParty || !s.Class.FirstParty() {
					c.untrusted = true
				}
			}
		}
	}

	// J2: the endpoint's host is exactly a machine's name.
	for _, ep := range sn.Assets {
		if ep.Kind != "tls-endpoint" {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(ep.Host))
		if name == "" || looksLikeIP(name) {
			continue
		}
		for _, hst := range hostsByName[name] {
			if hst.SystemID == ep.SystemID && !sn.KeepSameSystem {
				continue
			}
			c := get(ep.ID, hst.SystemID)
			c.Rules = append(c.Rules, RuleHit{RuleName, fmt.Sprintf("the endpoint's host name %q is the name of host %s", clipDesc(name), clipDesc(hst.Name))})
			if !hst.FirstParty || !ep.FirstParty {
				c.untrusted = true
			}
		}
	}

	// Strength from the fixed table, then auto-confirmation.
	out := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		c.Strength = strengthOf(c)
		c.AutoConfirm = c.Strength == StrengthStrong && !c.Ambiguous && !c.untrusted
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AssetID != out[j].AssetID {
			return out[i].AssetID < out[j].AssetID
		}
		return out[i].SystemID < out[j].SystemID
	})
	return out
}

// strengthOf is the fixed table of DN-6.
//
//	J1 (a certificate the endpoint presents is held there) ........ strong
//	J1 with any other rule ....................................... strong
//	J2 alone, or J2 with J3 ...................................... medium
//	J3 alone ..................................................... weak
//
// An ambiguous J1 (the same certificate on several systems) is downgraded to medium: it points
// at a group, not at one machine.
func strengthOf(c *Candidate) Strength {
	has := map[string]bool{}
	for _, r := range c.Rules {
		has[r.ID] = true
	}
	switch {
	case has[RuleCertificate] && c.Ambiguous:
		return StrengthMedium
	case has[RuleCertificate]:
		return StrengthStrong
	case has[RuleName]:
		return StrengthMedium
	}
	return StrengthWeak
}

func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12] + "..."
	}
	return fp
}

func clipDesc(s string) string {
	s = clean(s, 80)
	return s
}

func looksLikeIP(s string) bool {
	if strings.Contains(s, ":") {
		return true
	}
	dots := 0
	for _, r := range s {
		switch {
		case r == '.':
			dots++
		case r < '0' || r > '9':
			return false
		}
	}
	return dots == 3
}

func sortedInts[V any](m map[int64]V) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
