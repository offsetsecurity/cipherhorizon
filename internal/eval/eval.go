// Package eval turns an observed TLS scan report into judgements: findings with
// severities, a post-quantum readiness level, and a TLS hygiene score.
//
// Everything here is a pure function of the report (and the time, for
// certificate expiry). Every finding carries citations and an evidence tier, and
// a test fails any rule without a citation: the product states nothing it cannot
// source. The readiness scale and the hygiene score are this product's own; the
// facts they rest on are cited, the scales themselves are not presented as standards.
package eval

import (
	"sort"
	"time"

	"github.com/example/cbom-scan/internal/tlsprobe"
)

// Version identifies the rule set that produced an Evaluation. Stored evaluations
// keep the version they were made with, so history shows what was concluded then.
const Version = "eval/2"

// Severity ranks a finding.
type Severity string

// The severities, most serious first.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Rank orders severities: lower is more serious.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	}
	return 4
}

// Evidence says how a statement is known.
type Evidence string

// The evidence tiers.
const (
	// Observed: a server reply demonstrated it.
	Observed Evidence = "observed"
	// Inferred: a consequence of what was observed (e.g. POODLE from SSLv3 plus CBC
	// suites), not separately tested.
	Inferred Evidence = "inferred"
	// Registry: stated by an authoritative registry (e.g. IANA marks a suite Discouraged).
	Registry Evidence = "registry"
	// NotMeasured: something the product does not test, listed so its absence is not
	// mistaken for a clean result.
	NotMeasured Evidence = "not-measured"
)

// Citation points to the source of a statement.
type Citation struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Finding is one judgement about an endpoint.
type Finding struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Category    string     `json:"category"` // protocol | cipher | key-exchange | certificate | feature | vulnerability | pqc
	Detail      string     `json:"detail"`   // what was seen on this endpoint
	Evidence    Evidence   `json:"evidence"`
	Citations   []Citation `json:"citations"`
	Remediation string     `json:"remediation"`
}

// Evaluation is the full judgement of one scan.
type Evaluation struct {
	Version   string           `json:"version"`
	Findings  []Finding        `json:"findings"`
	Readiness Readiness        `json:"readiness"`
	Hygiene   Hygiene          `json:"hygiene"`
	Counts    map[Severity]int `json:"counts"`
}

// Evaluate judges a scan report. now is used for certificate expiry.
func Evaluate(rep *tlsprobe.Report, now time.Time) Evaluation {
	c := newContext(rep, now)

	var findings []Finding
	for _, r := range rules {
		for _, h := range r.check(c) {
			sev := r.severity
			if h.severity != "" {
				sev = h.severity
			}
			ev := r.evidence
			if h.evidence != "" {
				ev = h.evidence
			}
			findings = append(findings, Finding{
				ID: r.id, Title: r.title, Severity: sev, Category: r.category,
				Detail: h.detail, Evidence: ev, Citations: r.citations, Remediation: r.remediation,
			})
		}
	}

	ready := assessReadiness(c)
	findings = append(findings, pqcFindings(ready)...)

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() < findings[j].Severity.Rank()
		}
		return findings[i].ID < findings[j].ID
	})

	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return Evaluation{
		Version: Version, Findings: findings, Readiness: ready,
		Hygiene: computeHygiene(c, findings), Counts: counts,
	}
}

// ctx is the report plus the derived views every rule needs.
type ctx struct {
	rep *tlsprobe.Report
	now time.Time

	supported map[string]bool // protocol version name -> supported
	suites    []tlsprobe.SuiteResult
	byVersion map[string][]tlsprobe.SuiteResult
}

func newContext(rep *tlsprobe.Report, now time.Time) *ctx {
	c := &ctx{rep: rep, now: now, supported: map[string]bool{}, byVersion: map[string][]tlsprobe.SuiteResult{}}
	for _, p := range rep.Protocols {
		c.supported[p.Version] = p.Supported
	}
	for _, s := range rep.Suites {
		c.suites = append(c.suites, s)
		c.byVersion[s.Version] = append(c.byVersion[s.Version], s)
	}
	return c
}

// inconclusive reports whether the protocol probe for v proved nothing.
func (c *ctx) inconclusive(v string) bool {
	for _, p := range c.rep.Protocols {
		if p.Version == v {
			return p.Evidence == tlsprobe.EvidenceInconclusive
		}
	}
	return true // never probed
}
