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

	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Version identifies the rule set that produced an Evaluation. Stored evaluations
// keep the version they were made with, so history shows what was concluded then.
const Version = "eval/9"

// eval/7 (PRD-008): a post-quantum signature scheme proved accepted by the signature stage counts
// toward L4, and SSH endpoints are judged into the same shape (Protocol "ssh").

// eval/6: a check that found nothing says what it confirmed (Check.Pass).
// eval/5 (PRD-006): the evaluation lists every check it ran, found or not, so a report can
// show what was evaluated and not only what failed.
// eval/4 (PRD-005 follow-up): a vulnerabilities section with an exposed attack is never
// "good", and each attack line states its result rather than only its condition.

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

	// Section is the endpoint-page section the finding belongs to.
	Section string `json:"section"`
	// Labels name the published attacks this weakness enables (FREAK, Logjam,
	// ...). They are labels on the finding, never separate findings.
	Labels []string `json:"labels,omitempty"`
	// Availability marks findings that make clients fail to connect.
	Availability bool `json:"availability,omitempty"`
}

// Evaluation is the full judgement of one scan.
type Evaluation struct {
	Version string `json:"version"`
	// Protocol is "ssh" for an SSH endpoint and empty for TLS, so stored TLS evaluations are unchanged.
	Protocol  string           `json:"protocol,omitempty"`
	Findings  []Finding        `json:"findings"`
	Readiness Readiness        `json:"readiness"`
	Hygiene   Hygiene          `json:"hygiene"`
	Counts    map[Severity]int `json:"counts"`

	// eval/3 additions.
	EvaluatedAt     time.Time    `json:"evaluatedAt"`
	Sections        []Section    `json:"sections"`
	FixFirst        []string     `json:"fixFirst"` // rule IDs, at most three
	PKI             []ChainView  `json:"pki"`
	Vulnerabilities []AttackView `json:"vulnerabilities"`
	ReferenceData   []RefInfo    `json:"referenceData"`
	// DHGroup names the server's DHE prime when it is a published group.
	DHGroup *DHGroupView `json:"dhGroup,omitempty"`

	// Checks is every check this evaluation considered, with its result (PRD-006 REQ-EV-1).
	Checks []Check `json:"checks"`
	// LegacyReport is set when the report predates tls-report/2: the sections
	// that need its data are marked not-collected.
	LegacyReport bool `json:"legacyReport,omitempty"`
	// SSHAlgorithms is, for an SSH endpoint, every advertised algorithm with its verdict.
	SSHAlgorithms []SSHAlgorithm `json:"sshAlgorithms,omitempty"`
	// Baseline is, for an SSH endpoint, how it measures against an SSH baseline (PRD-008 WP-G).
	// SSH servers are judged this way and get no hygiene score (REQ-SHE-5).
	Baseline *Conformance `json:"baseline,omitempty"`

	// eval/9 (PRD-010): the classical strength of every accepted suite (rated by its weakest part)
	// and of every accepted group and presented certificate key.
	SuiteStrength []SuiteStrength `json:"suiteStrength,omitempty"`
	KeyStrength   []KeyStrength   `json:"keyStrength,omitempty"`
}

// Check is one check the evaluation ran. Title names what was looked for (a problem, as a
// finding would be titled); Result is found, not-found, not-checked (its stage did not run) or
// not-applicable (the area does not exist for this service).
type Check struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Section  string   `json:"section"`
	Severity Severity `json:"severity"`
	Result   string   `json:"result"`
	// Pass says what was confirmed when the check found nothing.
	Pass string `json:"pass,omitempty"`
}

// DHGroupView is a published Diffie-Hellman group the server's prime matched.
type DHGroupView struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Bits       int    `json:"bits"`
	Negotiated bool   `json:"rfc7919"`
}

// Evaluate judges a scan report at now, against the bundled root stores and no
// private anchors.
func Evaluate(rep *tlsprobe.Report, now time.Time) Evaluation {
	return EvaluateWith(rep, Input{Now: now})
}

// EvaluateWith judges a scan report with explicit inputs.
func EvaluateWith(rep *tlsprobe.Report, in Input) Evaluation {
	if in.Stores == nil {
		in.Stores = refdata.Stores()
	}
	c := newContext(rep, in.Now)
	c.in = in
	c.legacy = rep.SchemaVersion == "" || rep.SchemaVersion == tlsprobe.SchemaVersion1
	if !c.legacy {
		c.analyseChains()
	}

	var findings []Finding
	var checks []Check
	checkAt := map[string]int{}
	for _, r := range allRules() {
		if r.legacyOnly && !c.legacy || r.v2Only && c.legacy {
			continue
		}
		hits := r.check(c)
		i, seen := checkAt[r.id]
		if !seen {
			i = len(checks)
			checkAt[r.id] = i
			checks = append(checks, Check{ID: r.id, Title: r.title, Severity: r.severity, Result: "not-found", Pass: passText[r.id],
				Section: sectionOf(Finding{ID: r.id, Category: r.category})})
		}
		if len(hits) > 0 {
			checks[i].Result = "found"
		}
		for _, h := range hits {
			sev := r.severity
			if h.severity != "" {
				sev = h.severity
			}
			ev := r.evidence
			if h.evidence != "" {
				ev = h.evidence
			}
			if r.legacyOnly && !c.legacy || r.v2Only && c.legacy {
				continue
			}
			findings = append(findings, Finding{
				ID: r.id, Title: r.title, Severity: sev, Category: r.category,
				Detail: h.detail, Evidence: ev, Citations: r.citations, Remediation: r.remediation,
			})
		}
	}

	ready := assessReadiness(c)
	pf := pqcFindings(ready)
	findings = append(findings, pf...)
	for _, f := range pf {
		checks = append(checks, Check{ID: f.ID, Title: f.Title, Severity: f.Severity, Result: "found", Section: SecKeyExchange})
	}
	if !containsCheck(checks, "PQC.HNDL-EXPOSED") && !containsCheck(checks, "PQC.NO-PQ-POSSIBLE") {
		checks = append(checks, Check{ID: "PQC.HNDL-EXPOSED", Title: "Traffic is exposed to harvest-now-decrypt-later", Severity: Medium, Result: "not-found", Section: SecKeyExchange,
			Pass: passText["PQC.HNDL-EXPOSED"]})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() < findings[j].Severity.Rank()
		}
		return findings[i].ID < findings[j].ID
	})

	annotate(findings)

	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	ev := Evaluation{
		Version: Version, Findings: findings, Readiness: ready,
		Hygiene: computeHygiene(c, findings), Counts: counts,
		EvaluatedAt: in.Now.UTC(), LegacyReport: c.legacy, PKI: []ChainView{},
	}
	for _, ch := range c.chains {
		ev.PKI = append(ev.PKI, ch.view)
	}
	ev.Sections = sections(c, findings)
	// A check whose stage did not run was not checked, whatever its rule returned.
	skipped := map[string]string{}
	for _, s := range ev.Sections {
		switch s.Status {
		case StatusNotChecked, StatusNotCollected:
			skipped[s.ID] = "not-checked"
		case StatusNotApplicable:
			skipped[s.ID] = "not-applicable"
		}
	}
	for i := range checks {
		if r := skipped[checks[i].Section]; checks[i].Result == "not-found" && r != "" {
			checks[i].Result = r
		}
	}
	ev.Checks = checks
	ev.FixFirst = fixFirst(findings)
	ev.Vulnerabilities = attacks(findings)
	ev.ReferenceData = referenceData(in.Now)
	ev.SuiteStrength = suiteStrengths(rep)
	ev.KeyStrength = keyStrengths(rep)
	if rep.DH != nil {
		if p, ok := refdata.LookupDHPrime(rep.DH.PrimeSHA256); ok {
			ev.DHGroup = &DHGroupView{Name: p.Name, Source: p.Source, Bits: p.Bits, Negotiated: p.Negotiated}
		}
	}
	return ev
}

// ctx is the report plus the derived views every rule needs.
type ctx struct {
	rep    *tlsprobe.Report
	now    time.Time
	in     Input
	legacy bool     // the report predates tls-report/2
	chains []*chain // the PKI view of each served chain (tls-report/2 only)

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

func containsCheck(cs []Check, id string) bool {
	for _, c := range cs {
		if c.ID == id {
			return true
		}
	}
	return false
}
