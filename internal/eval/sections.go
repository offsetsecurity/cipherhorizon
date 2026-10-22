package eval

import (
	"sort"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Section identifiers, in page order (PRD-004 REQ-TUI-4, REQ-TUI-8).
const (
	SecCertificates    = "certificates"
	SecRevocation      = "revocation"
	SecProtocols       = "protocols"
	SecSuites          = "suites"
	SecKeyExchange     = "key-exchange"
	SecFeatures        = "features"
	SecHTTP            = "http"
	SecVulnerabilities = "vulnerabilities"
)

// SectionOrder is the order sections appear in.
var SectionOrder = []string{SecCertificates, SecRevocation, SecProtocols, SecSuites, SecKeyExchange, SecFeatures, SecHTTP, SecVulnerabilities}

// Section statuses: a word, never only a colour.
const (
	StatusProblem      = "problem"
	StatusAttention    = "attention"
	StatusGood         = "good"
	StatusNotChecked   = "not-checked"
	StatusNotCollected = "not-collected"
	// StatusNotApplicable: the area does not exist for this service (no HTTP layer behind an SMTP
	// or LDAP endpoint), so there was nothing to check; it is not a gap in the scan.
	StatusNotApplicable = "not-applicable"
	StatusInconclusive  = "inconclusive"
	// StatusUnknown: every check in the area ran, but the property the area is about cannot be
	// known from the endpoint alone (revocation, without contacting the CA). Its checks still count.
	StatusUnknown = "unknown"
)

// Section is one part of the endpoint page with its status.
type Section struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	// Reason explains a not-checked, not-collected or inconclusive status, or
	// a limit of what a good section means.
	Reason     string   `json:"reason,omitempty"`
	ReasonCode string   `json:"reasonCode,omitempty"`
	Findings   []string `json:"findings"` // rule IDs, in severity order
	// Inconclusive lists the parts of the stage that proved nothing.
	Inconclusive []string `json:"inconclusive,omitempty"`
}

// AttackView is one named attack in the vulnerabilities section.
type AttackView struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"` // exposed | not-exposed | not-tested
	Findings []string `json:"findings,omitempty"`
	Why      string   `json:"why"`             // the result for this endpoint, in a sentence
	Needs    string   `json:"needs,omitempty"` // the condition the attack requires
}

// RefInfo is one bundled reference list as the evaluation used it.
type RefInfo struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	Retrieved string `json:"retrieved"`
	Count     int    `json:"count"`
	AgeDays   int    `json:"ageDays"`
	Stale     bool   `json:"stale"`
	Licence   string `json:"licence"`
}

// sectionOf maps a finding to its section.
func sectionOf(f Finding) string {
	switch {
	case strings.HasPrefix(f.ID, "HTTP."):
		return SecHTTP
	case strings.HasPrefix(f.ID, "OCSP.") || strings.HasPrefix(f.ID, "CT."):
		return SecRevocation
	}
	switch f.Category {
	case "protocol":
		return SecProtocols
	case "cipher":
		return SecSuites
	case "key-exchange", "pqc":
		return SecKeyExchange
	case "certificate":
		return SecCertificates
	case "revocation":
		return SecRevocation
	case "feature":
		return SecFeatures
	case "http":
		return SecHTTP
	}
	return SecVulnerabilities
}

// availabilityRules make clients fail to connect (REQ-TUI-2).
var availabilityRules = map[string]bool{
	"CERT.EXPIRED": true, "CERT.UNTRUSTED": true, "CERT.NAME-MISMATCH": true, "CERT.CHAIN-INCOMPLETE": true,
	"CERT.NO-SERVERAUTH": true, "OCSP.MUST-STAPLE-MISSING": true, "OCSP.REVOKED": true, "CERT.COMPROMISED-ROOT": true,
}

// attackLabels name the attacks a finding enables (REQ-TVLN-1). The detail
// decides between FREAK and Logjam for export suites.
var attackLabels = map[string][]string{
	"KX.DH-SMALL": {"Logjam"}, "KX.DH-COMMON-PRIME": {"Logjam"}, "PROTO.SSL2": {"DROWN"}, "KX.DH-COMPOSITE": {"Logjam"},
	"FEAT.COMPRESSION": {"CRIME"}, "CIPHER.SWEET32": {"SWEET32"}, "CIPHER.RC4": {"RC4 biases"},
	"VULN.POODLE": {"POODLE"}, "VULN.BEAST": {"BEAST"}, "CIPHER.CBC": {"LUCKY13"}, "VULN.DROWN-SHARED-KEY": {"DROWN"},
}

func annotate(findings []Finding) {
	for i := range findings {
		f := &findings[i]
		f.Section = sectionOf(*f)
		f.Availability = availabilityRules[f.ID]
		f.Labels = append([]string(nil), attackLabels[f.ID]...)
		if f.ID == "CIPHER.EXPORT" {
			if strings.Contains(f.Detail, "RSA_EXPORT") {
				f.Labels = append(f.Labels, "FREAK")
			}
			if strings.Contains(f.Detail, "DHE_") && strings.Contains(f.Detail, "EXPORT") {
				f.Labels = append(f.Labels, "Logjam")
			}
			if len(f.Labels) == 0 {
				f.Labels = []string{"FREAK"}
			}
		}
		if f.ID == "CERT.NAME-MISMATCH" && strings.Contains(f.Detail, "[no-sni]") {
			f.Availability = false // only clients that send no server name are affected
		}
	}
}

// stageFor names the scan stage a section depends on.
var stageFor = map[string]string{
	SecCertificates: tlsprobe.StageCerts, SecRevocation: tlsprobe.StageRevocation, SecProtocols: tlsprobe.StageProtocols,
	SecSuites: tlsprobe.StageSuites, SecKeyExchange: tlsprobe.StageKeyExchange, SecFeatures: tlsprobe.StageFeatures,
	SecHTTP: tlsprobe.StageHTTP, SecVulnerabilities: tlsprobe.StageSuites,
}

func sections(c *ctx, findings []Finding) []Section {
	stages := map[string]tlsprobe.Stage{}
	for _, s := range c.rep.Stages {
		stages[s.Name] = s
	}
	var out []Section
	for _, id := range SectionOrder {
		s := Section{ID: id, Findings: []string{}}
		worst := Info
		seen := map[string]bool{}
		for _, f := range findings {
			if f.Section != id && (id != SecVulnerabilities || len(f.Labels) == 0) {
				continue
			}
			if !seen[f.ID] {
				seen[f.ID] = true
				s.Findings = append(s.Findings, f.ID)
			}
			if f.Severity.Rank() < worst.Rank() {
				worst = f.Severity
			}
		}
		switch {
		case worst.Rank() <= High.Rank():
			s.Status = StatusProblem
		case worst.Rank() <= Low.Rank():
			s.Status = StatusAttention
		default:
			s.Status = StatusGood
		}
		// An attack the configuration makes possible is never "good", even when the finding
		// behind it is informational (LUCKY13 on CBC suites, for instance).
		if id == SecVulnerabilities && len(s.Findings) > 0 && s.Status == StatusGood {
			s.Status = StatusAttention
		}

		if id == SecRevocation && s.Status == StatusGood && !c.legacy && !c.revocationVouched() {
			s.Status, s.ReasonCode = StatusUnknown, "not-contacted"
			s.Reason = "No stapled OCSP response vouches for the certificate, and this scan does not contact the CA's OCSP responder or CRL, so whether it has been revoked is not known."
		}
		if c.legacy {
			switch id {
			case SecRevocation:
				s.Status, s.ReasonCode = StatusNotCollected, tlsprobe.ReasonLegacy
				s.Reason = "OCSP stapling contents and Certificate Transparency were not collected by the version that ran this scan."
			case SecCertificates:
				s.Reason = "Chain analysis and per-store trust were not collected by the version that ran this scan; trust shown is the scanning machine's own store."
			case SecHTTP:
				if c.rep.HSTS == nil {
					s.Status, s.ReasonCode = StatusNotChecked, tlsprobe.ReasonOptionOff
					s.Reason = "The HTTP check was not run on this scan (it was off by default before this version)."
				}
			}
			out = append(out, s)
			continue
		}
		if st, ok := stages[stageFor[id]]; ok {
			s.Inconclusive = st.Inconclusive
			switch st.Outcome {
			case tlsprobe.OutcomeSkipped:
				s.Status, s.Reason, s.ReasonCode = StatusNotChecked, st.Reason, st.ReasonCode
				if st.ReasonCode == tlsprobe.ReasonNotApplicable {
					s.Status = StatusNotApplicable
				}
			case tlsprobe.OutcomeInconclusive:
				s.Status, s.Reason, s.ReasonCode = StatusInconclusive, st.Reason, st.ReasonCode
			}
		}
		out = append(out, s)
	}
	return out
}

func sectionRank(id string) int {
	for i, s := range SectionOrder {
		if s == id {
			return i
		}
	}
	return len(SectionOrder)
}

// fixFirst picks the three most important findings: severity, then
// availability impact, then section order; one entry per rule ID; never info.
func fixFirst(findings []Finding) []string {
	fs := append([]Finding(nil), findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Availability != b.Availability {
			return a.Availability
		}
		return sectionRank(a.Section) < sectionRank(b.Section)
	})
	out := []string{}
	seen := map[string]bool{}
	for _, f := range fs {
		if f.Severity == Info || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f.ID)
		if len(out) == 3 {
			break
		}
	}
	return out
}

// The attacks the vulnerabilities section lists, in order. Inferable ones are
// exposed when a labelled finding is present; active-only ones are never
// tested (decision D2: no exploit traffic). needs is the condition the attack
// requires; Why states the result for this endpoint in a sentence, so a line
// that says "not exposed" never reads like a finding.
var inferableAttacks = []struct{ name, needs, note string }{
	{"DROWN", "SSLv2 on this server, or its key on another SSLv2 server you scanned", ""},
	{"POODLE", "SSLv3 with CBC suites", ""},
	{"BEAST", "TLS 1.0 with CBC suites", ""},
	{"CRIME", "TLS-level compression", ""},
	{"FREAK", "RSA export suites", ""},
	{"Logjam", "DHE export suites, a DH prime of 1024 bits or fewer, or a widely shared published prime", ""},
	{"SWEET32", "64-bit block ciphers", ""},
	{"RC4 biases", "RC4 suites", ""},
	{"LUCKY13", "CBC suites", "a timing attack, mitigated in maintained TLS libraries"},
}

var activeOnlyAttacks = []struct{ name, why string }{
	{"Heartbleed", "Not tested: it needs a malformed heartbeat request, exploit traffic this product never sends."},
	{"CCS injection", "Not tested: it needs an out-of-order ChangeCipherSpec, exploit traffic."},
	{"ROBOT", "Not tested: it needs thousands of crafted RSA key exchanges, exploit traffic."},
	{"Ticketbleed", "Not tested: it needs a crafted session ticket, exploit traffic."},
	{"Padding oracles", "Not tested: they need crafted records after the handshake, exploit traffic."},
}

func attacks(findings []Finding) []AttackView {
	by := map[string][]string{}
	for _, f := range findings {
		for _, l := range f.Labels {
			if !contains(by[l], f.ID) {
				by[l] = append(by[l], f.ID)
			}
		}
	}
	out := []AttackView{}
	for _, a := range inferableAttacks {
		v := AttackView{Name: a.name, Status: "not-exposed", Needs: a.needs,
			Why: "Needs " + a.needs + "; not seen on this server."}
		if ids := by[a.name]; len(ids) > 0 {
			v.Status, v.Findings = "exposed", ids
			v.Why = "Possible: the server accepts " + a.needs + "."
			if a.note != "" {
				v.Why = "Possible: the server accepts " + a.needs + " (" + a.note + ")."
			}
		}
		out = append(out, v)
	}
	for _, a := range activeOnlyAttacks {
		out = append(out, AttackView{Name: a.name, Status: "not-tested", Why: a.why})
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func referenceData(now time.Time) []RefInfo {
	var out []RefInfo
	for _, s := range refdata.Sources() {
		age := s.Age(now)
		out = append(out, RefInfo{Name: s.Name, Source: s.URL, Retrieved: s.Retrieved, Count: s.Count,
			AgeDays: age, Stale: age > refdata.StaleAfterDays, Licence: s.Licence})
	}
	return out
}

// revocationVouched reports whether a stapled OCSP response that verifies says the served leaf is
// good: the only revocation status this scan can know without contacting the CA.
func (c *ctx) revocationVouched() bool {
	for _, ch := range c.chains {
		if ch.cr.NoSNI {
			continue
		}
		if o := ch.view.OCSP; o != nil && o.ForThisCert && o.Error == "" && o.Status == "good" && o.Signature == "valid" {
			return true
		}
	}
	return false
}
