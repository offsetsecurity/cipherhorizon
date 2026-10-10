package eval

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Prioritisation orders systems for migration work by an explicit, cited sequence of rules.
// There is no composite score: a system's position is fully explained by the facts listed on
// its row, and the rules themselves are published (PriorityMethodology). PRD-003 REQ-PRI-1..3.
//
// The order is lexicographic. Each rule decides between two systems only when every earlier rule
// tied, so a reader can always say why one system is above another.

// PriorityVersion identifies the rule set, recorded with every ranking.
const PriorityVersion = "priority/1"

// PriorityMeta holds the facts a person provides about a system (any may be empty: "not provided").
type PriorityMeta struct {
	Criticality       string // low, moderate, high
	Exposure          string // internet, internal, restricted
	DataLifetimeYears *int
}

// ServiceFacts is what the latest completed scan of one of the system's endpoints established.
type ServiceFacts struct {
	Name                  string
	HNDLExposed           bool
	ReadinessLevel        *int
	Critical, High        int
	HygieneCriticalOrHigh int
}

// PriorityInput is everything ranking reads about one system.
type PriorityInput struct {
	SystemID int64
	Name     string
	Meta     PriorityMeta
	Services []ServiceFacts
	Certs    []CertificateFacts // current end-entity certificates
	// EvidenceFirstParty says the system has at least one current source made by this product's
	// own scanner or collector; false means everything known about it was imported.
	EvidenceFirstParty bool
	EvidenceSources    int // current sources of any class
}

// Reason is one fact that puts a system where it is, with its sources.
type Reason struct {
	Rule      string     `json:"rule"`
	Text      string     `json:"text"`
	Citations []Citation `json:"citations,omitempty"`
}

// Ranked is one row of the ranking.
type Ranked struct {
	Rank     int      `json:"rank"`
	SystemID int64    `json:"systemId"`
	Name     string   `json:"name"`
	Tier     string   `json:"tier"` // the first rule that placed it, in words
	Reasons  []Reason `json:"reasons"`
	// Missing lists the inputs a person has not provided that would change how it is ranked.
	Missing []string `json:"missing"`
	// EvidenceOnly is true when none of exposure, criticality and data lifetime was provided: the
	// position rests on what was observed alone.
	EvidenceOnly bool   `json:"evidenceOnly"`
	Basis        string `json:"basis"`
	// Evidence says how the system is known: "observed" (this product's own scan or collector),
	// "imported" (only from imported documents) or "none" (no current source).
	Evidence string `json:"evidence"`
}

var (
	hndlBeyond = 2030 // NIST IR 8547 (draft): quantum-vulnerable public-key algorithms deprecated by 2030
)

type keyed struct {
	in       PriorityInput
	hndlCase int // 0 exposed with known lifetime past 2030; 1 exposed, lifetime unknown or shorter; 2 no exposure observed
	lifeEnd  int // year the data must stay confidential to, for ordering within case 0
	exposure int
	crit     int
	defect   int // worst severity rank among defects (0 critical ... 4 none)
	defects  int
	firstP   int // 0 first-party evidence, 1 imported only
	reasons  []Reason
	missing  []string
	tier     string
}

// Prioritise ranks systems. now fixes the calendar (data lifetimes are years from now).
func Prioritise(inputs []PriorityInput, now time.Time) []Ranked {
	ks := make([]keyed, 0, len(inputs))
	for _, in := range inputs {
		ks = append(ks, assess(in, now))
	}
	sort.SliceStable(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		switch {
		case a.hndlCase != b.hndlCase:
			return a.hndlCase < b.hndlCase
		case a.lifeEnd != b.lifeEnd:
			return a.lifeEnd > b.lifeEnd // data that must stay secret longer is more exposed
		case a.exposure != b.exposure:
			return a.exposure < b.exposure
		case a.crit != b.crit:
			return a.crit < b.crit
		case a.defect != b.defect:
			return a.defect < b.defect
		case a.defects != b.defects:
			return a.defects > b.defects
		case a.firstP != b.firstP:
			return a.firstP < b.firstP
		}
		if la, lb := strings.ToLower(a.in.Name), strings.ToLower(b.in.Name); la != lb {
			return la < lb
		}
		return a.in.SystemID < b.in.SystemID
	})
	out := make([]Ranked, len(ks))
	for i, k := range ks {
		metaGiven := k.in.Meta.Exposure != "" || k.in.Meta.Criticality != "" || k.in.Meta.DataLifetimeYears != nil
		basis := "based on observed evidence and the details you provided"
		if !metaGiven {
			basis = "based on evidence only: no exposure, criticality or data lifetime was provided"
		}
		evidence := "none"
		switch {
		case k.in.EvidenceFirstParty:
			evidence = "observed"
		case k.in.EvidenceSources > 0:
			evidence = "imported"
		}
		out[i] = Ranked{Rank: i + 1, SystemID: k.in.SystemID, Name: k.in.Name, Tier: k.tier, Reasons: k.reasons, Missing: k.missing, EvidenceOnly: !metaGiven, Basis: basis, Evidence: evidence}
	}
	return out
}

func assess(in PriorityInput, now time.Time) keyed {
	k := keyed{in: in, defect: 4, exposure: 3, crit: 3}
	add := func(rule, text string, cites ...Citation) {
		k.reasons = append(k.reasons, Reason{Rule: rule, Text: text, Citations: cites})
	}

	// Rule 1: harvest now, decrypt later.
	var exposed []string
	for _, s := range in.Services {
		if s.HNDLExposed {
			exposed = append(exposed, s.Name)
		}
	}
	lifetime := in.Meta.DataLifetimeYears
	switch {
	case len(exposed) > 0 && lifetime != nil && now.Year()+*lifetime > hndlBeyond:
		k.hndlCase = 0
		k.lifeEnd = now.Year() + *lifetime
		k.tier = "Recorded traffic is readable later, and the data must stay confidential past 2030"
		add("R1 harvest-now-decrypt-later",
			fmt.Sprintf("%s: a current client negotiates a key exchange that is not post-quantum, so traffic recorded today can be decrypted once a quantum computer exists. The data on this system must stay confidential for %d year(s), until about %d, which is past 2030, the date by which NIST IR 8547 plans to deprecate the classical public-key algorithms.",
				listNames(exposed), *lifetime, k.lifeEnd), citHNDL, citIR8547)
	case len(exposed) > 0:
		k.hndlCase = 1
		k.tier = "Recorded traffic would be readable later; how long the data must stay secret is not known here"
		why := "how long the data must stay confidential was not provided, so this cannot be ranked above the systems where it is known to outlive 2030"
		if lifetime != nil {
			why = fmt.Sprintf("the data is recorded as needing confidentiality for %d year(s), which ends by 2030", *lifetime)
		}
		add("R1 harvest-now-decrypt-later",
			fmt.Sprintf("%s: a current client negotiates a key exchange that is not post-quantum, so traffic recorded today could be decrypted later; %s.", listNames(exposed), why), citHNDL)
		if lifetime == nil {
			k.missing = append(k.missing, "data lifetime")
		}
	default:
		k.hndlCase = 2
		k.tier = "No exposed key exchange observed"
		if len(in.Services) == 0 {
			add("R1 harvest-now-decrypt-later", "no TLS service of this system has been scanned, so exposure of recorded traffic is not known (absence of a scan is not absence of exposure)")
		} else {
			add("R1 harvest-now-decrypt-later", "every scanned TLS service of this system negotiates a post-quantum or hybrid key exchange, or its scan could not establish otherwise")
		}
	}

	// Rule 2: exposure, then criticality.
	switch in.Meta.Exposure {
	case "internet":
		k.exposure = 0
	case "internal":
		k.exposure = 1
	case "restricted":
		k.exposure = 2
	default:
		k.missing = append(k.missing, "exposure")
	}
	switch in.Meta.Criticality {
	case "high":
		k.crit = 0
	case "moderate":
		k.crit = 1
	case "low":
		k.crit = 2
	default:
		k.missing = append(k.missing, "criticality")
	}
	if in.Meta.Exposure != "" || in.Meta.Criticality != "" {
		var parts []string
		if in.Meta.Exposure != "" {
			parts = append(parts, "exposure: "+in.Meta.Exposure)
		}
		if in.Meta.Criticality != "" {
			parts = append(parts, "criticality: "+in.Meta.Criticality+" (FIPS 199 vocabulary)")
		}
		add("R2 exposure and criticality", strings.Join(parts, "; ")+", as entered by a person")
	} else {
		add("R2 exposure and criticality", "not provided: internet exposure and criticality decide the order among systems with the same key-exchange risk, and none was entered")
	}

	// Rule 3: certificate and hygiene defects.
	worst := 4
	ids := map[string]int{}
	total := 0
	var cites []Citation
	for _, c := range in.Certs {
		for _, f := range EvaluateCertificate(c, now) {
			total++
			ids[f.ID]++
			if r := f.Severity.Rank(); r < worst {
				worst = r
			}
			cites = mergeCites(cites, f.Citations)
		}
	}
	scanCH := 0
	for _, s := range in.Services {
		if s.Critical > 0 && worst > 0 {
			worst = 0
		} else if s.High > 0 && worst > 1 {
			worst = 1
		}
		scanCH += s.Critical + s.High
	}
	k.defect, k.defects = worst, total+scanCH
	switch total + scanCH {
	case 0:
		add("R3 certificate and TLS defects", "no certificate or TLS finding of high severity or above was observed on the current evidence")
	default:
		var parts []string
		for _, id := range sortedKeys(ids) {
			parts = append(parts, fmt.Sprintf("%s x%d", id, ids[id]))
		}
		text := fmt.Sprintf("%d certificate finding(s)", total)
		if len(parts) > 0 {
			text += " (" + strings.Join(parts, ", ") + ")"
		}
		if scanCH > 0 {
			text += fmt.Sprintf(" and %d critical or high TLS finding(s) from scans", scanCH)
		}
		add("R3 certificate and TLS defects", text, cites...)
	}

	// Rule 4: how the system is known.
	if in.EvidenceFirstParty {
		k.firstP = 0
		add("R4 evidence", fmt.Sprintf("%d current source(s), including this product's own scanner or collector", in.EvidenceSources))
	} else {
		k.firstP = 1
		add("R4 evidence", "everything known about this system came from imported documents, which are not verified by this product; treat the ranking as a lead, not a finding")
	}
	return k
}

func listNames(names []string) string {
	sort.Strings(names)
	if len(names) > 4 {
		return fmt.Sprintf("%s and %d more service(s)", strings.Join(names[:4], ", "), len(names)-4)
	}
	return strings.Join(names, ", ")
}

func mergeCites(have, add []Citation) []Citation {
	for _, c := range add {
		dup := false
		for _, h := range have {
			dup = dup || h.URL == c.URL
		}
		if !dup {
			have = append(have, c)
		}
	}
	return have
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Rule describes one step of the ordering for the published methodology.
type Rule struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	Text      string     `json:"text"`
	Citations []Citation `json:"citations,omitempty"`
}

// PriorityMethodology is the ordered rule list exactly as applied. A test keeps it in step with
// the rule identifiers Prioritise puts on its reasons.
func PriorityMethodology() []Rule {
	return []Rule{
		{"R1 harvest-now-decrypt-later", "Recorded traffic that a quantum computer could read, for data that must stay secret long enough",
			"Systems with a TLS service whose key exchange a current client negotiates without post-quantum protection come first. Among them, those whose data must stay confidential past 2030 (the year NIST IR 8547 plans to deprecate the classical public-key algorithms) rank above those where the lifetime is unknown or shorter, and a longer required lifetime ranks higher. A system with no scanned TLS service has no observed exposure: that is not evidence of safety.",
			[]Citation{citHNDL, citIR8547}},
		{"R2 exposure and criticality", "Who can reach it, and what depends on it",
			"Then internet-facing before internal before restricted, then high before moderate before low criticality (FIPS 199 vocabulary). Both are entered by a person; a system without them ranks after those that have them, and says so.", nil},
		{"R3 certificate and TLS defects", "Concrete defects",
			"Then the worst severity among the system's certificate findings and its scans' critical and high findings, then how many. The certificate rules are the cited ones: expired, expiring, not yet valid, weak key, broken signature hash, and a quantum-vulnerable key in a certificate that outlives 2030 or 2035.",
			[]Citation{citRFC5280, citCABF, citSP80057, citIR8547}},
		{"R4 evidence", "How well the system is known",
			"Then systems known from this product's own scanner or collector before systems known only from imported documents; then name, so the order is stable.", nil},
	}
}
