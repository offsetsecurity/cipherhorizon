package eval

import (
	"strings"
	"testing"
	"time"
)

var prioNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func years(n int) *int { return &n }

func svc(name string, exposed bool) ServiceFacts {
	return ServiceFacts{Name: name, HNDLExposed: exposed}
}

func rankNames(r []Ranked) string {
	var out []string
	for _, x := range r {
		out = append(out, x.Name)
	}
	return strings.Join(out, ">")
}

func base(id int64, name string) PriorityInput {
	return PriorityInput{SystemID: id, Name: name, EvidenceFirstParty: true, EvidenceSources: 1}
}

// PRD-003 AC-PRI-1: on a fixture with known systems the ranking equals the golden order and every
// row says why. Each system below differs from the others in exactly the way its name says.
func TestRankingFollowsTheRulesInOrder(t *testing.T) {
	mk := func(id int64, name string, f func(*PriorityInput)) PriorityInput {
		in := base(id, name)
		f(&in)
		return in
	}
	exposedLong := mk(1, "a-exposed-25y", func(i *PriorityInput) {
		i.Services = []ServiceFacts{svc("a:443", true)}
		i.Meta.DataLifetimeYears = years(25)
	})
	exposedLonger := mk(2, "b-exposed-40y", func(i *PriorityInput) {
		i.Services = []ServiceFacts{svc("b:443", true)}
		i.Meta.DataLifetimeYears = years(40)
	})
	exposedUnknown := mk(3, "c-exposed-unknown", func(i *PriorityInput) { i.Services = []ServiceFacts{svc("c:443", true)} })
	exposedShort := mk(4, "d-exposed-2y", func(i *PriorityInput) {
		i.Services = []ServiceFacts{svc("d:443", true)}
		i.Meta.DataLifetimeYears = years(2)
	})
	internetHigh := mk(5, "e-internet-high", func(i *PriorityInput) { i.Meta.Exposure, i.Meta.Criticality = "internet", "high" })
	internetLow := mk(6, "f-internet-low", func(i *PriorityInput) { i.Meta.Exposure, i.Meta.Criticality = "internet", "low" })
	internalHigh := mk(7, "g-internal-high", func(i *PriorityInput) { i.Meta.Exposure, i.Meta.Criticality = "internal", "high" })
	nothing := mk(8, "h-nothing-known", func(i *PriorityInput) {})
	expired := PriorityInput{SystemID: 9, Name: "i-expired-cert", EvidenceFirstParty: true, EvidenceSources: 1,
		Meta:  PriorityMeta{Exposure: "restricted", Criticality: "low"},
		Certs: []CertificateFacts{{Subject: "CN=x", NotBefore: prioNow.Add(-90 * 24 * time.Hour), NotAfter: prioNow.Add(-24 * time.Hour), KeyAlgorithm: "ECDSA", KeyBits: 256, SigName: "ECDSA-SHA256"}}}
	restrictedLow := mk(10, "j-restricted-low", func(i *PriorityInput) { i.Meta.Exposure, i.Meta.Criticality = "restricted", "low" })
	importedOnly := mk(11, "k-imported-only", func(i *PriorityInput) {
		i.EvidenceFirstParty = false
		i.Meta.Exposure, i.Meta.Criticality = "restricted", "low"
	})

	in := []PriorityInput{nothing, restrictedLow, importedOnly, internetLow, exposedShort, expired, internalHigh, exposedUnknown, internetHigh, exposedLonger, exposedLong}
	got := Prioritise(in, prioNow)
	// Top tier (exposed key exchange, data must outlive 2030), longest lifetime first; then the exposed systems where that is
	// not shown, by exposure and criticality (neither entered, so by defects, evidence and name); then everything else by
	// exposure, criticality, defects, evidence, name.
	wantOrder := "b-exposed-40y>a-exposed-25y>c-exposed-unknown>d-exposed-2y>e-internet-high>f-internet-low>g-internal-high>i-expired-cert>j-restricted-low>k-imported-only>h-nothing-known"
	if order := rankNames(got); order != wantOrder {
		t.Errorf("order\n got  %s\n want %s", order, wantOrder)
	}
	for i, r := range got {
		if r.Rank != i+1 || len(r.Reasons) != 4 {
			t.Errorf("%s: rank %d with %d reasons, want %d and 4", r.Name, r.Rank, len(r.Reasons), i+1)
		}
	}
}

// Two systems that differ only in how long their data must stay secret rank by that.
func TestTwoSystemsDifferingOnlyInDataLifetimeRankByIt(t *testing.T) {
	a := base(1, "short")
	a.Services = []ServiceFacts{svc("s:443", true)}
	a.Meta.DataLifetimeYears = years(6)
	b := base(2, "long")
	b.Services = []ServiceFacts{svc("l:443", true)}
	b.Meta.DataLifetimeYears = years(30)
	got := Prioritise([]PriorityInput{a, b}, prioNow)
	if got[0].Name != "long" || got[1].Name != "short" {
		t.Errorf("order = %s", rankNames(got))
	}
	// 6 years from 2026 is 2032: past 2030, so both are in the top tier and the longer one leads.
	if !strings.Contains(got[1].Reasons[0].Text, "2032") || !strings.Contains(got[0].Reasons[0].Text, "2056") {
		t.Errorf("reasons do not state the years: %q / %q", got[0].Reasons[0].Text, got[1].Reasons[0].Text)
	}
	// A lifetime that ends by 2030 does not reach the top tier, and the row says why.
	c := base(3, "brief")
	c.Services = []ServiceFacts{svc("b:443", true)}
	c.Meta.DataLifetimeYears = years(3)
	r := Prioritise([]PriorityInput{c, b}, prioNow)
	if r[0].Name != "long" || !strings.Contains(r[1].Reasons[0].Text, "ends by 2030") {
		t.Errorf("order %s; brief reason %q", rankNames(r), r[1].Reasons[0].Text)
	}
}

// AC-PRI-2: a system with nothing provided is still ranked, and says its position rests on
// evidence alone and what would change it.
func TestASystemWithNoMetadataIsRankedAndLabelled(t *testing.T) {
	in := base(1, "bare")
	in.Services = []ServiceFacts{svc("bare:443", true)}
	got := Prioritise([]PriorityInput{in}, prioNow)[0]
	if !got.EvidenceOnly || !strings.Contains(got.Basis, "evidence only") {
		t.Errorf("basis = %q, evidenceOnly=%v", got.Basis, got.EvidenceOnly)
	}
	missing := strings.Join(got.Missing, ",")
	for _, want := range []string{"exposure", "criticality", "data lifetime"} {
		if !strings.Contains(missing, want) {
			t.Errorf("missing = %q, lacks %q", missing, want)
		}
	}
	given := base(2, "given")
	given.Meta = PriorityMeta{Exposure: "internet", Criticality: "high", DataLifetimeYears: years(10)}
	given.Services = []ServiceFacts{svc("g:443", true)}
	g := Prioritise([]PriorityInput{given}, prioNow)[0]
	if g.EvidenceOnly || len(g.Missing) != 0 {
		t.Errorf("a fully described system: evidenceOnly=%v missing=%v", g.EvidenceOnly, g.Missing)
	}
}

// Absence of a scan is not absence of exposure, and the row says so.
func TestNoScanIsNotReportedAsSafe(t *testing.T) {
	got := Prioritise([]PriorityInput{base(1, "unscanned")}, prioNow)[0]
	if !strings.Contains(got.Reasons[0].Text, "not known") || !strings.Contains(got.Reasons[0].Text, "absence of a scan") {
		t.Errorf("reason = %q", got.Reasons[0].Text)
	}
}

// Everything imported: ranked after the same system known from first-party evidence, and labelled a lead.
func TestImportedOnlyEvidenceRanksAfterAndSaysSo(t *testing.T) {
	a := base(1, "aaa-imported")
	a.EvidenceFirstParty = false
	b := base(2, "zzz-observed")
	got := Prioritise([]PriorityInput{a, b}, prioNow)
	if got[0].Name != "zzz-observed" {
		t.Errorf("order = %s", rankNames(got))
	}
	if !strings.Contains(got[1].Reasons[3].Text, "not verified") {
		t.Errorf("reason = %q", got[1].Reasons[3].Text)
	}
}

// REQ-PRI-3: every rule that orders systems is published, every reason names a published rule,
// and every reason that rests on a source cites it.
func TestEveryRuleIsPublishedAndCited(t *testing.T) {
	published := map[string]Rule{}
	for _, r := range PriorityMethodology() {
		if r.ID == "" || r.Title == "" || len(r.Text) < 40 {
			t.Errorf("incomplete rule %+v", r)
		}
		published[r.ID] = r
	}
	if len(published) != 4 {
		t.Fatalf("%d published rules, want 4", len(published))
	}
	for _, id := range []string{"R1 harvest-now-decrypt-later", "R3 certificate and TLS defects"} {
		if len(published[id].Citations) == 0 {
			t.Errorf("rule %s has no citation", id)
		}
		for _, c := range published[id].Citations {
			if c.Title == "" || !strings.HasPrefix(c.URL, "https://") {
				t.Errorf("rule %s: bad citation %+v", id, c)
			}
		}
	}
	in := base(1, "all")
	in.Services = []ServiceFacts{svc("a:443", true)}
	in.Meta = PriorityMeta{Exposure: "internet", Criticality: "high", DataLifetimeYears: years(20)}
	in.Certs = []CertificateFacts{{Subject: "CN=x", NotBefore: prioNow.Add(-time.Hour), NotAfter: prioNow.Add(-time.Minute), KeyAlgorithm: "RSA", KeyBits: 1024, SigName: "SHA1-RSA"}}
	row := Prioritise([]PriorityInput{in}, prioNow)[0]
	if len(row.Reasons) != 4 {
		t.Fatalf("%d reasons", len(row.Reasons))
	}
	for _, r := range row.Reasons {
		if _, ok := published[r.Rule]; !ok {
			t.Errorf("reason names an unpublished rule %q", r.Rule)
		}
	}
	if len(row.Reasons[0].Citations) == 0 || len(row.Reasons[2].Citations) == 0 {
		t.Errorf("the harvest and defect reasons must cite their sources: %+v", row.Reasons)
	}
	if !strings.Contains(row.Reasons[2].Text, "CERT.EXPIRED") || !strings.Contains(row.Reasons[2].Text, "CERT.WEAK-KEY") {
		t.Errorf("the defect reason does not name the findings: %q", row.Reasons[2].Text)
	}
}

func TestRankingIsDeterministicAndStableUnderReordering(t *testing.T) {
	var in []PriorityInput
	for i := 0; i < 30; i++ {
		s := base(int64(i+1), strings.Repeat("s", i%7)+string(rune('a'+i%26)))
		s.Meta.Criticality = []string{"low", "moderate", "high", ""}[i%4]
		s.Meta.Exposure = []string{"internet", "internal", "restricted", ""}[i%3]
		if i%5 == 0 {
			s.Services = []ServiceFacts{svc("x", true)}
			s.Meta.DataLifetimeYears = years(i)
		}
		in = append(in, s)
	}
	want := rankNames(Prioritise(in, prioNow))
	rev := append([]PriorityInput(nil), in...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if got := rankNames(Prioritise(rev, prioNow)); got != want {
		t.Errorf("the order depends on input order:\n%s\n%s", got, want)
	}
}
