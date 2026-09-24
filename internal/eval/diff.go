package eval

import (
	"fmt"
	"sort"

	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// Impact says whether a change moved the endpoint's posture the right way.
type Impact string

// The impacts.
const (
	Better  Impact = "better"
	Worse   Impact = "worse"
	Neutral Impact = "neutral"
)

// Change is one difference between two scans of the same endpoint.
type Change struct {
	Area    string `json:"area"` // readiness | hygiene | protocol | suite | group | certificate | finding
	Kind    string `json:"kind"` // added | removed | changed
	Subject string `json:"subject"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
	Impact  Impact `json:"impact"`
}

// Diff is the set of differences between two scans.
type Diff struct {
	Changes []Change `json:"changes"`
	Better  int      `json:"better"`
	Worse   int      `json:"worse"`
	Neutral int      `json:"neutral"`
	Summary string   `json:"summary"`
}

var areaOrder = map[string]int{"readiness": 0, "hygiene": 1, "protocol": 2, "group": 3, "suite": 4, "certificate": 5, "finding": 6}

// Compare reports what changed from one scan to a later one.
func Compare(fromRep, toRep *tlsprobe.Report, fromEv, toEv Evaluation) Diff {
	var ch []Change
	add := func(c Change) { ch = append(ch, c) }

	// Readiness and hygiene first: they are the headline.
	if fromEv.Readiness.Level != toEv.Readiness.Level {
		imp := Worse
		if toEv.Readiness.Level > fromEv.Readiness.Level {
			imp = Better
		}
		add(Change{Area: "readiness", Kind: "changed", Subject: "PQC readiness level",
			Before: fmt.Sprintf("L%d %s", fromEv.Readiness.Level, fromEv.Readiness.Label),
			After:  fmt.Sprintf("L%d %s", toEv.Readiness.Level, toEv.Readiness.Label), Impact: imp})
	}
	if fromEv.Hygiene.Band != toEv.Hygiene.Band {
		add(Change{Area: "hygiene", Kind: "changed", Subject: "TLS hygiene",
			Before: hygieneText(fromEv.Hygiene), After: hygieneText(toEv.Hygiene),
			Impact: bandImpact(fromEv.Hygiene.Band, toEv.Hygiene.Band)})
	}

	// Protocols.
	fp, tp := protocolSet(fromRep), protocolSet(toRep)
	for _, v := range union(keys(fp), keys(tp)) {
		if fp[v] == tp[v] {
			continue
		}
		legacy := v == "SSLv2" || v == "SSLv3" || v == "TLSv1.0" || v == "TLSv1.1"
		switch {
		case tp[v] && legacy:
			add(Change{Area: "protocol", Kind: "added", Subject: v, Impact: Worse})
		case tp[v]:
			add(Change{Area: "protocol", Kind: "added", Subject: v, Impact: Better})
		case legacy:
			add(Change{Area: "protocol", Kind: "removed", Subject: v, Impact: Better})
		default:
			add(Change{Area: "protocol", Kind: "removed", Subject: v, Impact: Worse})
		}
	}

	// Cipher suites.
	fs, ts := suiteSet(fromRep), suiteSet(toRep)
	for _, k := range union(keysS(fs), keysS(ts)) {
		f, inF := fs[k]
		t, inT := ts[k]
		switch {
		case inT && !inF:
			add(Change{Area: "suite", Kind: "added", Subject: k, Impact: suiteImpact(t, true)})
		case inF && !inT:
			add(Change{Area: "suite", Kind: "removed", Subject: k, Impact: suiteImpact(f, false)})
		}
	}

	// Key-exchange groups.
	fg, tg := groupSet(fromRep), groupSet(toRep)
	for _, k := range union(keysG(fg), keysG(tg)) {
		f, inF := fg[k]
		t, inT := tg[k]
		switch {
		case inT && !inF:
			add(Change{Area: "group", Kind: "added", Subject: k, Impact: groupImpact(t, true)})
		case inF && !inT:
			add(Change{Area: "group", Kind: "removed", Subject: k, Impact: groupImpact(f, false)})
		}
	}

	// Certificates: a different leaf means the certificate was replaced or renewed.
	fc, tc := leaves(fromRep), leaves(toRep)
	for fp2, l := range tc {
		if _, ok := fc[fp2]; !ok && len(fc) > 0 {
			add(Change{Area: "certificate", Kind: "changed", Subject: "Leaf certificate replaced",
				After:  fmt.Sprintf("%s, valid until %s", l.Subject, l.NotAfter.Format("2006-01-02")),
				Impact: Neutral})
		}
	}
	for fp2, l := range fc {
		if _, ok := tc[fp2]; !ok && len(tc) > 0 {
			add(Change{Area: "certificate", Kind: "changed", Subject: "Previous leaf certificate no longer presented",
				Before: fmt.Sprintf("%s, valid until %s", l.Subject, l.NotAfter.Format("2006-01-02")), Impact: Neutral})
		}
	}

	// Findings.
	ff, tf := findingSet(fromEv), findingSet(toEv)
	for _, k := range union(keysF(ff), keysF(tf)) {
		f, inF := ff[k]
		t, inT := tf[k]
		switch {
		case inT && !inF:
			imp := Worse
			if t.Severity == Info {
				imp = Neutral
			}
			add(Change{Area: "finding", Kind: "added", Subject: t.ID + ": " + t.Title, After: string(t.Severity), Impact: imp})
		case inF && !inT:
			imp := Better
			if f.Severity == Info {
				imp = Neutral
			}
			add(Change{Area: "finding", Kind: "removed", Subject: f.ID + ": " + f.Title, Before: string(f.Severity), Impact: imp})
		}
	}

	sort.SliceStable(ch, func(i, j int) bool {
		if areaOrder[ch[i].Area] != areaOrder[ch[j].Area] {
			return areaOrder[ch[i].Area] < areaOrder[ch[j].Area]
		}
		return ch[i].Subject < ch[j].Subject
	})

	d := Diff{Changes: ch}
	if d.Changes == nil {
		d.Changes = []Change{}
	}
	for _, c := range ch {
		switch c.Impact {
		case Better:
			d.Better++
		case Worse:
			d.Worse++
		default:
			d.Neutral++
		}
	}
	switch {
	case len(ch) == 0:
		d.Summary = "No changes between these scans."
	default:
		d.Summary = fmt.Sprintf("%d change(s): %d better, %d worse, %d neutral.", len(ch), d.Better, d.Worse, d.Neutral)
	}
	if fromRep.Incomplete || toRep.Incomplete {
		d.Summary += " One of the scans was incomplete, so some differences may be artefacts of the probing."
	}
	return d
}

func hygieneText(h Hygiene) string {
	if h.Score < 0 {
		return h.Band
	}
	return fmt.Sprintf("%s (%d)", h.Band, h.Score)
}

func bandImpact(from, to string) Impact {
	switch {
	case BandRank(to) > BandRank(from):
		return Better
	case BandRank(to) < BandRank(from):
		return Worse
	}
	return Neutral
}

func weakSuite(s tlsprobe.SuiteResult) bool {
	return s.Export || s.Anon || s.Cipher == "NULL" || s.Cipher == "RC4" || s.Cipher == "DES" || s.BlockBits == 64 ||
		s.IANARecommended == "D"
}

func suiteImpact(s tlsprobe.SuiteResult, added bool) Impact {
	switch {
	case weakSuite(s) && added:
		return Worse
	case weakSuite(s):
		return Better
	}
	return Neutral
}

func groupImpact(g tlsprobe.GroupResult, added bool) Impact {
	if g.PQ && !g.Obsolete {
		if added {
			return Better
		}
		return Worse
	}
	return Neutral
}

func protocolSet(r *tlsprobe.Report) map[string]bool {
	m := map[string]bool{}
	for _, p := range r.Protocols {
		m[p.Version] = p.Supported
	}
	return m
}

func suiteSet(r *tlsprobe.Report) map[string]tlsprobe.SuiteResult {
	m := map[string]tlsprobe.SuiteResult{}
	for _, s := range r.Suites {
		m[s.Version+" "+s.Name] = s
	}
	return m
}

func groupSet(r *tlsprobe.Report) map[string]tlsprobe.GroupResult {
	m := map[string]tlsprobe.GroupResult{}
	for _, g := range r.Groups {
		m[g.Version+" "+g.Name] = g
	}
	return m
}

func leaves(r *tlsprobe.Report) map[string]tlsprobe.CertInfo {
	m := map[string]tlsprobe.CertInfo{}
	for _, cr := range r.Certificates {
		if l, ok := leafOf(cr); ok {
			m[l.SHA256] = l
		}
	}
	return m
}

func findingSet(e Evaluation) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range e.Findings {
		m[f.ID+"|"+f.Detail] = f
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysS(m map[string]tlsprobe.SuiteResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysG(m map[string]tlsprobe.GroupResult) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysF(m map[string]Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
