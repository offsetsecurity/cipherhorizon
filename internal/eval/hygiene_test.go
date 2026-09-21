package eval_test

import (
	"strings"
	"testing"

	"github.com/example/cbom-scan/internal/eval"
	"github.com/example/cbom-scan/internal/tlsprobe"
)

func hygiene(rep *tlsprobe.Report) eval.Hygiene { return eval.Evaluate(rep, now).Hygiene }

func TestBands(t *testing.T) {
	for score, want := range map[int]string{
		100: "Strong", 90: "Strong", 89: "Sound", 75: "Sound", 74: "Fair", 55: "Fair",
		54: "Weak", 30: "Weak", 29: "Broken", 0: "Broken", -1: eval.BandNotRated,
	} {
		if got := eval.BandFor(score); got != want {
			t.Errorf("score %d -> %s, want %s", score, got, want)
		}
	}
	order := []string{eval.BandNotRated, "Broken", "Weak", "Fair", "Sound", "Strong"}
	for i := 1; i < len(order); i++ {
		if eval.BandRank(order[i]) <= eval.BandRank(order[i-1]) {
			t.Errorf("%s should rank above %s", order[i], order[i-1])
		}
	}
}

func TestACleanEndpointIsStrong(t *testing.T) {
	h := hygiene(modern())
	if h.Band != "Strong" || h.Score < 90 {
		t.Errorf("hygiene = %+v", h)
	}
	if h.Ceiling != nil {
		t.Errorf("a clean endpoint hit a ceiling: %+v", h.Ceiling)
	}
	joined := strings.Join(h.NotMeasured, " ")
	if !strings.Contains(joined, "Strict Transport Security") || !strings.Contains(joined, "Heartbleed") {
		t.Errorf("unmeasured items not listed: %v", h.NotMeasured)
	}
	if !strings.Contains(h.Methodology, "not a standard") || !strings.Contains(h.Methodology, "own choice") {
		t.Errorf("the methodology must say the weights are this project's own choice and not a standard: %q", h.Methodology)
	}
}

// Every point taken off must trace to a finding on the same result, and the score must
// be exactly what the published weights give.
func TestEveryDeductionTracesToAFinding(t *testing.T) {
	weights := map[eval.Severity]int{eval.Critical: 40, eval.High: 20, eval.Medium: 10, eval.Low: 4, eval.Info: 0}
	for name, rep := range map[string]*tlsprobe.Report{"modern": modern(), "terrible": terrible()} {
		ev := eval.Evaluate(rep, now)
		byID := map[string]eval.Finding{}
		for _, f := range ev.Findings {
			if _, dup := byID[f.ID]; !dup { // worst first, so the first instance is the one counted
				byID[f.ID] = f
			}
		}
		total, seenIDs := 0, map[string]bool{}
		for _, d := range ev.Hygiene.Deductions {
			if seenIDs[d.Finding] {
				t.Errorf("%s: %s is deducted twice", name, d.Finding)
			}
			seenIDs[d.Finding] = true
			f, ok := byID[d.Finding]
			if !ok {
				t.Errorf("%s: deduction %s has no finding", name, d.Finding)
				continue
			}
			if f.Severity != d.Severity || d.Points != weights[f.Severity] || d.Points == 0 {
				t.Errorf("%s: deduction %+v does not match finding %s (%s)", name, d, f.ID, f.Severity)
			}
			if f.Category == "pqc" {
				t.Errorf("%s: post-quantum finding %s must not affect hygiene", name, f.ID)
			}
			total += d.Points
		}
		want := 100 - total
		if ev.Hygiene.Ceiling != nil {
			want = ev.Hygiene.Ceiling.Score
		}
		if want < 0 {
			want = 0
		}
		if ev.Hygiene.Score != want || ev.Hygiene.Band != eval.BandFor(want) {
			t.Errorf("%s: score %d band %s, want %d %s", name, ev.Hygiene.Score, ev.Hygiene.Band, want, eval.BandFor(want))
		}
	}
}

func TestTerribleEndpointIsBroken(t *testing.T) {
	h := hygiene(terrible())
	if h.Band != "Broken" || h.Score > 29 {
		t.Errorf("hygiene = %+v", h)
	}
	if len(h.Deductions) == 0 {
		t.Error("no deductions listed")
	}
}

func TestCeilings(t *testing.T) {
	// One high finding alone (an untrusted certificate) costs 20 points, which would be 80 (Sound);
	// the ceiling makes it at most Fair.
	rep := modern()
	rep.Certificates = []tlsprobe.CertResult{cert("RSA", 2048, func(c *tlsprobe.CertResult) { c.Trusted = false })}
	h := hygiene(rep)
	if h.Score != 74 || h.Band != "Fair" || h.Ceiling == nil || h.Ceiling.Score != 74 {
		t.Errorf("one high finding: %+v", h)
	}
}

func TestPostQuantumStateDoesNotChangeHygiene(t *testing.T) {
	hybridRep := modern()
	classical := modern()
	classical.Groups = []tlsprobe.GroupResult{x25519}
	classical.Negotiated = negotiated(x25519)
	a, b := eval.Evaluate(hybridRep, now), eval.Evaluate(classical, now)
	if a.Readiness.Level == b.Readiness.Level {
		t.Fatalf("test setup: readiness should differ (%d vs %d)", a.Readiness.Level, b.Readiness.Level)
	}
	if a.Hygiene.Score != b.Hygiene.Score || a.Hygiene.Band != b.Hygiene.Band {
		t.Errorf("readiness leaked into hygiene: %+v vs %+v", a.Hygiene, b.Hygiene)
	}
}

func TestUnratableWhenNoProtocolAnswers(t *testing.T) {
	h := hygiene(&tlsprobe.Report{Protocols: protocols()})
	if h.Band != eval.BandNotRated || h.Score != -1 {
		t.Errorf("hygiene = %+v", h)
	}
	if !strings.Contains(strings.Join(h.NotMeasured, " "), "could not be rated") {
		t.Errorf("the reason is not stated: %v", h.NotMeasured)
	}
}

// The product must not present its rating as, or borrow the vocabulary of, another scanner's.
func TestRatingVocabularyIsOwn(t *testing.T) {
	h := hygiene(terrible())
	text := strings.ToLower(h.Methodology + " " + strings.Join(h.NotMeasured, " "))
	for _, banned := range []string{"ssl labs", "ssllabs", "qualys", "a+", "grade"} {
		if strings.Contains(text, banned) {
			t.Errorf("rating text contains %q: %s", banned, text)
		}
	}
}
