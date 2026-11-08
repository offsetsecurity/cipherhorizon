package app

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
)

// CRYPTO-REVIEW-004 item 15: old bundled root stores are said beside the verdict, not scored.
func TestVerdictWarnsAboutOldRootStores(t *testing.T) {
	ev := eval.Evaluation{Readiness: eval.Readiness{Level: -1}, Hygiene: eval.Hygiene{Score: 90, Band: "Good"},
		ReferenceData: []eval.RefInfo{
			{Name: "Published DH groups", Retrieved: "2026-01-01", AgeDays: 300, Stale: true},
			{Name: "Mozilla root store", Retrieved: "2026-11-04", AgeDays: 45, Stale: true},
		}}
	var b strings.Builder
	if err := writeVerdict(&b, "example.test:443", ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "root stores in this version were retrieved 2026-11-04 (45 days before this evaluation)") {
		t.Errorf("no warning about old root stores:\n%s", b.String())
	}

	ev.ReferenceData[1].Stale = false
	b.Reset()
	if err := writeVerdict(&b, "example.test:443", ev); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "root stores in this version") {
		t.Errorf("warned although the root stores are current (an old DH list is not a trust problem):\n%s", b.String())
	}
}
