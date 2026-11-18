package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// REQ-POL-1, REQ-POL-2: the embedded catalog loads and passes every rule.
func TestTheEmbeddedCatalogIsValid(t *testing.T) {
	c, err := Parse(Raw())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Documents) == 0 || len(c.Milestones) == 0 || len(c.Profiles) == 0 {
		t.Fatalf("catalog is missing a section: %d documents, %d milestones, %d profiles", len(c.Documents), len(c.Milestones), len(c.Profiles))
	}
	if Default() == nil {
		t.Fatal("Default returned nil")
	}
}

// REQ-POL-2: every rule of ADR-0022 refuses a catalog that breaks it.
func TestValidateRefusesEachBrokenRule(t *testing.T) {
	base := func() map[string]any {
		var m map[string]any
		if err := json.Unmarshal(Raw(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	doc := func(m map[string]any, i int) map[string]any { return m["documents"].([]any)[i].(map[string]any) }
	ms := func(m map[string]any, i int) map[string]any { return m["milestones"].([]any)[i].(map[string]any) }
	prof := func(m map[string]any, i int) map[string]any { return m["profiles"].([]any)[i].(map[string]any) }
	draftIndex := func(m map[string]any) int {
		for i, d := range m["documents"].([]any) {
			if d.(map[string]any)["status"] == StatusDraft {
				return i
			}
		}
		t.Fatal("the catalog lists no draft to test with")
		return -1
	}

	cases := []struct {
		name, want string
		mutate     func(m map[string]any)
	}{
		{"no version", "no version", func(m map[string]any) { m["version"] = "" }},
		{"bad status", "status", func(m map[string]any) { doc(m, 0)["status"] = "approved" }},
		{"plain http", "https", func(m map[string]any) { doc(m, 0)["url"] = "http://example.org/x" }},
		{"bad date", "published", func(m map[string]any) { doc(m, 0)["published"] = "2024-13-01" }},
		{"no provenance", "provenance is empty", func(m map[string]any) { doc(m, 0)["provenance"] = " " }},
		{"control character", "control character", func(m map[string]any) { doc(m, 0)["title"] = "a\nb" }},
		{"duplicate document", "duplicate id", func(m map[string]any) { doc(m, 1)["id"] = doc(m, 0)["id"] }},
		{"bad family", "family", func(m map[string]any) { doc(m, 0)["families"] = []any{"RSA; DROP"} }},
		{"unknown document", "not in the catalog", func(m map[string]any) { ms(m, 0)["document"] = "nope" }},
		{"draft basis", "cannot rest on a draft", func(m map[string]any) {
			ms(m, 0)["document"] = doc(m, draftIndex(m))["id"]
		}},
		{"bad effect", "effect", func(m map[string]any) { ms(m, 0)["effect"] = "banned" }},
		{"bad relation", "relation", func(m map[string]any) { ms(m, 0)["relation"] = "before" }},
		{"month-only milestone date", "date", func(m map[string]any) { ms(m, 0)["date"] = "2030-12" }},
		{"bad scope", "scope", func(m map[string]any) { ms(m, 0)["scope"] = "eu" }},
		{"dangling profile reference", "not in the catalog", func(m map[string]any) { prof(m, 0)["milestones"] = []any{"missing"} }},
		{"empty profile", "lists no milestones", func(m map[string]any) { prof(m, 0)["milestones"] = []any{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(m)
			b, _ := json.Marshal(m)
			_, err := Parse(b)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}

	// A draft may still back a recommendation: a reader can be pointed at it.
	m := base()
	ms(m, 0)["document"] = doc(m, draftIndex(m))["id"]
	ms(m, 0)["effect"] = EffectRecommended
	b, _ := json.Marshal(m)
	if _, err := Parse(b); err != nil {
		t.Fatalf("a recommendation resting on a draft was refused: %v", err)
	}

	// Unknown fields are a typo, not an extension.
	m = base()
	doc(m, 0)["statsu"] = "final"
	b, _ = json.Marshal(m)
	if _, err := Parse(b); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}

// "After 2030" runs from the first instant of 2031; "by" a day includes that whole day.
func TestCutoffIsTheLastInstantOfTheDay(t *testing.T) {
	m := Default().MustMilestone("ir8547.signatures-deprecated")
	if got, want := m.Cutoff(), time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("cutoff %v, want %v", got, want)
	}
	d := Default().MustMilestone("ir8547.signatures-disallowed")
	if got := d.Cutoff(); got.Year() != 2035 || got.Month() != 12 || got.Day() != 31 {
		t.Fatalf("disallowed after 2035 must be the end of 2035, got %v", got)
	}
}

// The facts the evaluation rests on are the documents' own: IR 8547 is final, and its public-key
// milestones say deprecated after 2030 and disallowed after 2035 for both signatures and key establishment.
func TestTheIR8547MilestonesMatchTheDocument(t *testing.T) {
	c := Default()
	d, ok := c.Document("nist-ir-8547")
	if !ok || d.Status != StatusFinal || d.Published != "2026-10-27" {
		t.Fatalf("IR 8547 entry: %+v", d)
	}
	for id, want := range map[string]string{
		"ir8547.signatures-deprecated":        "2030-12-31",
		"ir8547.key-establishment-deprecated": "2030-12-31",
		"ir8547.signatures-disallowed":        "2035-12-31",
		"ir8547.key-establishment-disallowed": "2035-12-31",
	} {
		m := c.MustMilestone(id)
		if m.Date != want || m.Relation != RelationAfter || m.Document != "nist-ir-8547" || m.Scope != ScopeGeneral {
			t.Errorf("%s: %+v", id, m)
		}
	}
	for _, id := range []string{"nist-sp-800-131a-r3", "nist-fips-206"} {
		if d, ok := c.Document(id); !ok || d.Status != StatusDraft {
			t.Errorf("%s must be listed as a draft until it is final: %+v", id, d)
		}
	}
}
