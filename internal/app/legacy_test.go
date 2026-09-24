package app_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The host inventory became an evidence pipeline (ADR-0001, ADR-0010). What a
// Debian/Ubuntu package inventory *says* must not have changed: this test holds the
// current output to the frozen pre-refactor output (testing/golden/legacy).
//
// The current output may add properties (claim, method, coverage, ...). It may not
// add or drop a component, change one, change an edge, or change or drop any
// property the old output carried.

type legacyBOM struct {
	Metadata struct {
		Component struct {
			BOMRef string `json:"bom-ref"`
			Type   string `json:"type"`
			Name   string `json:"name"`
		} `json:"component"`
	} `json:"metadata"`
	Components   []legacyComponent  `json:"components"`
	Dependencies []legacyDependency `json:"dependencies"`
}

type legacyComponent struct {
	BOMRef     string            `json:"bom-ref"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Purl       string            `json:"purl"`
	Properties []legacyProperty  `json:"properties"`
	Evidence   *legacyEvidence   `json:"evidence"`
	Crypto     json.RawMessage   `json:"cryptoProperties"`
	Other      map[string]string `json:"-"`
}

type legacyProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type legacyEvidence struct {
	Occurrences []struct {
		Location string `json:"location"`
	} `json:"occurrences"`
}

type legacyDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
	Provides  []string `json:"provides"`
}

func decodeBOM(t *testing.T, raw []byte) legacyBOM {
	t.Helper()
	var b legacyBOM
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (c legacyComponent) props() map[string][]string {
	m := map[string][]string{}
	for _, p := range c.Properties {
		m[p.Name] = append(m[p.Name], p.Value)
	}
	return m
}

func (c legacyComponent) locations() []string {
	var out []string
	if c.Evidence != nil {
		for _, o := range c.Evidence.Occurrences {
			out = append(out, o.Location)
		}
	}
	sort.Strings(out)
	return out
}

func TestLegacyOutputIsPreserved(t *testing.T) {
	for _, name := range []string{"ubuntu-24.04", "debian-13"} {
		t.Run(name, func(t *testing.T) {
			oldRaw, err := os.ReadFile(filepath.Join(goldenDir, "legacy", name+".cbom.json"))
			if err != nil {
				t.Fatal(err)
			}
			old := decodeBOM(t, oldRaw)

			code, stdout, stderr := run(t, "run", "--root", fixture(name))
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			cur := decodeBOM(t, []byte(stdout))

			// The subject is unchanged.
			if old.Metadata.Component != cur.Metadata.Component {
				t.Errorf("metadata.component changed: %+v -> %+v", old.Metadata.Component, cur.Metadata.Component)
			}

			// Exactly the same components.
			oldBy, curBy := map[string]legacyComponent{}, map[string]legacyComponent{}
			for _, c := range old.Components {
				oldBy[c.BOMRef] = c
			}
			for _, c := range cur.Components {
				curBy[c.BOMRef] = c
			}
			for ref := range oldBy {
				if _, ok := curBy[ref]; !ok {
					t.Errorf("component %s disappeared", ref)
				}
			}
			for ref := range curBy {
				if _, ok := oldBy[ref]; !ok {
					t.Errorf("component %s appeared: the package inventory changed", ref)
				}
			}

			for ref, o := range oldBy {
				c, ok := curBy[ref]
				if !ok {
					continue
				}
				if o.Type != c.Type || o.Name != c.Name || o.Version != c.Version || o.Purl != c.Purl {
					t.Errorf("%s: identity changed: %+v -> %+v", ref, o, c)
				}
				if string(o.Crypto) != string(c.Crypto) {
					t.Errorf("%s: cryptoProperties changed:\n old %s\n new %s", ref, o.Crypto, c.Crypto)
				}
				if !reflect.DeepEqual(o.locations(), c.locations()) {
					t.Errorf("%s: evidence locations changed: %v -> %v", ref, o.locations(), c.locations())
				}
				// Every old property survives with the same values, in the same relative order.
				curProps := c.props()
				for k, want := range o.props() {
					if !reflect.DeepEqual(curProps[k], want) {
						t.Errorf("%s: property %s changed: %v -> %v", ref, k, want, curProps[k])
					}
				}
			}

			// Exactly the same edges.
			edges := func(b legacyBOM) map[string]string {
				m := map[string]string{}
				for _, d := range b.Dependencies {
					if d.Ref == b.Metadata.Component.BOMRef {
						continue
					}
					dep, prov := append([]string(nil), d.DependsOn...), append([]string(nil), d.Provides...)
					sort.Strings(dep)
					sort.Strings(prov)
					m[d.Ref] = "dependsOn=" + strings.Join(dep, ",") + " provides=" + strings.Join(prov, ",")
				}
				return m
			}
			oe, ce := edges(old), edges(cur)
			if !reflect.DeepEqual(oe, ce) {
				for k, v := range oe {
					if ce[k] != v {
						t.Errorf("edges of %s changed:\n old %s\n new %s", k, v, ce[k])
					}
				}
				for k := range ce {
					if _, ok := oe[k]; !ok {
						t.Errorf("new edges appeared for %s: %s", k, ce[k])
					}
				}
			}
		})
	}
}

// What the pipeline adds is the point of it: every inventoried component says what
// kind of statement it is and how it was found, every provides edge is labelled as
// a mapped capability, and the document says what it could not see.
func TestCurrentOutputCarriesClaimsAndCoverage(t *testing.T) {
	_, stdout, _ := run(t, "run", "--root", fixture("debian-13"))
	cur := decodeBOM(t, []byte(stdout))

	var sawProvider bool
	for _, c := range cur.Components {
		if c.Type == "cryptographic-asset" {
			continue
		}
		p := c.props()
		for _, k := range []string{"cipherhorizon:claim", "cipherhorizon:method", "cipherhorizon:method-quality"} {
			if len(p[k]) != 1 {
				t.Errorf("%s: missing %s", c.BOMRef, k)
			}
		}
		if p["cipherhorizon:claim"][0] != "present" || p["cipherhorizon:method-quality"][0] != "authoritative" {
			t.Errorf("%s: claim/quality = %v / %v", c.BOMRef, p["cipherhorizon:claim"], p["cipherhorizon:method-quality"])
		}
		hasProvides := false
		for _, d := range cur.Dependencies {
			if d.Ref == c.BOMRef && len(d.Provides) > 0 {
				hasProvides, sawProvider = true, true
			}
		}
		// A provides edge must always be labelled as a mapped capability, never left ambiguous.
		if hasProvides != (len(p["cipherhorizon:provides-claim"]) == 1 && p["cipherhorizon:provides-claim"][0] == "capable-mapped") {
			t.Errorf("%s: provides edges and the provides-claim label disagree", c.BOMRef)
		}
	}
	if !sawProvider {
		t.Fatal("no component provides anything: the fixture no longer exercises capability")
	}

	// The document states its privilege tier and what it cannot see.
	var raw struct {
		Metadata struct {
			Properties []legacyProperty `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatal(err)
	}
	meta := map[string][]string{}
	for _, p := range raw.Metadata.Properties {
		meta[p.Name] = append(meta[p.Name], p.Value)
	}
	if meta["cipherhorizon:privilege-tier"][0] != "user" {
		t.Errorf("privilege-tier = %v", meta["cipherhorizon:privilege-tier"])
	}
	if len(meta["cipherhorizon:coverage"]) == 0 || len(meta["cipherhorizon:not-seen"]) == 0 {
		t.Errorf("the document does not state coverage or blind spots: %v", meta)
	}
	if len(meta["cipherhorizon:coverage-note"]) != 1 || !strings.Contains(meta["cipherhorizon:coverage-note"][0], "elevated") {
		t.Errorf("a user-tier run must carry the privilege note: %v", meta["cipherhorizon:coverage-note"])
	}
}
