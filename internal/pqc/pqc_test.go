package pqc

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/collector"
	"github.com/example/cipherhorizon/internal/schematest"
)

// Principle 7: no citation, no verdict.
func TestEveryRuleIsCited(t *testing.T) {
	for i, r := range rules {
		if r.class != Vulnerable && r.class != Safe {
			t.Errorf("rule %d: invalid class %q", i, r.class)
		}
		if strings.TrimSpace(r.rationale) == "" {
			t.Errorf("rule %d (%v): no rationale", i, r.algos)
		}
		if len(r.basis) == 0 {
			t.Errorf("rule %d (%v): no citations", i, r.algos)
		}
		for _, b := range r.basis {
			if b.Title == "" || !strings.HasPrefix(b.URL, "https://") {
				t.Errorf("rule %d: bad citation %+v", i, b)
			}
		}
		if len(r.algos)+len(r.oids)+len(r.arcs) == 0 {
			t.Errorf("rule %d matches nothing", i)
		}
	}
}

// Adding an algorithm to the catalogue without adding its evidence must fail.
func TestEveryCatalogueAlgorithmIsClassified(t *testing.T) {
	for _, a := range algo.All() {
		byName, _ := classify(a.ID, "")
		if a.NoPQCVerdict != "" {
			// A deliberate, reasoned absence: it must really have no rule.
			if byName != nil {
				t.Errorf("%s: declared NoPQCVerdict but a rule matches it", a.ID)
			}
			continue
		}
		if byName == nil {
			t.Errorf("%s: no rule matches its name (classify it, or set NoPQCVerdict with the reason)", a.ID)
			continue
		}
		if a.OID != "" {
			byOID, _ := classify("", a.OID)
			if byOID != byName {
				t.Errorf("%s: OID and name resolve to different rules", a.ID)
			}
		}
	}
}

func TestRulesDoNotOverlapOrContradict(t *testing.T) {
	oids, names, arcs := map[string]int{}, map[string]int{}, map[string]int{}
	for i, r := range rules {
		for _, id := range r.algos {
			a := algo.MustGet(id)
			if j, dup := names[strings.ToLower(a.ID)]; dup {
				t.Errorf("name %s claimed by rules %d and %d", a.ID, j, i)
			}
			names[strings.ToLower(a.ID)] = i
			if a.OID != "" {
				if j, dup := oids[a.OID]; dup {
					t.Errorf("OID %s claimed by rules %d and %d", a.OID, j, i)
				}
				oids[a.OID] = i
			}
		}
		for _, o := range r.oids {
			if j, dup := oids[o]; dup {
				t.Errorf("OID %s claimed by rules %d and %d", o, j, i)
			}
			oids[o] = i
		}
		for _, a := range r.arcs {
			if j, dup := arcs[a]; dup {
				t.Errorf("arc %s claimed by rules %d and %d", a, j, i)
			}
			arcs[a] = i
		}
	}
	// An exact OID that also falls under another rule's arc must agree with it.
	for oid, i := range oids {
		for arc, j := range arcs {
			if underArc(oid, arc) && rules[i].class != rules[j].class {
				t.Errorf("OID %s (%s) lies under arc %s (%s)", oid, rules[i].class, arc, rules[j].class)
			}
		}
	}
}

func algoComp(name, oid string) cdx.Component {
	return cdx.Component{
		BOMRef: "ref:" + name + oid, Name: name, Type: cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm, OID: oid},
	}
}

func verdict(t *testing.T, name, oid string) (Class, string) {
	t.Helper()
	r, how := classify(name, oid)
	if r == nil {
		return "", ""
	}
	return r.class, how
}

func TestVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name, oid string
		want      Class
		how       string
	}{
		{"RSA", "", Vulnerable, `name "RSA"`},
		{"rsa", "", Vulnerable, `name "rsa"`}, // exact, case-insensitive
		{"ECDSA", "", Vulnerable, `name "ECDSA"`},
		{"DH", "", Vulnerable, `name "DH"`},
		{"AES", "", Safe, `name "AES"`},
		{"ML-KEM-768", "", Safe, `name "ML-KEM-768"`},
		{"SLH-DSA-SHAKE-256f", "", Safe, `name "SLH-DSA-SHAKE-256f"`},

		// OID evidence, including names we have never heard of.
		{"whatever", "1.2.840.113549.1.1.1", Vulnerable, "OID 1.2.840.113549.1.1.1"},
		{"SHA256withRSA", "1.2.840.113549.1.1.11", Vulnerable, "OID under arc 1.2.840.113549.1.1"},
		{"RSA-OAEP", "1.2.840.113549.1.1.7", Vulnerable, "OID under arc 1.2.840.113549.1.1"},
		{"ecdsa-with-SHA256", "1.2.840.10045.4.3.2", Vulnerable, "OID under arc 1.2.840.10045"},
		{"secp256r1", "1.2.840.10045.3.1.7", Vulnerable, "OID under arc 1.2.840.10045"},
		{"Ed448", "1.3.101.113", Vulnerable, "OID 1.3.101.113"},
		{"AES-256-GCM", "2.16.840.1.101.3.4.1.46", Safe, "OID 2.16.840.1.101.3.4.1.46"},        // catalogued variant: exact OID
		{"AES-192-GCM", "2.16.840.1.101.3.4.1.26", Safe, "OID under arc 2.16.840.1.101.3.4.1"}, // not catalogued: the arc still classifies it
		{"x", "2.16.840.1.101.3.4.4.2", Safe, "OID 2.16.840.1.101.3.4.4.2"},
		{"x", "2.16.840.1.101.3.4.3.18", Safe, "OID 2.16.840.1.101.3.4.3.18"},

		// OID beats a contradictory name.
		{"AES", "1.2.840.113549.1.1.1", Vulnerable, "OID 1.2.840.113549.1.1.1"},
	} {
		got, how := verdict(t, tc.name, tc.oid)
		if got != tc.want || how != tc.how {
			t.Errorf("classify(%q, %q) = %q via %q; want %q via %q", tc.name, tc.oid, got, how, tc.want, tc.how)
		}
	}
}

// Principle 7: with no evidence, no verdict. Nothing is inferred from a name that
// merely resembles a known algorithm.
func TestUnknownIsUnclassified(t *testing.T) {
	for _, tc := range []struct{ name, oid string }{
		{"SHA256withRSA", ""}, // looks like RSA; no OID, not an exact catalogue name
		{"RSA-2048", ""},
		{"rsa-ish", ""},
		{"Twofish", ""},
		{"Blowfish", "1.3.6.1.4.1.3029.1.2"},
		{"Kyber768", ""},          // pre-standard name; deliberately not guessed
		{"x", "1.2.840.100451.1"}, // shares a string prefix with the EC arc but is not under it
		{"", ""},
	} {
		if got, how := verdict(t, tc.name, tc.oid); got != "" {
			t.Errorf("classify(%q, %q) = %q via %q; want unclassified", tc.name, tc.oid, got, how)
		}
	}
}

func TestUnderArcRespectsComponentBoundaries(t *testing.T) {
	for _, tc := range []struct {
		oid, arc string
		want     bool
	}{
		{"1.2.840.10045", "1.2.840.10045", true},
		{"1.2.840.10045.4.3.2", "1.2.840.10045", true},
		{"1.2.840.100451", "1.2.840.10045", false},
		{"1.2.840", "1.2.840.10045", false},
	} {
		if got := underArc(tc.oid, tc.arc); got != tc.want {
			t.Errorf("underArc(%q, %q) = %v", tc.oid, tc.arc, got)
		}
	}
}

func TestAnalyze(t *testing.T) {
	rsa, aes, mlkem := algo.MustGet("RSA"), algo.MustGet("AES"), algo.MustGet("ML-KEM-768")
	bom, _ := cbom.Build([]collector.CryptoAsset{
		{Component: cdx.Component{BOMRef: "lib1", Type: cdx.ComponentTypeLibrary, Name: "libssl3"}, Provides: []string{rsa.BOMRef(), mlkem.BOMRef()}},
		{Component: cdx.Component{BOMRef: "lib2", Type: cdx.ComponentTypeApplication, Name: "gpg"}, Provides: []string{rsa.BOMRef()}},
		rsa.Asset(), aes.Asset(), mlkem.Asset(),
		{Component: algoComp("Blowfish", "")}, // catalogue-external: unclassified
	}, cbom.Options{})

	rep := Analyze(bom)
	if len(rep.Findings) != 3 || rep.Count(Vulnerable) != 1 || rep.Count(Safe) != 2 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	if len(rep.Unclassified) != 1 || rep.Unclassified[0] != "ref:Blowfish" {
		t.Errorf("unclassified = %v", rep.Unclassified)
	}
	var f Finding
	for _, x := range rep.Findings {
		if x.Name == "RSA" {
			f = x
		}
	}
	if f.Class != Vulnerable || len(f.Basis) == 0 || f.Rationale == "" || f.MatchedBy == "" {
		t.Errorf("RSA finding incomplete: %+v", f)
	}
	if got := strings.Join(f.ProvidedBy, ","); got != "lib1,lib2" {
		t.Errorf("ProvidedBy = %q, want lib1,lib2 (capability providers)", got)
	}
	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i-1].Ref > rep.Findings[i].Ref {
			t.Error("findings not sorted by ref")
		}
	}
	if s := rep.Summary(); !strings.Contains(s, "1 quantum-vulnerable, 2 quantum-safe") || !strings.Contains(s, "1 unclassified") ||
		!strings.Contains(s, "RSA (available via 2 component(s))") {
		t.Errorf("summary:\n%s", s)
	}
}

func TestAnalyzeDoesNotMutateAndHandlesEmpty(t *testing.T) {
	bom, _ := cbom.Build([]collector.CryptoAsset{algo.MustGet("RSA").Asset()}, cbom.Options{})
	before := encodeOf(t, bom)
	Analyze(bom)
	if !bytes.Equal(before, encodeOf(t, bom)) {
		t.Error("Analyze modified the BOM")
	}
	if rep := Analyze(nil); len(rep.Findings) != 0 {
		t.Error("nil BOM")
	}
	if rep := Analyze(&cdx.BOM{}); len(rep.Findings) != 0 {
		t.Error("empty BOM")
	}
	Annotate(nil, Report{})
	Annotate(&cdx.BOM{}, Report{})
}

func TestAnnotate(t *testing.T) {
	rsa := algo.MustGet("RSA")
	unknown := algoComp("Blowfish", "")
	unknown.Properties = &[]cdx.Property{{Name: "keep", Value: "me"}}
	lib := collector.CryptoAsset{Component: cdx.Component{BOMRef: "lib", Type: cdx.ComponentTypeLibrary, Name: "libssl3",
		Properties: &[]cdx.Property{cbom.Property("collector", "apt")}}}
	bom, _ := cbom.Build([]collector.CryptoAsset{lib, rsa.Asset(), {Component: unknown}}, cbom.Options{})

	rep := Analyze(bom)
	Annotate(bom, rep)
	Annotate(bom, rep) // idempotent

	props := func(ref string) map[string][]string {
		out := map[string][]string{}
		for _, c := range *bom.Components {
			if c.BOMRef == ref && c.Properties != nil {
				for _, p := range *c.Properties {
					out[p.Name] = append(out[p.Name], p.Value)
				}
			}
		}
		return out
	}

	r := props(rsa.BOMRef())
	if r["cipherhorizon:pqc:status"][0] != "quantum-vulnerable" || len(r["cipherhorizon:pqc:status"]) != 1 {
		t.Errorf("status = %v (want exactly one after two Annotate calls)", r["cipherhorizon:pqc:status"])
	}
	if len(r["cipherhorizon:pqc:rationale"]) != 1 || len(r["cipherhorizon:pqc:matched-by"]) != 1 {
		t.Errorf("duplicated annotations: %v", r)
	}
	if n := len(r["cipherhorizon:pqc:basis"]); n != len(rep.Findings[0].Basis) || n < 2 {
		t.Errorf("basis entries = %d; want one per citation (%d)", n, len(rep.Findings[0].Basis))
	}
	if !strings.Contains(r["cipherhorizon:pqc:basis"][0], "https://") {
		t.Errorf("basis lacks a URL: %v", r["cipherhorizon:pqc:basis"])
	}

	if p := props("ref:Blowfish"); len(p) != 1 || p["keep"][0] != "me" {
		t.Errorf("unclassified component altered: %v", p)
	}
	if p := props("lib"); len(p) != 1 || p["cipherhorizon:collector"][0] != "apt" {
		t.Errorf("non-algorithm component altered: %v", p)
	}

	schematest.Validate(t, encodeOf(t, bom))
}

func encodeOf(t *testing.T, bom *cdx.BOM) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
