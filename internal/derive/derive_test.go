package derive

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
)

func pkgObs(name, version, family string) evidence.Observation {
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindPackage, Key: "pkg:" + name, Name: name,
			Attrs: map[string]string{"name": name, "version": version, "family": family, "kind": "library"}},
		Claim: evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
		Method: evidence.MethodDpkgStatus, Source: evidence.Source{Kind: "database", Location: "var/lib/dpkg/status"}, Privilege: "user",
	}
	evidence.Finish(&o)
	return o
}

func fileObs(method, key string, attrs map[string]string) evidence.Observation {
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindArtefact, Key: key, Name: "f", Attrs: attrs},
		Claim:   evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
		Method: method, Source: evidence.Source{Kind: "file", Location: "a/b"}, Privilege: "user",
	}
	evidence.Finish(&o)
	return o
}

func algos(g *evidence.Graph) map[string]bool {
	out := map[string]bool{}
	for _, n := range g.Nodes() {
		if n.Subject.Kind == evidence.KindAlgorithm {
			out[n.Subject.Name] = true
		}
	}
	return out
}

func TestPackageCapabilities(t *testing.T) {
	g := evidence.NewGraph(evidence.Host{})
	if err := g.Add(pkgObs("libssl3t64", "3.5.1-1", "openssl")); err != nil {
		t.Fatal(err)
	}
	if err := Capabilities(g); err != nil {
		t.Fatal(err)
	}
	got := algos(g)
	for _, want := range []string{"RSA", "AES", "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHAKE-256f"} {
		if !got[want] {
			t.Errorf("3.5.1 should provide %s", want)
		}
	}
	if len(got) != 27 {
		t.Errorf("%d algorithms, want 27", len(got))
	}
}

func TestCapabilityIsCitedAndRestsOnItsInput(t *testing.T) {
	g := evidence.NewGraph(evidence.Host{})
	base := pkgObs("libssl3", "3.0.13-1", "openssl")
	_ = g.Add(base)
	if err := Capabilities(g); err != nil {
		t.Fatal(err)
	}
	n, _ := g.Node("algo:RSA")
	d := n.Derived()
	if len(d) != 1 {
		t.Fatalf("derived = %d", len(d))
	}
	o := d[0]
	if o.Origin != evidence.OriginDerived || len(o.BasedOn) != 1 || o.BasedOn[0] != base.ID {
		t.Errorf("does not name its input: %+v", o)
	}
	if o.Knowledge == nil || len(o.Knowledge.Citations) == 0 || !strings.HasPrefix(o.Knowledge.ID, "capability/openssl@") {
		t.Errorf("not cited: %+v", o.Knowledge)
	}
	if o.Claim.Rung != evidence.RungCapable || o.Claim.Capable != evidence.CapableMapped {
		t.Errorf("claim = %+v", o.Claim)
	}
	if len(o.Relations) != 1 || o.Relations[0].Kind != RelProvidedBy || o.Relations[0].To != "pkg:libssl3" {
		t.Errorf("relations = %+v", o.Relations)
	}
}

func TestUnparseableVersionOmitsGatedCapabilities(t *testing.T) {
	g := evidence.NewGraph(evidence.Host{})
	_ = g.Add(pkgObs("libssl3", "unknown", "openssl"))
	if err := Capabilities(g); err != nil {
		t.Fatal(err)
	}
	got := algos(g)
	if !got["RSA"] || got["ML-KEM-768"] {
		t.Errorf("got %v", got)
	}
}

func TestInventoryOnlyFamilyGetsNoCapabilities(t *testing.T) {
	g := evidence.NewGraph(evidence.Host{})
	_ = g.Add(pkgObs("libgcrypt20", "1.10.3-2", "libgcrypt"))
	if err := Capabilities(g); err != nil {
		t.Fatal(err)
	}
	if len(algos(g)) != 0 {
		t.Errorf("uncurated family credited: %v", algos(g))
	}
}

// A file recognised only by its name is not evidence enough: the decoy control.
func TestNameOnlyArtefactIsNeverCapable(t *testing.T) {
	g := evidence.NewGraph(evidence.Host{})
	_ = g.Add(fileObs(evidence.MethodFSWalkName, "file:decoy", map[string]string{"family": "openssl", "path": "a/libcrypto-3-x64.dll", "kind": "library"}))
	if err := Capabilities(g); err != nil {
		t.Fatal(err)
	}
	if len(algos(g)) != 0 {
		t.Errorf("a filename match was credited with capabilities: %v", algos(g))
	}
}

func TestParsedArtefactIsCapable(t *testing.T) {
	g := evidence.NewGraph(evidence.Host{})
	_ = g.Add(fileObs(evidence.MethodFSWalkName, "file:real", map[string]string{"family": "openssl", "kind": "library"}))
	_ = g.Add(fileObs(evidence.MethodPEVersion, "file:real", map[string]string{"family": "openssl", "fileVersion": "3.5.7"}))
	if err := Capabilities(g); err != nil {
		t.Fatal(err)
	}
	got := algos(g)
	if !got["ML-KEM-768"] || len(got) != 27 {
		t.Errorf("3.5.7 PE: %d algorithms", len(got))
	}
	// The derived fact rests on the *parsed* observation, not the name match.
	n, _ := g.Node("algo:ML-KEM-768")
	base, _ := g.Observation(n.Derived()[0].BasedOn[0])
	if base.Method != evidence.MethodPEVersion {
		t.Errorf("rests on %s, want the parsed observation", base.Method)
	}
}

func TestParsedArtefactWithoutAVersionGetsUngatedOnly(t *testing.T) {
	g := evidence.NewGraph(evidence.Host{})
	_ = g.Add(fileObs(evidence.MethodPEVersion, "file:nover", map[string]string{"family": "openssl", "peValid": "true"}))
	if err := Capabilities(g); err != nil {
		t.Fatal(err)
	}
	got := algos(g)
	if !got["RSA"] || got["ML-KEM-768"] {
		t.Errorf("got %v", got)
	}
}

func TestDeterministic(t *testing.T) {
	build := func() []string {
		g := evidence.NewGraph(evidence.Host{})
		_ = g.Add(pkgObs("libssl3t64", "3.5.1-1", "openssl"))
		_ = g.Add(pkgObs("gpg", "2.4.4-2", "gnupg"))
		_ = Capabilities(g)
		var ids []string
		for _, n := range g.Nodes() {
			for _, o := range n.Observations {
				ids = append(ids, o.ID)
			}
		}
		return ids
	}
	a, b := build(), build()
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Error("two runs produced different observations")
	}
}
