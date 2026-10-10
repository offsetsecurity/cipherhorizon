package evidence

import (
	"strings"
	"testing"
)

func present(method, key string, attrs map[string]string) Observation {
	o := Observation{
		Stream: StreamHost, Origin: OriginObserved,
		Subject: Subject{Kind: KindArtefact, Key: key, Name: "x", Attrs: attrs},
		Claim:   Claim{Rung: RungPresent}, Outcome: OutcomeObserved,
		Method: method, Source: Source{Kind: "file", Location: "a/b"}, Privilege: "user",
	}
	Finish(&o)
	return o
}

func derivedCapable(key string, basedOn ...string) Observation {
	o := Observation{
		Stream: StreamHost, Origin: OriginDerived,
		Subject: Subject{Kind: KindAlgorithm, Key: key},
		Claim:   Claim{Rung: RungCapable, Capable: CapableMapped}, Outcome: OutcomeObserved,
		Method: MethodKnowledge, Privilege: "user", BasedOn: basedOn,
		Knowledge: &KnowledgeRef{ID: "k@1", Version: "1"},
	}
	Finish(&o)
	return o
}

func TestValidateAcceptsAWellFormedObservation(t *testing.T) {
	if err := Validate(present(MethodPEVersion, "file:a", map[string]string{"fileVersion": "3.5.7"})); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	base := func() Observation { return present(MethodPEVersion, "file:a", nil) }
	for name, mutate := range map[string]func(*Observation){
		"unknown method":                   func(o *Observation) { o.Method = "made.up@1" },
		"attribute not on the allow-list":  func(o *Observation) { o.Subject.Attrs = map[string]string{"password": "hunter2"} },
		"over-long attribute":              func(o *Observation) { o.Subject.Attrs = map[string]string{"path": strings.Repeat("a", maxAttrLen+1)} },
		"capable kind without capable":     func(o *Observation) { o.Claim = Claim{Rung: RungPresent, Capable: CapableProbed} },
		"policy without a direction":       func(o *Observation) { o.Claim = Claim{Rung: RungPolicy} },
		"bound without a binding kind":     func(o *Observation) { o.Claim = Claim{Rung: RungBound} },
		"host claims exercised":            func(o *Observation) { o.Claim = Claim{Rung: RungExercised} },
		"unknown outcome without a reason": func(o *Observation) { o.Outcome = OutcomeUnknown },
		"reason on an observed outcome":    func(o *Observation) { o.Unknown = &UnknownReason{Code: UnknownError} },
		"confirmed absent from a name":     func(o *Observation) { o.Method, o.Outcome = MethodFSWalkName, OutcomeConfirmedAbsent },
		"derived without BasedOn":          func(o *Observation) { o.Origin = OriginDerived },
		"observed with BasedOn":            func(o *Observation) { o.BasedOn = []string{"obs:x"} },
		"backslash in the source":          func(o *Observation) { o.Source.Location = `a\b` },
		"unknown privilege":                func(o *Observation) { o.Privilege = "root" },
		"relation stronger than its fact": func(o *Observation) {
			o.Relations = []Relation{{Kind: "imports", To: "file:b", Claim: Claim{Rung: RungBound, Binding: BindStaticImport}}}
		},
		"quality raised": func(o *Observation) { o.Downgrade = &QualityLowered{To: QualityAuthoritative, Reason: "trust me"} },
	} {
		t.Run(name, func(t *testing.T) {
			o := base()
			mutate(&o)
			Finish(&o) // the ID is right; the content is what is wrong
			if err := Validate(o); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestValidateRejectsStaleID(t *testing.T) {
	o := present(MethodPEVersion, "file:a", nil)
	o.Subject.Name = "changed after Finish"
	if err := Validate(o); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("err = %v", err)
	}
}

func TestMappedCapabilityMustCiteKnowledge(t *testing.T) {
	o := derivedCapable("algo:RSA", "obs:x")
	o.Knowledge = nil
	Finish(&o)
	if err := Validate(o); err == nil {
		t.Error("a mapped capability without a citation was accepted")
	}
}

func TestIDIsDeterministicAndContentSensitive(t *testing.T) {
	a := present(MethodPEVersion, "file:a", map[string]string{"fileVersion": "3.5.7", "productName": "P"})
	b := present(MethodPEVersion, "file:a", map[string]string{"productName": "P", "fileVersion": "3.5.7"}) // map order differs
	if a.ID != b.ID {
		t.Errorf("same content, different IDs: %s %s", a.ID, b.ID)
	}
	c := present(MethodPEVersion, "file:a", map[string]string{"fileVersion": "3.5.8", "productName": "P"})
	if a.ID == c.ID {
		t.Error("different content, same ID")
	}
}

func TestGraphMergesSameSubjectAcrossMethodsAndKeepsAll(t *testing.T) {
	g := NewGraph(Host{})
	byName := present(MethodFSWalkName, "file:libcrypto", map[string]string{"path": "p", "family": "openssl"})
	byPE := present(MethodPEVersion, "file:libcrypto", map[string]string{"fileVersion": "3.5.7", "family": "openssl"})
	for _, o := range []Observation{byName, byPE} {
		if err := g.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	n, ok := g.Node("file:libcrypto")
	if !ok || len(n.Observations) != 2 {
		t.Fatalf("node = %+v", n)
	}
	if n.Subject.Attrs["fileVersion"] != "3.5.7" || n.Subject.Attrs["path"] != "p" {
		t.Errorf("merged attrs = %v", n.Subject.Attrs)
	}
	if q, _ := n.PresentQuality(); q != QualityParsed {
		t.Errorf("present quality = %s, want the stronger (parsed)", q)
	}
	if len(g.Nodes()) != 1 {
		t.Errorf("nodes = %d", len(g.Nodes()))
	}
}

func TestGraphNameOnlyIsNotSufficientForCapability(t *testing.T) {
	g := NewGraph(Host{})
	if err := g.Add(present(MethodFSWalkName, "file:decoy", nil)); err != nil {
		t.Fatal(err)
	}
	n, _ := g.Node("file:decoy")
	if q, ok := n.PresentQuality(); !ok || q.Sufficient() {
		t.Errorf("a filename match was judged sufficient (%s, %v)", q, ok)
	}
}

func TestGraphStrongerAttrsWin(t *testing.T) {
	g := NewGraph(Host{})
	weak := present(MethodFSWalkName, "file:x", map[string]string{"fileVersion": "0.0.0"})
	strong := present(MethodPEVersion, "file:x", map[string]string{"fileVersion": "3.5.7"})
	// Insert strong first: the outcome must not depend on insertion order.
	for _, o := range []Observation{strong, weak} {
		if err := g.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	n, _ := g.Node("file:x")
	if n.Subject.Attrs["fileVersion"] != "3.5.7" {
		t.Errorf("weaker observation overrode a stronger one: %v", n.Subject.Attrs)
	}
}

func TestGraphDerivedMustRestOnObservationsThatExist(t *testing.T) {
	g := NewGraph(Host{})
	if err := g.Add(derivedCapable("algo:RSA", "obs:missing")); err == nil {
		t.Error("a derived fact resting on nothing was accepted")
	}
	base := present(MethodPEVersion, "file:a", nil)
	if err := g.Add(base); err != nil {
		t.Fatal(err)
	}
	if err := g.Add(derivedCapable("algo:RSA", base.ID)); err != nil {
		t.Errorf("valid derived fact rejected: %v", err)
	}
}

// The central rule: a derived claim may not be stronger than the weakest
// evidence it rests on.
func TestGraphRejectsOverClaimingDerivedFact(t *testing.T) {
	g := NewGraph(Host{})
	base := present(MethodPEVersion, "file:a", nil) // E0
	if err := g.Add(base); err != nil {
		t.Fatal(err)
	}

	over := Observation{
		Stream: StreamHost, Origin: OriginDerived,
		Subject: Subject{Kind: KindArtefact, Key: "file:app"},
		Claim:   Claim{Rung: RungBound, Binding: BindStaticImport}, // E1, resting on E0
		Outcome: OutcomeObserved, Method: MethodKnowledge, Privilege: "user", BasedOn: []string{base.ID},
	}
	Finish(&over)
	if err := g.Add(over); err == nil || !strings.Contains(err.Error(), "claims") {
		t.Errorf("over-claiming derived fact accepted: %v", err)
	}

	relOver := derivedCapable("algo:RSA", base.ID)
	relOver.Relations = []Relation{{Kind: "used-by", To: "file:a", Claim: Claim{Rung: RungLoaded}}}
	relOver.Claim = Claim{Rung: RungCapable, Capable: CapableMapped}
	Finish(&relOver)
	if err := g.Add(relOver); err == nil {
		t.Error("a relation stronger than its inputs was accepted")
	}
}

func TestAddIsIdempotent(t *testing.T) {
	g := NewGraph(Host{})
	o := present(MethodPEVersion, "file:a", nil)
	for i := 0; i < 3; i++ {
		if err := g.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := g.Node("file:a"); len(n.Observations) != 1 {
		t.Errorf("observations = %d", len(n.Observations))
	}
}

func TestClasses(t *testing.T) {
	if E0Existence >= E1Reachable || E1Reachable >= E2Loaded || E2Loaded >= E3Exercised {
		t.Error("classes out of order")
	}
	for claim, want := range map[Rung]Class{
		RungPresent: E0Existence, RungProvisioned: E0Existence, RungCapable: E0Existence, RungPolicy: E0Existence,
		RungBound: E1Reachable, RungLoaded: E2Loaded, RungExercised: E3Exercised,
	} {
		if got := ClassOf(Claim{Rung: claim}); got != want {
			t.Errorf("ClassOf(%s) = %s, want %s", claim, got, want)
		}
	}
	if MinClass(E2Loaded, E0Existence, E3Exercised) != E0Existence {
		t.Error("MinClass is not the minimum")
	}
	if MinClass() != E3Exercised {
		t.Error("MinClass() of nothing should not weaken")
	}
	for c := E0Existence; c <= E3Exercised; c++ {
		if c.Wording() == "" || c.String() == "unknown class" {
			t.Errorf("class %d has no wording", c)
		}
	}
}

func TestQualityOfCanOnlyLower(t *testing.T) {
	o := present(MethodPEVersion, "file:a", nil) // parsed
	o.Downgrade = &QualityLowered{To: QualityHeuristic, Reason: "unusual PE"}
	if q, err := QualityOf(o); err != nil || q != QualityHeuristic {
		t.Errorf("lowering: %v %v", q, err)
	}
	if !QualityAuthoritative.Sufficient() || !QualityParsed.Sufficient() || QualityHeuristic.Sufficient() || QualitySampled.Sufficient() {
		t.Error("Sufficient() is wrong")
	}
}

func TestRedactPath(t *testing.T) {
	for in, want := range map[string]string{
		"Users/alice/AppData/Local/Programs/x": "Users/%USER%/AppData/Local/Programs/x",
		"users/Bob/x":                          "users/%USER%/x",
		"home/carol/.config":                   "home/%USER%/.config",
		"Users/Public/Documents":               "Users/Public/Documents",
		"Program Files/Git/bin":                "Program Files/Git/bin",
		"Users":                                "Users",
		"usr/lib/x":                            "usr/lib/x",
	} {
		if got := RedactPath(in); got != want {
			t.Errorf("RedactPath(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.Contains(RedactPath("Users/alice/x"), "alice") {
		t.Error("a user name survived redaction")
	}
}

func TestMethodsAreDeclaredSanely(t *testing.T) {
	cdxTechniques := set("source-code-analysis", "binary-analysis", "manifest-analysis", "ast-fingerprint", "hash-comparison", "instrumentation", "dynamic-analysis", "filename", "attestation", "other")
	for _, m := range Methods() {
		if !cdxTechniques[m.Technique] {
			t.Errorf("%s: technique %q is not in CycloneDX 1.6's closed list", m.ID, m.Technique)
		}
		if m.Quality.rank() == 0 && m.Quality != QualitySampled {
			t.Errorf("%s: unknown quality %q", m.ID, m.Quality)
		}
		if m.SecretProximity != "none" && m.SecretProximity != "adjacent" {
			t.Errorf("%s: secret proximity %q", m.ID, m.SecretProximity)
		}
	}
}
