package estate_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/estate"
)

// The estate fixture (PRD-003 AC-COR-1): unique and shared certificates, a wildcard on 40 hosts,
// name collisions and forged imports as hostile decoys. IDs are chosen to make failures readable:
// endpoints 1xx, hosts 2xx, systems 1000+asset.

func fp(n int) string { return strings.Repeat(fmt.Sprintf("%02x", n), 32) }

type fixture struct{ sn estate.Snapshot }

func (f *fixture) endpoint(id int64, host string) int64 {
	f.sn.Assets = append(f.sn.Assets, estate.AssetInfo{ID: id, SystemID: 1000 + id, Kind: "tls-endpoint", Name: host + ":443", Host: host, FirstParty: true})
	return id
}

func (f *fixture) host(id int64, name string, firstParty bool) int64 {
	f.sn.Assets = append(f.sn.Assets, estate.AssetInfo{ID: id, SystemID: 1000 + id, Kind: "host", Name: name, Host: name, FirstParty: firstParty})
	return id
}

// presents: a scan of the endpoint saw this leaf certificate.
func (f *fixture) presents(endpoint int64, cert int, names ...string) {
	f.sn.Sightings = append(f.sn.Sightings, estate.CertSighting{Fingerprint: fp(cert), SystemID: 1000 + endpoint, AssetID: endpoint,
		Stream: estate.StreamNetwork, Class: estate.ClassScanner, Leaf: true, DNSNames: names, Where: "scan"})
}

// holds: a host holds this end-entity certificate, seen by a collector or an import.
func (f *fixture) holds(host int64, cert int, class estate.SourceClass) {
	f.sn.Sightings = append(f.sn.Sightings, estate.CertSighting{Fingerprint: fp(cert), SystemID: 1000 + host, AssetID: host,
		Stream: estate.StreamHost, Class: class, Where: fmt.Sprintf("held on host %d", host)})
}

// holdsImported: an import (attached to a system, not an asset) lists this certificate.
func (f *fixture) holdsImported(system int64, cert int) {
	f.sn.Sightings = append(f.sn.Sightings, estate.CertSighting{Fingerprint: fp(cert), SystemID: system,
		Stream: estate.StreamImported, Class: estate.ClassImported, Where: "listed in an imported document"})
}

func find(cands []estate.Candidate, asset, system int64) *estate.Candidate {
	for i := range cands {
		if cands[i].AssetID == asset && cands[i].SystemID == system {
			return &cands[i]
		}
	}
	return nil
}

// A certificate seen on one endpoint and held by exactly one host, both first-party: the one case
// that may join without a person.
func TestAUniqueFirstPartyCertificateIsAStrongAutoConfirmedJoin(t *testing.T) {
	var f fixture
	e := f.endpoint(101, "shop.example.test")
	h := f.host(201, "web-01", true)
	f.presents(e, 1)
	f.holds(h, 1, estate.ClassCollector)
	got := estate.Correlate(f.sn)
	if len(got) != 1 {
		t.Fatalf("%d candidates: %+v", len(got), got)
	}
	c := got[0]
	if c.AssetID != e || c.SystemID != 1000+h || c.Strength != estate.StrengthStrong || !c.AutoConfirm || c.Ambiguous {
		t.Errorf("candidate = %+v", c)
	}
	if len(c.Rules) != 1 || c.Rules[0].ID != estate.RuleCertificate || !strings.Contains(c.Rules[0].Detail, "held on host 201") || !strings.Contains(c.Rules[0].Detail, fp(1)[:12]) {
		t.Errorf("the explanation does not say what matched: %+v", c.Rules)
	}
}

// REQ-COR-3: the same certificate on several hosts joins none of them by itself.
func TestACertificateOnSeveralHostsIsAmbiguousAndJoinsNothing(t *testing.T) {
	var f fixture
	e := f.endpoint(101, "shop.example.test")
	for i, name := range []string{"web-01", "web-02", "web-03"} {
		f.holds(f.host(int64(201+i), name, true), 1, estate.ClassCollector)
	}
	f.presents(e, 1)
	got := estate.Correlate(f.sn)
	if len(got) != 3 {
		t.Fatalf("%d candidates, want one per holder", len(got))
	}
	for _, c := range got {
		if !c.Ambiguous || c.AutoConfirm || c.Strength != estate.StrengthMedium || !strings.Contains(c.Note, "3 systems") {
			t.Errorf("candidate = %+v", c)
		}
	}
}

// SR-15: a certificate on more systems than the cap is shared infrastructure and joins nothing.
func TestAWildcardOnFortyHostsJoinsNothing(t *testing.T) {
	var f fixture
	e := f.endpoint(101, "app.example.test")
	f.presents(e, 7)
	for i := 0; i < 40; i++ {
		f.holds(f.host(int64(300+i), fmt.Sprintf("node-%02d", i), true), 7, estate.ClassCollector)
	}
	if got := estate.Correlate(f.sn); len(got) != 0 {
		t.Errorf("%d candidates from a widely shared certificate", len(got))
	}
	// Exactly at the cap it still proposes (as ambiguous), one over it does not.
	var g fixture
	e = g.endpoint(101, "app.example.test")
	g.presents(e, 7)
	for i := 0; i < estate.WidelySharedCap; i++ {
		g.holds(g.host(int64(300+i), fmt.Sprintf("node-%02d", i), true), 7, estate.ClassCollector)
	}
	if got := estate.Correlate(g.sn); len(got) != estate.WidelySharedCap {
		t.Errorf("at the cap: %d candidates, want %d", len(got), estate.WidelySharedCap)
	}
}

// SR-05, T-05: a forged imported document carrying a real fingerprint can add a proposal of its
// own, but it can neither be auto-confirmed nor make the legitimate strong join ambiguous.
func TestAForgedImportCannotHijackOrBlockTheRealJoin(t *testing.T) {
	var f fixture
	e := f.endpoint(101, "shop.example.test")
	h := f.host(201, "web-01", true)
	f.presents(e, 1)
	f.holds(h, 1, estate.ClassCollector)
	f.holdsImported(9001, 1) // the forgery: a system that only exists because someone uploaded a file
	got := estate.Correlate(f.sn)
	real, forged := find(got, e, 1000+h), find(got, e, 9001)
	if real == nil || forged == nil {
		t.Fatalf("candidates = %+v", got)
	}
	if !real.AutoConfirm || real.Ambiguous || real.Strength != estate.StrengthStrong {
		t.Errorf("the forgery interfered with the legitimate join: %+v", real)
	}
	if forged.AutoConfirm || forged.Strength != estate.StrengthStrong {
		t.Errorf("the forged candidate must be a plain proposal: %+v", forged)
	}

	// And a forgery alone, with no first-party holder, is only ever proposed.
	var g fixture
	e = g.endpoint(101, "shop.example.test")
	g.presents(e, 2)
	g.holdsImported(9001, 2)
	got = estate.Correlate(g.sn)
	if len(got) != 1 || got[0].AutoConfirm {
		t.Errorf("an imported holder auto-confirmed: %+v", got)
	}
}

// A join through a host imported as an untrusted label is not automatic either.
func TestAnUploadedHostLabelDoesNotAutoConfirmByName(t *testing.T) {
	var f fixture
	e := f.endpoint(101, "web-01.example.test")
	f.endpoint(102, "web-01")
	f.host(201, "web-01", false) // a host known only from an uploaded document
	got := estate.Correlate(f.sn)
	c := find(got, 102, 1201)
	if c == nil || c.Strength != estate.StrengthMedium || c.AutoConfirm {
		t.Errorf("candidate = %+v", c)
	}
	if find(got, e, 1201) != nil {
		t.Error("a host name that merely starts the endpoint's name was matched: fuzzy matching is refused")
	}
}

// The strength table (DN-6): names alone are medium or weak, never strong, never automatic.
func TestNamesAloneAreNeverStrong(t *testing.T) {
	var f fixture
	e1 := f.endpoint(101, "web-01")
	e2 := f.endpoint(102, "shop.example.test")
	h := f.host(201, "web-01", true)
	f.host(202, "shop", true)   // a near-collision: not the same name
	f.presents(e2, 5, "web-01") // a certificate that names the host
	got := estate.Correlate(f.sn)
	j2 := find(got, e1, 1000+h)
	if j2 == nil || j2.Strength != estate.StrengthMedium || j2.AutoConfirm || len(j2.Rules) != 1 || j2.Rules[0].ID != estate.RuleName {
		t.Errorf("J2 = %+v", j2)
	}
	j3 := find(got, e2, 1000+h)
	if j3 == nil || j3.Strength != estate.StrengthWeak || j3.AutoConfirm || j3.Rules[0].ID != estate.RuleSAN {
		t.Errorf("J3 = %+v", j3)
	}
	if find(got, e2, 1202) != nil {
		t.Error("\"shop\" matched \"shop.example.test\": similarity matching is refused")
	}
	// J2 and J3 together on the same pair: medium, still not automatic.
	var g fixture
	ep := g.endpoint(101, "web-01")
	hh := g.host(201, "web-01", true)
	g.presents(ep, 5, "web-01")
	c := find(estate.Correlate(g.sn), ep, 1000+hh)
	if c == nil || len(c.Rules) != 2 || c.Strength != estate.StrengthMedium || c.AutoConfirm {
		t.Errorf("J2+J3 = %+v", c)
	}
	// An endpoint addressed by IP never matches a name.
	var ip fixture
	ip.endpoint(103, "10.0.0.5")
	ip.host(203, "10.0.0.5", true)
	if got := estate.Correlate(ip.sn); len(got) != 0 {
		t.Errorf("an IP address matched a host name: %+v", got)
	}
}

func TestAnEndpointIsNeverProposedToItsOwnSystem(t *testing.T) {
	var f fixture
	e := f.endpoint(101, "web-01")
	f.host(201, "web-01", true)
	f.sn.Assets[0].SystemID = 1201 // the endpoint already belongs to the host's system
	f.presents(e, 1)
	f.sn.Sightings[0].SystemID = 1201
	f.holds(201, 1, estate.ClassCollector)
	if got := estate.Correlate(f.sn); len(got) != 0 {
		t.Errorf("%d candidates for an endpoint already in the system: %+v", len(got), got)
	}
}

// Only leaf certificates an endpoint presents can join; a chain certificate shared with every
// site of a CA must not.
func TestChainCertificatesNeverJoin(t *testing.T) {
	var f fixture
	e := f.endpoint(101, "shop.example.test")
	h := f.host(201, "web-01", true)
	f.sn.Sightings = append(f.sn.Sightings, estate.CertSighting{Fingerprint: fp(3), SystemID: 1000 + e, AssetID: e,
		Stream: estate.StreamNetwork, Class: estate.ClassScanner, Leaf: false, Where: "scan"}) // an intermediate in the chain
	f.holds(h, 3, estate.ClassCollector)
	if got := estate.Correlate(f.sn); len(got) != 0 {
		t.Errorf("a chain certificate joined: %+v", got)
	}
}

// REQ-COR-8: the same inputs in any order give the same candidates in the same order.
func TestCorrelationIsDeterministic(t *testing.T) {
	build := func(seed int64) estate.Snapshot {
		var f fixture
		for i := 0; i < 12; i++ {
			e := f.endpoint(int64(100+i), fmt.Sprintf("svc%d.example.test", i))
			h := f.host(int64(200+i), fmt.Sprintf("host%d", i), i%2 == 0)
			f.presents(e, i%5, fmt.Sprintf("host%d", (i+1)%12))
			f.holds(h, i%5, estate.ClassCollector)
			f.holds(h, (i+2)%5, estate.ClassCollector)
		}
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(f.sn.Assets), func(i, j int) { f.sn.Assets[i], f.sn.Assets[j] = f.sn.Assets[j], f.sn.Assets[i] })
		r.Shuffle(len(f.sn.Sightings), func(i, j int) { f.sn.Sightings[i], f.sn.Sightings[j] = f.sn.Sightings[j], f.sn.Sightings[i] })
		return f.sn
	}
	want := fmt.Sprintf("%+v", estate.Correlate(build(1)))
	for seed := int64(2); seed < 12; seed++ {
		if got := fmt.Sprintf("%+v", estate.Correlate(build(seed))); got != want {
			t.Fatalf("seed %d gives a different result:\n%s\nvs\n%s", seed, got, want)
		}
	}
	if !strings.Contains(want, "AssetID") {
		t.Fatal("nothing was correlated; the fixture proves nothing")
	}
}

// Hostile text in names and locations is bounded in the explanation.
func TestExplanationsAreBounded(t *testing.T) {
	var f fixture
	long := strings.Repeat("A", 5000) + "\x1b[31m"
	e := f.endpoint(101, long)
	f.sn.Assets[0].Host = "web-01"
	f.host(201, "web-01", true)
	f.presents(e, 1)
	f.holds(201, 1, estate.ClassCollector)
	for _, c := range estate.Correlate(f.sn) {
		for _, r := range c.Rules {
			if len(r.Detail) > 400 || strings.ContainsAny(r.Detail, "\x1b") {
				t.Errorf("rule detail of %d bytes: %.60q", len(r.Detail), r.Detail)
			}
		}
	}
}

// REQ-COR-8 / SR-15: the pass is cheap enough to run after every scan and upload. This is a
// design target measured, not a promise: 3,000 endpoints, 3,000 hosts and 9,000 certificate
// sightings, with a few shared ones, complete well inside a second on a developer laptop.
func TestCorrelationScales(t *testing.T) {
	var f fixture
	for i := 0; i < 3000; i++ {
		e := f.endpoint(int64(100000+i), fmt.Sprintf("svc%d.example.test", i))
		h := f.host(int64(200000+i), fmt.Sprintf("host%d", i), true)
		f.presents(e, i)
		f.holds(h, i, estate.ClassCollector)
		if i%50 == 0 {
			f.holds(h, (i+1)%3000, estate.ClassCollector) // some certificates are shared
		}
	}
	start := time.Now()
	got := estate.Correlate(f.sn)
	elapsed := time.Since(start)
	if len(got) < 3000 {
		t.Fatalf("%d candidates from 3000 matching pairs", len(got))
	}
	t.Logf("%d candidates in %s", len(got), elapsed)
	if elapsed.Seconds() > 3 {
		t.Errorf("correlating 3,000 endpoints took %s", elapsed)
	}
}
