package eval_test

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
)

// Client simulation (PRD-018): every profile names only registry suites and groups, and the
// outcomes on known servers are the ones a real handshake would give.

func simOf(t *testing.T, ev eval.Evaluation, id string) eval.ClientSim {
	t.Helper()
	for _, c := range ev.Clients {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("client %s missing", id)
	return eval.ClientSim{}
}

func TestClientProfilesNameOnlyRegistryEntries(t *testing.T) {
	suites := map[string]bool{}
	for _, s := range registry.Suites() {
		suites[s.Name] = true
	}
	groups := map[string]bool{}
	for _, g := range registry.Groups() {
		groups[strings.ToLower(g.Name)] = true
	}
	ids := map[string]bool{}
	for _, p := range eval.Clients() {
		if ids[p.ID] {
			t.Errorf("duplicate client id %s", p.ID)
		}
		ids[p.ID] = true
		if p.Name == "" || p.Source == "" || p.Released == "" || len(p.Versions) == 0 || len(p.SigAlgs) == 0 {
			t.Errorf("%s: a profile names its name, source, release, versions and signature algorithms", p.ID)
		}
		for _, n := range append(append([]string(nil), p.Suites13...), p.Suites12...) {
			if !suites[n] {
				t.Errorf("%s: suite %s is not in the IANA registry", p.ID, n)
			}
		}
		for _, g := range p.Groups {
			if !groups[strings.ToLower(g)] {
				t.Errorf("%s: group %s is not in the IANA registry", p.ID, g)
			}
		}
		for _, v := range p.Versions {
			if v == "TLSv1.3" && len(p.Suites13) == 0 {
				t.Errorf("%s: offers TLS 1.3 without TLS 1.3 suites", p.ID)
			}
		}
	}
}

func TestClientSimulationOnKnownServers(t *testing.T) {
	// The modern server: TLS 1.3 and 1.2, ECDHE AES-GCM, X25519MLKEM768 and X25519, RSA-2048.
	ev := eval.Evaluate(modern(), now)
	if len(ev.Clients) != len(eval.Clients()) {
		t.Fatalf("%d simulations for %d clients", len(ev.Clients), len(eval.Clients()))
	}
	chrome := simOf(t, ev, "chrome-131")
	if !chrome.Connects || chrome.Version != "TLSv1.3" || !chrome.PQ || chrome.Group != "X25519MLKEM768" || !chrome.ForwardSecrecy {
		t.Errorf("chrome: %+v", chrome)
	}
	// Safari 17 has no post-quantum group: X25519, no retry, no PQ.
	saf := simOf(t, ev, "safari-17")
	if !saf.Connects || saf.PQ || saf.Group != "x25519" || saf.HelloRetry {
		t.Errorf("safari 17: %+v", saf)
	}
	// Java 8 offers no x25519 and the modern fixture accepts only the hybrid and x25519 on TLS 1.3,
	// and no TLS 1.2 curves were enumerated: TLS 1.3 fails on groups, so the simulation says why.
	j8 := simOf(t, ev, "java-8")
	if j8.Connects || !strings.Contains(j8.Why, "no common key-exchange group") {
		t.Errorf("java 8: %+v", j8)
	}
	// Java 6 speaks TLS 1.0 only: no common version.
	j6 := simOf(t, ev, "java-6")
	if j6.Connects || !strings.Contains(j6.Why, "no common protocol version") {
		t.Errorf("java 6: %+v", j6)
	}
	sum := eval.SummariseClients(ev.Clients)
	if sum == nil || sum.Connect == 0 || sum.Fail == 0 || sum.PQ == 0 {
		t.Errorf("summary: %+v", sum)
	}
}

func TestClientSimulationRespectsServerOrderAndLegacyLimits(t *testing.T) {
	// A TLS 1.2-only server that ranks a static RSA suite first, then ECDHE: a server-order client
	// gets the server's favourite; a DH-capped client sees the DHE limit.
	rsa := suite("TLSv1.2", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES", "CBC", 128, 128, false, false)
	rsa.Rank, rsa.MAC = 1, "SHA1"
	ecdhe := suite("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES", "GCM", 128, 128, true, true)
	ecdhe.Rank = 2
	dhe := suite("TLSv1.2", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "AES", "CBC", 128, 128, false, true)
	dhe.Rank, dhe.MAC = 3, "SHA1"
	rep := &tlsprobe.Report{
		Protocols:    protocols("TLSv1.2", "TLSv1.0"),
		Suites:       []tlsprobe.SuiteResult{rsa, ecdhe, dhe},
		Groups:       []tlsprobe.GroupResult{{Version: "TLSv1.2", ID: 23, Name: "secp256r1"}},
		DH:           &tlsprobe.DHResult{PrimeBits: 2048},
		Preference:   []tlsprobe.PreferenceResult{{Version: "TLSv1.2", Subject: "suites", Order: "server"}},
		Certificates: []tlsprobe.CertResult{cert("RSA", 2048)},
	}
	ev := eval.Evaluate(rep, now)
	chrome := simOf(t, ev, "chrome-131")
	if !chrome.Connects || chrome.Version != "TLSv1.2" || chrome.Suite != "TLS_RSA_WITH_AES_128_CBC_SHA" || chrome.ForwardSecrecy || chrome.Decided != "server" {
		t.Errorf("chrome on a static-RSA-first server: %+v", chrome)
	}
	// Java 7: TLS 1.0 only. The TLS 1.0 suite list is empty in this fixture, so it fails on suites.
	j7 := simOf(t, ev, "java-7")
	if j7.Connects || j7.Version != "TLSv1.0" {
		t.Errorf("java 7: %+v", j7)
	}
	// Give TLS 1.0 the DHE suite only, with a 2048-bit prime: Java 7's 1024-bit cap fails it, by name.
	dhe10 := dhe
	dhe10.Version = "TLSv1.0"
	rep.Suites = append(rep.Suites, dhe10)
	j7 = simOf(t, eval.Evaluate(rep, now), "java-7")
	if j7.Connects || !strings.Contains(j7.Why, "2048 bits") {
		t.Errorf("java 7 with a 2048-bit DHE prime: %+v", j7)
	}
	// An ML-DSA-only server: classical clients cannot verify the certificate.
	pq := modern()
	pq.Certificates = []tlsprobe.CertResult{cert("ML-DSA-65", 0)}
	ff := simOf(t, eval.Evaluate(pq, now), "firefox-132")
	if ff.Connects || !strings.Contains(ff.Why, "post-quantum (ML-DSA) certificate") {
		t.Errorf("firefox on an ML-DSA-only server: %+v", ff)
	}
	// A legacy client that sends no SNI is told it gets the default certificate.
	noSNI := modern()
	noSNI.Protocols = protocols("TLSv1.3", "TLSv1.2", "TLSv1.0")
	noSNI.Suites = append(noSNI.Suites, func() tlsprobe.SuiteResult { s := rsa; s.Version = "TLSv1.0"; return s }())
	noSNI.NoSNI = "CN=default.example"
	j6 := simOf(t, eval.Evaluate(noSNI, now), "java-6")
	if !j6.Connects || !j6.DefaultCertificate || !strings.Contains(j6.Note, "default.example") {
		t.Errorf("java 6 without SNI: %+v", j6)
	}
}

func TestClientSimulationNeedsTheEnumeration(t *testing.T) {
	rep := &tlsprobe.Report{Protocols: protocols("TLSv1.3"), Stages: []tlsprobe.Stage{{Name: tlsprobe.StageProtocols, Outcome: tlsprobe.OutcomeDone},
		{Name: tlsprobe.StageSuites, Outcome: tlsprobe.OutcomeSkipped}}}
	if ev := eval.Evaluate(rep, now); len(ev.Clients) != 0 {
		t.Errorf("clients simulated without a suite enumeration: %d", len(ev.Clients))
	}
}
