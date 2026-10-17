package tlscbom_test

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// AUDIT-TLS-CBOM-001 §3, priority 2: each fact says how it was learned, and the document says what
// was not tested.

// A-5: observed (protocols, certificates and what they state), accepted (groups), derived (what an
// accepted suite's IANA name implies), negotiated (the one handshake).
func TestEvidenceStatesSayHowEachFactWasLearned(t *testing.T) {
	assets := tlscbom.FromTLSReport(negotiatedHybridReport())
	want := map[string][]string{
		"protocol/tls/1.3":                                                     {"observed", "negotiated"},
		"protocol/tls/1.2":                                                     {"observed"},
		"crypto/algorithm/x25519mlkem768":                                      {"accepted", "negotiated"},
		"crypto/algorithm/x25519@1.3.101.110":                                  {"accepted"},
		"crypto/algorithm/ecdh@1.3.132.1.12":                                   {"derived"},
		"crypto/algorithm/rsa-2048@1.2.840.113549.1.1.1":                       {"observed"},
		"crypto/certificate/" + sampleReport().Certificates[0].Chain[0].SHA256: {"observed"},
	}
	for ref, states := range want {
		c := findComponent(assets, ref)
		if c == nil {
			t.Errorf("no component %s", ref)
			continue
		}
		got, _ := property(c, "evidence")
		if got != strings.Join(states, ", ") {
			t.Errorf("%s: evidence %q, want %q", ref, got, strings.Join(states, ", "))
		}
	}
	// Every component says how it was learned.
	for _, a := range assets {
		if _, ok := property(&a, "evidence"); !ok {
			t.Errorf("%s has no evidence state", a.Component.BOMRef)
		}
	}
}

// A-14: a negotiated component names the version of the handshake that used it.
func TestNegotiatedFlagNamesTheVersion(t *testing.T) {
	assets := tlscbom.FromTLSReport(negotiatedHybridReport())
	c := findComponent(assets, "crypto/algorithm/x25519mlkem768")
	if v, _ := property(c, "negotiated-in"); v != "TLSv1.3" {
		t.Errorf("negotiated-in = %q, want TLSv1.3", v)
	}
	if v, _ := property(c, "negotiated"); v != "true" {
		t.Errorf("negotiated = %q: the flag must keep its value for existing consumers", v)
	}
}

// A-6: the stages reach the document's metadata, so an absent component can be told from an
// untested one.
func TestCBOMStatesWhatWasNotTested(t *testing.T) {
	rep := sampleReport()
	rep.Incomplete = true
	rep.Stages = []tlsprobe.Stage{
		{Name: tlsprobe.StageProtocols, Outcome: tlsprobe.OutcomeDone},
		{Name: tlsprobe.StageKeyExchange, Outcome: tlsprobe.OutcomeDone, Inconclusive: []string{"secp521r1 timed out"}},
		{Name: tlsprobe.StageHTTP, Outcome: tlsprobe.OutcomeSkipped, ReasonCode: tlsprobe.ReasonOptionOff, Reason: "HTTP checks are off"},
	}
	got := map[string]string{}
	for _, p := range tlscbom.Coverage(rep) {
		got[strings.TrimPrefix(p.Name, cbom.PropertyNamespace+":")] = p.Value
	}
	for k, v := range map[string]string{
		"scan-complete":         "false",
		"coverage:protocols":    "done",
		"coverage:key-exchange": "done; inconclusive: secp521r1 timed out",
		"coverage:http":         "not tested: HTTP checks are off",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if !strings.Contains(got["mapping"], "IANA TLS cipher suites retrieved") {
		t.Errorf("mapping = %q", got["mapping"])
	}
}

// A-15: the same report gives the same document, byte for byte, once the serial number and the
// timestamp (which differ by design) are fixed.
func TestCBOMIsDeterministicApartFromSerialAndTime(t *testing.T) {
	first := encode17(t, tlscbom.FromTLSReport(negotiatedHybridReport()))
	for i := 0; i < 5; i++ {
		if again := encode17(t, tlscbom.FromTLSReport(negotiatedHybridReport())); again != first {
			t.Fatal("two CBOMs of the same report differ")
		}
	}
}
