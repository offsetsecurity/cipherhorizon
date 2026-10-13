package eval

import (
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// An exposed attack is never shown under a "good" section, and a line that says "not
// exposed" reads as a result, not as a finding (the morafinance report: LUCKY13 exposed
// under a green "Good"; BEAST "not exposed — TLS 1.0 with CBC suites" read as found).
func TestVulnerabilitiesSectionAgreesWithItsAttacks(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	rep := &tlsprobe.Report{
		SchemaVersion: "tls-report/2",
		Target:        tlsprobe.Target{Host: "cbc.example", Port: 443},
		Protocols: []tlsprobe.ProtocolResult{
			{Version: "TLSv1.3", Supported: false, Evidence: "alert"},
			{Version: "TLSv1.2", Supported: true, Evidence: "server-hello"},
			{Version: "TLSv1.0", Supported: false, Evidence: "alert"},
		},
		Suites: []tlsprobe.SuiteResult{
			{Version: "TLSv1.2", Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Cipher: "AES", KeyBits: 128, Mode: "GCM", Kx: "ECDHE", Ephemeral: true, AEAD: true, IANARecommended: "Y"},
			{Version: "TLSv1.2", Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Cipher: "AES", KeyBits: 128, Mode: "CBC", Kx: "ECDHE", Ephemeral: true, IANARecommended: "N"},
		},
	}
	ev := Evaluate(rep, now)
	var lucky, beast *AttackView
	for i := range ev.Vulnerabilities {
		switch ev.Vulnerabilities[i].Name {
		case "LUCKY13":
			lucky = &ev.Vulnerabilities[i]
		case "BEAST":
			beast = &ev.Vulnerabilities[i]
		}
	}
	if lucky == nil || lucky.Status != "exposed" || !strings.HasPrefix(lucky.Why, "Possible:") {
		t.Fatalf("LUCKY13: %+v", lucky)
	}
	if beast == nil || beast.Status != "not-exposed" || !strings.HasPrefix(beast.Why, "Needs TLS 1.0") || !strings.Contains(beast.Why, "not seen on this server") {
		t.Fatalf("BEAST: %+v", beast)
	}
	for _, s := range ev.Sections {
		if s.ID == SecVulnerabilities && s.Status == StatusGood {
			t.Errorf("an exposed attack under a good section: %+v", s)
		}
	}
}

// Every check the evaluation ran is listed, and the ones marked found are exactly the findings
// (PRD-006 REQ-EV-1): a report can show what passed as well as what failed.
func TestChecksListEveryRuleConsideredAndAgreeWithFindings(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	rep := &tlsprobe.Report{
		SchemaVersion: "tls-report/2",
		Target:        tlsprobe.Target{Host: "x.example", Port: 443},
		Protocols: []tlsprobe.ProtocolResult{
			{Version: "TLSv1.3", Supported: false, Evidence: "alert"},
			{Version: "TLSv1.2", Supported: true, Evidence: "server-hello"},
			{Version: "TLSv1.0", Supported: true, Evidence: "server-hello"},
		},
		Suites: []tlsprobe.SuiteResult{
			{Version: "TLSv1.2", Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Cipher: "AES", KeyBits: 128, Mode: "GCM", Kx: "ECDHE", Ephemeral: true, AEAD: true, IANARecommended: "Y"},
		},
	}
	ev := Evaluate(rep, now)
	found := map[string]bool{}
	for _, f := range ev.Findings {
		found[f.ID] = true
	}
	results := map[string]string{}
	for _, c := range ev.Checks {
		if c.Section == "" || c.Title == "" {
			t.Errorf("check without section or title: %+v", c)
		}
		if _, dup := results[c.ID]; dup {
			t.Errorf("check %s listed twice", c.ID)
		}
		results[c.ID] = c.Result
	}
	for id := range found {
		if results[id] != "found" {
			t.Errorf("finding %s has check result %q", id, results[id])
		}
	}
	notFound := 0
	for id, r := range results {
		if r == "found" && !found[id] {
			t.Errorf("check %s found without a finding", id)
		}
		if r == "not-found" {
			notFound++
		}
	}
	if len(ev.Checks) < 30 || notFound < 20 || results["PROTO.TLS10"] != "found" || results["CIPHER.RC4"] != "not-found" {
		t.Errorf("%d checks, %d not found; TLS10=%q RC4=%q", len(ev.Checks), notFound, results["PROTO.TLS10"], results["CIPHER.RC4"])
	}
}

// Every check that can pass says, in words, what it confirmed (no "X: not found").
func TestEveryCheckSaysWhatPassing(t *testing.T) {
	ids := map[string]bool{"PQC.HNDL-EXPOSED": true}
	for _, r := range allRules() {
		ids[r.id] = true
	}
	for _, r := range sshRules {
		ids[r.id] = true
	}
	for id := range ids {
		if PassText(id) == "" {
			t.Errorf("%s has no pass text", id)
		}
	}
	for id := range passText {
		if !ids[id] {
			t.Errorf("pass text for %s, which is no rule", id)
		}
	}
}
