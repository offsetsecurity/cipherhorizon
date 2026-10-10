package server_test

import (
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// PRD-007 REQ-SX-3: an endpoint keeps its STARTTLS choice, a scan uses it, the report says so,
// and the HTTP check is skipped for a service that is not HTTP.
func TestEndpointKeepsItsSTARTTLS(t *testing.T) {
	e := newEnv(t)
	smtp := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, StartTLS: "smtp",
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}})

	type view struct {
		ID           int64  `json:"id"`
		Port         int    `json:"port"`
		StartTLS     string `json:"starttls"`
		StartTLSUsed string `json:"starttlsUsed"`
	}
	var byScheme, byField, plain view
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "smtp://" + smtp.Addr}, &byScheme); s != 201 ||
		byScheme.StartTLS != "smtp" || byScheme.StartTLSUsed != "smtp" {
		t.Fatalf("by scheme: %d %+v", s, byScheme)
	}
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "mail.example.com:2525", "starttls": "SMTP"}, &byField); s != 201 ||
		byField.StartTLS != "smtp" || byField.StartTLSUsed != "smtp" {
		t.Fatalf("by field: %d %+v", s, byField)
	}
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "mail.example.com:587"}, &plain); s != 201 ||
		plain.StartTLS != "auto" || plain.StartTLSUsed != "smtp" {
		t.Fatalf("auto by port: %d %+v", s, plain)
	}
	var sub view
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "submission://mail2.example.com"}, &sub); s != 201 || sub.Port != 587 || sub.StartTLSUsed != "smtp" {
		t.Fatalf("submission:// = %d %+v", s, sub)
	}
	if s, body := e.do("POST", "/api/v1/assets", map[string]any{"target": "x.example.com:25", "starttls": "telnet"}); s != 400 || !strings.Contains(string(body), "starttls") {
		t.Fatalf("an unknown protocol: %d %s", s, body)
	}
	// The choice can be changed, and is validated.
	var patched view
	if s := e.call("PATCH", "/api/v1/assets/"+itoa(plain.ID), map[string]any{"starttls": "none"}, &patched); s != 200 || patched.StartTLS != "none" || patched.StartTLSUsed != "" {
		t.Fatalf("patch to none: %d %+v", s, patched)
	}
	if s, _ := e.do("PATCH", "/api/v1/assets/"+itoa(plain.ID), map[string]any{"starttls": "gopher"}); s != 400 {
		t.Fatalf("patch to an unknown protocol: %d", s)
	}

	// A scan goes through STARTTLS and its report says so; the HTTP check does not apply.
	sc := e.scanAndWait(byScheme.ID)
	if sc.Status != "done" {
		t.Fatalf("scan: %s %s", sc.Status, sc.Error)
	}
	_, raw, _ := e.req("GET", "/api/v1/scans/"+itoa(sc.ID)+"/report", nil, nil)
	var rep struct {
		Target struct {
			StartTLS string `json:"starttls"`
		} `json:"target"`
		Stages []struct{ Name, Outcome, ReasonCode string }
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Target.StartTLS != "smtp" {
		t.Errorf("report target STARTTLS = %q", rep.Target.StartTLS)
	}
	for _, st := range rep.Stages {
		if st.Name == "http" && (st.Outcome != "skipped" || st.ReasonCode != "not-applicable") {
			t.Errorf("http stage: %+v", st)
		}
	}
	_, raw, _ = e.req("GET", "/api/v1/scans/"+itoa(sc.ID)+"/evaluation", nil, nil)
	var ev struct {
		Findings []struct{ ID string }                  `json:"findings"`
		Sections []struct{ ID, Status string }          `json:"sections"`
		Checks   []struct{ ID, Section, Result string } `json:"checks"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	for _, f := range ev.Findings {
		if strings.HasPrefix(f.ID, "HTTP.") {
			t.Errorf("an SMTP service got an HTTP finding: %s", f.ID)
		}
	}
	// The HTTP area does not exist for SMTP: not applicable, which is not a gap in the scan.
	for _, sec := range ev.Sections {
		if sec.ID == "http" && sec.Status != "not-applicable" {
			t.Errorf("http section status %q, want not-applicable", sec.Status)
		}
	}
	for _, c := range ev.Checks {
		if c.Section == "http" && c.Result != "not-applicable" {
			t.Errorf("check %s: %q, want not-applicable", c.ID, c.Result)
		}
		if c.Result == "not-checked" {
			t.Errorf("check %s was not checked over STARTTLS", c.ID)
		}
	}
	if sc.Level == nil || *sc.Level != 3 {
		t.Errorf("readiness through STARTTLS = %v, want L3", sc.Level)
	}
}
