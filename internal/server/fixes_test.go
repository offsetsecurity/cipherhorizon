package server_test

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

type fixJSON struct {
	ID         int64   `json:"id"`
	Title      string  `json:"title"`
	Group      string  `json:"group"`
	Result     string  `json:"result"`
	Detail     string  `json:"detail"`
	FixedAt    *string `json:"fixedAt"`
	CameBackAt *string `json:"cameBackAt"`
	HoldUntil  *string `json:"holdUntil"`
	NextScanAt *string `json:"nextScanAt"`
	Owner      string  `json:"owner"`
	Overdue    bool    `json:"overdue"`
	Ticket     string  `json:"ticket"`
	History    []struct{ Kind, By string }
	HowTo      string `json:"howTo"`
}

type fixesJSON struct {
	Progress struct{ Endpoints, Scanned, AtL3, BelowL3, WithWork, Undetermined int }
	CameBack, BeingFixed, OnHold, Fixed []fixJSON
	ToFix                               []struct {
		Key, Title string
		Subject    struct {
			Kind       string `json:"kind"`
			AssetID    int64  `json:"assetId"`
			FindingKey string `json:"findingKey"`
		}
	}
}

func fixes(t *testing.T, e *env) fixesJSON {
	t.Helper()
	var f fixesJSON
	if s := e.call("GET", "/api/v1/fixes", nil, &f); s != 200 {
		t.Fatalf("fixes: %d", s)
	}
	return f
}

// REQ-FIX-1..5: a problem is assigned once; after that only scans change its state. An unchanged
// endpoint reads not fixed, a changed one is fixed with the date, and a change undone comes back.
// Nobody presses anything to verify.
func TestAFixIsDecidedByScansAlone(t *testing.T) {
	e := newEnv(t)
	srv := tls12Server(t)
	a := e.addAsset(srv.Addr)
	e.scanAndWait(a.ID)

	if before := fixes(t, e); len(before.ToFix) == 0 || len(before.BeingFixed) != 0 {
		t.Fatalf("before assigning, the scan's problems are in To fix next and nothing is being fixed: %+v", before)
	}

	assign := map[string]any{"subject": map[string]any{"kind": "finding", "assetId": a.ID, "findingKey": "PROTO.NO-TLS13"},
		"owner": "web team", "due": "2001-01-01", "ticket": "https://tracker.example/CHG-7"}
	if s := e.call("POST", "/api/v1/fixes", map[string]any{"subject": assign["subject"], "ticket": "javascript:alert(1)"}, nil); s != 400 {
		t.Fatalf("a ticket that is not a web link: %d", s)
	}
	var made struct {
		Fix       fixJSON
		Scheduled []string
	}
	if s := e.call("POST", "/api/v1/fixes", assign, &made); s != 201 {
		t.Fatalf("assign: %d", s)
	}
	if made.Fix.Group != "being-fixed" || made.Fix.Result != "not-checked" || !strings.Contains(made.Fix.Title, "on "+a.Name) ||
		len(made.Scheduled) != 1 || made.Fix.Ticket != "https://tracker.example/CHG-7" {
		t.Fatalf("assigned: %+v", made)
	}
	if s := e.call("POST", "/api/v1/fixes", assign, nil); s != 409 {
		t.Fatalf("assigning the same problem twice: %d", s)
	}
	var asset struct {
		Interval int `json:"intervalSeconds"`
	}
	e.call("GET", "/api/v1/assets/"+itoa(a.ID), nil, &asset)
	if asset.Interval != 86400 {
		t.Fatalf("an assigned endpoint with no schedule is scanned daily: %d", asset.Interval)
	}
	id := made.Fix.ID

	// Scanned, unchanged: not fixed, overdue, and still not in To fix next.
	e.scanAndWait(a.ID)
	f := fixes(t, e)
	if len(f.BeingFixed) != 1 || f.BeingFixed[0].Result != "not-fixed" || !f.BeingFixed[0].Overdue || len(f.Fixed) != 0 {
		t.Fatalf("after a scan of the unchanged endpoint: %+v", f)
	}
	for _, s := range f.ToFix {
		if s.Subject.FindingKey == "PROTO.NO-TLS13" {
			t.Fatalf("an assigned problem is still suggested: %+v", s)
		}
	}

	// Really changed: the next scan moves it to fixed, with nobody pressing anything.
	srv = restartWith(t, srv, testserver.Config{MinVersion: tls.VersionTLS12})
	e.scanAndWait(a.ID)
	f = fixes(t, e)
	if len(f.Fixed) != 1 || f.Fixed[0].FixedAt == nil || len(f.BeingFixed) != 0 || f.Fixed[0].Overdue {
		t.Fatalf("after the real change: %+v", f)
	}

	// Undone: the next scan brings it back, and the monitor reports it.
	restartWith(t, srv, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	e.scanAndWait(a.ID)
	f = fixes(t, e)
	if len(f.CameBack) != 1 || f.CameBack[0].CameBackAt == nil || !strings.Contains(f.CameBack[0].Detail, "PROTO.NO-TLS13") || len(f.Fixed) != 0 {
		t.Fatalf("after the change was undone: %+v", f)
	}
	if ev := hasKind(events(t, e), "work.regressed"); ev == nil || ev.Severity != "critical" || ev.Link != "#/fixes/"+itoa(id) {
		t.Fatalf("the monitor reports what came back: %+v", ev)
	}

	// One fix's page: how to fix it, and what happened, in order.
	var d fixJSON
	if s := e.call("GET", "/api/v1/fixes/"+itoa(id), nil, &d); s != 200 || d.HowTo == "" {
		t.Fatalf("detail: %d %+v", s, d)
	}
	var kinds []string
	for i := len(d.History) - 1; i >= 0; i-- {
		kinds = append(kinds, d.History[i].Kind+"/"+d.History[i].By)
	}
	if got, want := strings.Join(kinds, " "), "assigned/local fixed/scanner came-back/scanner"; got != want {
		t.Fatalf("history %q, want %q", got, want)
	}

	// On hold until a date, then it resumes by itself.
	soon := time.Now().AddDate(0, 1, 0).UTC().Format(time.DateOnly)
	if s, b := move(t, e, "", id, map[string]any{"transition": "hold", "note": "change freeze", "until": soon}); s != 200 {
		t.Fatalf("hold: %d %s", s, b)
	}
	if f = fixes(t, e); len(f.OnHold) != 1 || f.OnHold[0].HoldUntil == nil || len(f.CameBack) != 0 {
		t.Fatalf("on hold: %+v", f)
	}
}

// REQ-FIX-6: the progress line counts endpoints out of those scanned, and what is being fixed.
func TestFixesProgressCountsOutOfScannedEndpoints(t *testing.T) {
	e := newEnv(t)
	classical := e.addAsset(classicalServer(t).Addr)
	hybrid := e.addAsset(hybridServer(t).Addr)
	e.addAsset(deadPort(t))
	e.scanAndWait(classical.ID)
	e.scanAndWait(hybrid.ID)
	if s := e.call("POST", "/api/v1/fixes", map[string]any{"subject": map[string]any{"kind": "readiness", "assetId": hybrid.ID}}, nil); s != 400 {
		t.Fatalf("a fix for something already done: %d", s)
	}
	if s := e.call("POST", "/api/v1/fixes", map[string]any{"subject": map[string]any{"kind": "readiness", "assetId": classical.ID}, "owner": "platform"}, nil); s != 201 {
		t.Fatalf("assign: %d", s)
	}
	p := fixes(t, e).Progress
	if p.Endpoints != 3 || p.Scanned != 2 || p.AtL3 != 1 || p.BelowL3 != 1 || p.WithWork != 1 {
		t.Fatalf("progress: %+v", p)
	}
}

// REQ-REN-1..3: Renewals lists served certificates by date; an assigned renewal is done when a scan
// sees a newer certificate; a change nobody was assigned is listed until someone says it was expected.
func TestRenewals(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	oldCert, oldFP := selfSignedFrom(t, now.Add(-80*24*time.Hour), now.Add(5*24*time.Hour))
	newCert, _ := selfSignedFrom(t, now.Add(-10*time.Minute), now.Add(90*24*time.Hour))
	other, _ := selfSignedFrom(t, now.Add(-5*time.Minute), now.Add(60*24*time.Hour))
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{oldCert}})
	a := e.addAsset(srv.Addr)
	e.scanAndWait(a.ID)

	type renewals struct {
		Certificates []struct {
			Fingerprint, Name string
			DaysLeft          int
			Endpoints         int
			Fix               *fixJSON
		}
		Unplanned []struct {
			AssetID int64 `json:"assetId"`
			ToScan  int64 `json:"toScan"`
		}
	}
	var r renewals
	if s := e.call("GET", "/api/v1/renewals", nil, &r); s != 200 || len(r.Certificates) != 1 || r.Certificates[0].Fingerprint != oldFP ||
		r.Certificates[0].Name != "pay.test" || r.Certificates[0].DaysLeft > 5 || r.Certificates[0].Fix != nil {
		t.Fatalf("renewals: %d %+v", s, r)
	}
	if s := e.call("POST", "/api/v1/fixes", map[string]any{"subject": map[string]any{"kind": "certificate", "certificate": oldFP}, "owner": "PKI team"}, nil); s != 201 {
		t.Fatalf("assign the renewal: %d", s)
	}
	r = renewals{}
	e.call("GET", "/api/v1/renewals", nil, &r)
	if r.Certificates[0].Fix == nil || r.Certificates[0].Fix.Owner != "PKI team" || !strings.Contains(r.Certificates[0].Fix.Title, "pay.test") {
		t.Fatalf("an assigned renewal shows who has it: %+v", r.Certificates[0])
	}

	srv = restartWith(t, srv, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{newCert}})
	e.scanAndWait(a.ID)
	if f := fixes(t, e); len(f.Fixed) != 1 {
		t.Fatalf("the renewal is done once a scan sees the newer certificate: %+v", f)
	}
	r = renewals{}
	e.call("GET", "/api/v1/renewals", nil, &r)
	if len(r.Unplanned) != 0 {
		t.Fatalf("an assigned renewal is not an unplanned change: %+v", r.Unplanned)
	}

	// Someone swaps the certificate again with nobody assigned.
	restartWith(t, srv, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{other}})
	e.scanAndWait(a.ID)
	r = renewals{}
	e.call("GET", "/api/v1/renewals", nil, &r)
	if len(r.Unplanned) != 1 || r.Unplanned[0].AssetID != a.ID {
		t.Fatalf("a change nobody was assigned: %+v", r.Unplanned)
	}
	if s := e.call("POST", "/api/v1/renewals/expected", map[string]any{"assetId": a.ID, "toScan": r.Unplanned[0].ToScan}, nil); s != 204 {
		t.Fatalf("expected: %d", s)
	}
	r = renewals{}
	e.call("GET", "/api/v1/renewals", nil, &r)
	if len(r.Unplanned) != 0 {
		t.Fatalf("still listed after it was marked as expected: %+v", r.Unplanned)
	}
}
