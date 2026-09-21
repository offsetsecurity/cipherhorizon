package server_test

import (
	"crypto/tls"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/cbom-scan/internal/eval"
	"github.com/example/cbom-scan/internal/store"
	"github.com/example/cbom-scan/internal/tlsprobe"
	"github.com/example/cbom-scan/internal/tlsprobe/testserver"
)

// ---- US-01: add assets -------------------------------------------------------------------------

func TestAC01_AddAssets(t *testing.T) {
	e := newEnv(t)

	// AC-01.1: appears at once, default port 443, name defaults to the address.
	var a assetJSON
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "Example.COM", "tags": []string{" prod ", "web", "PROD"}}, &a); s != 201 {
		t.Fatalf("status %d", s)
	}
	if a.Host != "example.com" || a.Port != 443 || a.Address != "example.com:443" || a.Name != "example.com:443" ||
		len(a.Tags) != 2 || a.Tags[0] != "prod" {
		t.Errorf("asset = %+v", a)
	}
	var list []assetJSON
	e.call("GET", "/api/v1/assets", nil, &list)
	if len(list) != 1 || list[0].ID != a.ID {
		t.Errorf("list = %+v", list)
	}

	// AC-01.3: duplicate.
	var dup map[string]string
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "example.com:443"}, &dup); s != 409 || !strings.Contains(dup["error"], "already added") {
		t.Errorf("duplicate: %d %v", s, dup)
	}
}

// AC-01.4
func TestAC01_TargetsAreNormalisedAndValidated(t *testing.T) {
	e := newEnv(t, noLoopback())
	for in, want := range map[string]string{
		"https://Example.com:8443/path?x=1#frag": "example.com:8443",
		"http://example.org/":                    "example.org:443",
		"tls://svc.internal:993":                 "svc.internal:993",
		"  example.net  ":                        "example.net:443",
		"example.com.":                           "example.com:443",
		"10.0.0.5:8443":                          "10.0.0.5:8443",
		"[2001:db8::1]:443":                      "2001:db8::1:443",
		"under_score.example":                    "under_score.example:443",
	} {
		var a assetJSON
		if s := e.call("POST", "/api/v1/assets", map[string]any{"target": in}, &a); s != 201 {
			t.Errorf("%q rejected (status %d)", in, s)
			continue
		}
		if a.Port == 0 || (a.Address != want && !strings.Contains(want, "2001:db8")) {
			t.Errorf("%q -> %q, want %q", in, a.Address, want)
		}
	}
	for in, why := range map[string]string{
		"":                     "empty",
		"a b.example":          "whitespace",
		"host:0":               "port",
		"host:70000":           "port",
		"host:abc":             "port",
		"user:pw@host.example": "credentials",
		"ftp://host.example":   "scheme",
		"-bad.example":         "invalid host name",
		"bad-.example":         "invalid host name",
		"exa mple.com":         "whitespace",
		"a..b.example":         "invalid host name",
		"127.0.0.1":            "loopback",
		"169.254.169.254":      "link-local",
		"0.0.0.0":              "unspecified",
		"224.0.0.1":            "multicast",
		"fd00:ec2::254":        "metadata",
		"100.100.100.200":      "metadata",
	} {
		var out map[string]string
		if s := e.call("POST", "/api/v1/assets", map[string]any{"target": in}, &out); s != 400 || out["error"] == "" {
			t.Errorf("%q (%s): status %d %v, want a 400 with a reason", in, why, s, out)
		}
	}
}

// AC-01.2
func TestAC01_BulkAddReportsEveryLine(t *testing.T) {
	e := newEnv(t)
	e.addAsset("existing.example")
	text := "# my endpoints\r\nnew-1.example\n\nexisting.example:443\nnot a host\nhttps://new-2.example:8443/x\nhost:0\n"
	var out struct {
		Results []struct {
			Line   int    `json:"line"`
			Input  string `json:"input"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"results"`
		Added, Duplicate, Invalid int
	}
	if s := e.call("POST", "/api/v1/assets/bulk", map[string]any{"text": text, "tags": []string{"batch"}}, &out); s != 200 {
		t.Fatalf("status %d", s)
	}
	got := map[string]string{}
	for _, r := range out.Results {
		got[r.Input] = r.Status
		if r.Status != "added" && r.Reason == "" {
			t.Errorf("line %d (%s) has no reason", r.Line, r.Input)
		}
	}
	want := map[string]string{"new-1.example": "added", "existing.example:443": "duplicate", "not a host": "invalid",
		"https://new-2.example:8443/x": "added", "host:0": "invalid"}
	for in, st := range want {
		if got[in] != st {
			t.Errorf("%q = %q, want %q", in, got[in], st)
		}
	}
	if out.Added != 2 || out.Duplicate != 1 || out.Invalid != 2 || len(out.Results) != 5 {
		t.Errorf("counts added=%d dup=%d invalid=%d results=%d (comments and blanks are skipped)", out.Added, out.Duplicate, out.Invalid, len(out.Results))
	}
	var list []assetJSON
	e.call("GET", "/api/v1/assets", nil, &list)
	if len(list) != 3 { // one bad line never blocked the rest
		t.Errorf("assets = %d, want 3", len(list))
	}
	for _, a := range list {
		if a.Host == "new-1.example" && (len(a.Tags) != 1 || a.Tags[0] != "batch") {
			t.Errorf("bulk tags = %v", a.Tags)
		}
	}
}

// AC-01.5
func TestAC01_EditAndDeleteAsset(t *testing.T) {
	e := newEnv(t)
	srv := classicalServer(t)
	a := e.addAsset(srv.Addr)
	sc := e.scanAndWait(a.ID)

	var up assetJSON
	body := map[string]any{"name": "Payments API", "tags": []string{"prod", "pci"}, "notes": "owner: team-x"}
	if s := e.call("PATCH", "/api/v1/assets/"+itoa(a.ID), body, &up); s != 200 || up.Name != "Payments API" || len(up.Tags) != 2 || up.Notes != "owner: team-x" {
		t.Fatalf("patch: %d %+v", s, up)
	}
	for name, bad := range map[string]map[string]any{
		"empty name":   {"name": "  "},
		"long name":    {"name": strings.Repeat("x", 101)},
		"too many tag": {"tags": []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}},
		"bad interval": {"intervalSeconds": 5},
		"unknown key":  {"nope": 1},
	} {
		if s, _ := e.do("PATCH", "/api/v1/assets/"+itoa(a.ID), bad); s != 400 {
			t.Errorf("%s: status %d, want 400", name, s)
		}
	}

	if s, _ := e.do("DELETE", "/api/v1/assets/"+itoa(a.ID), nil); s != 204 {
		t.Fatalf("delete: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/assets/"+itoa(a.ID), nil); s != 404 {
		t.Errorf("deleted asset: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/scans/"+itoa(sc.ID)+"/report", nil); s != 404 {
		t.Errorf("history survived deletion: %d", s)
	}
	if s, _ := e.do("DELETE", "/api/v1/assets/"+itoa(a.ID), nil); s != 404 {
		t.Errorf("second delete: %d", s)
	}
}

// ---- US-02 / US-03: scanning and progress ------------------------------------------------------

func TestAC02_ScanCompletesWithResults(t *testing.T) {
	e := newEnv(t)
	srv := hybridServer(t)
	a := e.addAsset(srv.Addr)

	start := time.Now()
	queued := e.startScan(a.ID)
	if queued.Status != "queued" && queued.Status != "running" {
		t.Errorf("AC-02.1: status right after clicking Scan = %q", queued.Status)
	}
	if time.Since(start) > time.Second {
		t.Error("AC-02.1: the scan was not visible within 1 s")
	}

	done := e.wait(queued.ID)
	if done.Status != "done" || done.Level == nil || *done.Level != eval.LevelHybridNeg || done.Band == "" || done.ProgressPct != 100 || done.Connections < 10 {
		t.Fatalf("done = %+v", done)
	}

	// AC-02.3: the asset shows the result without any further action.
	var got assetJSON
	e.call("GET", "/api/v1/assets/"+itoa(a.ID), nil, &got)
	if got.LastDone == nil || got.LastDone.ID != done.ID || got.Latest.Status != "done" {
		t.Errorf("asset = %+v", got)
	}

	// The event log narrates the stages.
	var detail struct {
		Events []struct{ Message string } `json:"events"`
	}
	e.call("GET", "/api/v1/scans/"+itoa(done.ID), nil, &detail)
	var log []string
	for _, ev := range detail.Events {
		log = append(log, ev.Message)
	}
	joined := strings.Join(log, " | ")
	for _, want := range []string{"scan started", "testing protocol versions", "enumerating cipher suites", "fetching certificates", "evaluating results", "done: TLS hygiene"} {
		if !strings.Contains(joined, want) {
			t.Errorf("event log lacks %q:\n%s", want, joined)
		}
	}
}

// AC-02.2 and AC-02.5: a slow endpoint lets us watch a scan run, then cancel it.
func TestAC02_ProgressIsLiveAndScanCanBeCancelled(t *testing.T) {
	e := newEnv(t)
	real := hybridServer(t)
	slow := slowProxy(t, real.Addr, 250*time.Millisecond) // a scan of this endpoint runs for several seconds
	a := e.addAsset(slow)
	sc := e.startScan(a.ID)

	var seen []scanJSON
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		cur := e.getScan(sc.ID)
		if cur.Status == "running" && cur.Connections > 0 {
			seen = append(seen, cur)
			// Progress is written at most every 250 ms, so wait until it has visibly moved.
			if len(seen) >= 3 && cur.Connections > seen[0].Connections {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(seen) < 3 {
		t.Fatalf("saw only %d running observations", len(seen))
	}
	last := seen[len(seen)-1]
	if last.Stage == "" || last.ProgressPct <= 0 || last.ProgressPct >= 100 {
		t.Errorf("running scan = %+v (want a stage and 0 < pct < 100)", last)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i].Connections < seen[i-1].Connections || seen[i].ProgressPct < seen[i-1].ProgressPct {
			t.Errorf("progress went backwards: %+v then %+v", seen[i-1], seen[i])
		}
	}
	if seen[len(seen)-1].Connections == seen[0].Connections {
		t.Error("the connection counter never moved")
	}

	// AC-02.6 while it is running.
	if again := e.startScan(a.ID); again.ID != sc.ID {
		t.Errorf("a second scan request created scan %d instead of returning %d", again.ID, sc.ID)
	}

	// AC-02.5: cancel a running scan.
	var cancelled scanJSON
	if s := e.call("POST", "/api/v1/scans/"+itoa(sc.ID)+"/cancel", nil, &cancelled); s != 200 || cancelled.Status != "canceled" {
		t.Fatalf("cancel: %d %+v", s, cancelled)
	}
	time.Sleep(300 * time.Millisecond)
	if final := e.getScan(sc.ID); final.Status != "canceled" {
		t.Errorf("a canceled scan ended as %q", final.Status)
	}
	// The log must end at the cancellation, not go on announcing stages of a scan
	// that is no longer being run.
	time.Sleep(500 * time.Millisecond)
	var detail struct {
		Events []struct {
			Message string `json:"message"`
		} `json:"events"`
	}
	if s := e.call("GET", "/api/v1/scans/"+itoa(sc.ID), nil, &detail); s != 200 || len(detail.Events) == 0 {
		t.Fatalf("events: %d %+v", s, detail)
	}
	if last := detail.Events[len(detail.Events)-1].Message; last != "canceled by user" {
		t.Errorf("last event of a canceled scan = %q, want %q", last, "canceled by user")
	}
	// It freed the asset: a new scan can start.
	if next := e.startScan(a.ID); next.ID == sc.ID {
		t.Error("the slot was not freed by cancellation")
	}
	if s, _ := e.do("POST", "/api/v1/scans/"+itoa(sc.ID)+"/cancel", nil); s != 409 {
		t.Errorf("canceling a finished scan: %d, want 409", s)
	}
	if s, _ := e.do("POST", "/api/v1/scans/999/cancel", nil); s != 404 {
		t.Errorf("canceling a missing scan: %d", s)
	}
}

// AC-02.4
func TestAC02_UnreachableAndNonTLSEndpointsFailClearly(t *testing.T) {
	e := newEnv(t)

	dead := e.addAsset(deadPort(t))
	sc := e.scanAndWait(dead.ID)
	if sc.Status != "failed" || !strings.Contains(sc.Error, "no response") {
		t.Errorf("dead port: %+v", sc)
	}

	http1 := testserver.StartScript(t, func([]byte) []byte { return []byte("HTTP/1.1 400 Bad Request\r\n\r\n") })
	plain := e.addAsset(http1.Addr)
	sc2 := e.scanAndWait(plain.ID)
	if sc2.Status != "failed" || !strings.Contains(sc2.Error, "not with TLS") {
		t.Errorf("plain-text port: %+v", sc2)
	}

	// The failures did not block a healthy scan, and remain in history.
	good := e.addAsset(classicalServer(t).Addr)
	if ok := e.scanAndWait(good.ID); ok.Status != "done" {
		t.Errorf("healthy scan after failures: %+v", ok)
	}
	var h []struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	e.call("GET", "/api/v1/assets/"+itoa(dead.ID)+"/history", nil, &h)
	if len(h) != 1 || h[0].Status != "failed" || h[0].Error == "" {
		t.Errorf("history of a failed asset = %+v", h)
	}
}

// AC-03.1
func TestAC03_BulkScanRespectsConcurrencyAndQueue(t *testing.T) {
	e := newEnv(t, withWorkers(2))
	real := classicalServer(t)
	var ids []int64
	for i := 0; i < 5; i++ {
		// each proxy is a distinct address, so five distinct assets
		ids = append(ids, e.addAsset(slowProxy(t, real.Addr, 20*time.Millisecond)).ID)
	}
	var out struct {
		Queued        int        `json:"queued"`
		AlreadyActive int        `json:"alreadyActive"`
		Scans         []scanJSON `json:"scans"`
	}
	if s := e.call("POST", "/api/v1/scans", map[string]any{"all": true}, &out); s != 202 || out.Queued != 5 || len(out.Scans) != 5 {
		t.Fatalf("scan all: %d %+v", s, out)
	}
	// A second request is idempotent: nothing new is queued while these are active.
	var again struct{ Queued, AlreadyActive int }
	e.call("POST", "/api/v1/scans", map[string]any{"assetIds": ids}, &again)
	if again.Queued != 0 || again.AlreadyActive != 5 {
		t.Errorf("repeat request = %+v", again)
	}

	maxRunning := 0
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		var running []scanJSON
		e.call("GET", "/api/v1/scans?status=running", nil, &running)
		if len(running) > maxRunning {
			maxRunning = len(running)
		}
		var active int
		for _, id := range out.Scans {
			if s := e.getScan(id.ID).Status; s == "queued" || s == "running" {
				active++
			}
		}
		if active == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if maxRunning > 2 {
		t.Errorf("%d scans ran at once with 2 workers", maxRunning)
	}
	if maxRunning == 0 {
		t.Error("never observed a running scan")
	}
	for _, sc := range out.Scans {
		if got := e.getScan(sc.ID); got.Status != "done" {
			t.Errorf("scan %d = %+v", sc.ID, got)
		}
	}

	// Selecting by tag, and rejecting an empty selection.
	if s, _ := e.do("POST", "/api/v1/scans", map[string]any{"assetIds": []int64{}}); s != 400 {
		t.Errorf("empty selection: %d", s)
	}
	if s, _ := e.do("POST", "/api/v1/scans", map[string]any{"tag": "nonexistent"}); s != 400 {
		t.Errorf("tag with no assets: %d", s)
	}
}

// ---- US-04 / US-05 / US-06: readiness, detail, dashboard -----------------------------------

type evalJSON = eval.Evaluation

func (e *env) evaluation(scanID int64) evalJSON {
	e.t.Helper()
	var ev evalJSON
	if s := e.call("GET", "/api/v1/scans/"+itoa(scanID)+"/evaluation", nil, &ev); s != 200 {
		e.t.Fatalf("evaluation %d: status %d", scanID, s)
	}
	return ev
}

// AC-04.4 through the whole product: real servers, real scans, real API.
func TestAC04_ReadinessOfRealEndpoints(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name    string
		addr    string
		level   int
		exposed bool
	}{
		{"hybrid", hybridServer(t).Addr, eval.LevelHybridNeg, false},
		{"classical TLS 1.3", classicalServer(t).Addr, eval.LevelExposed, true},
		{"TLS 1.2 only", tls12Server(t).Addr, eval.LevelNotReady, true},
	}
	scans := map[string]int64{}
	for _, c := range cases {
		a := e.addAsset(c.addr)
		sc := e.scanAndWait(a.ID)
		if sc.Status != "done" || sc.Level == nil || *sc.Level != c.level || sc.HNDL != c.exposed {
			t.Errorf("%s: scan = %+v, want level %d exposed=%v", c.name, sc, c.level, c.exposed)
		}
		scans[c.name] = sc.ID

		// AC-04.1 / AC-05.2: everything is cited, and states its evidence.
		ev := e.evaluation(sc.ID)
		r := ev.Readiness
		if r.Level != c.level || r.Label == "" || r.Summary == "" || len(r.NextSteps) == 0 || len(r.Citations) == 0 {
			t.Errorf("%s: readiness = %+v", c.name, r)
		}
		for name, d := range map[string]eval.Dimension{"key": r.KeyEstablishment, "auth": r.Authentication, "symmetric": r.Symmetric} {
			if len(d.Citations) == 0 || d.Evidence == "" || d.Detail == "" {
				t.Errorf("%s: dimension %s lacks citation/evidence/detail: %+v", c.name, name, d)
			}
		}
		if len(ev.Findings) == 0 {
			t.Errorf("%s: no findings at all (the test certificate alone must be reported)", c.name)
		}
		for _, f := range ev.Findings {
			if len(f.Citations) == 0 || f.Detail == "" || f.Remediation == "" || f.Evidence == "" {
				t.Errorf("%s: finding %s is not fully sourced: %+v", c.name, f.ID, f)
			}
		}
		if ev.Hygiene.Band == "" || ev.Hygiene.Score < 0 || len(ev.Hygiene.NotMeasured) == 0 || ev.Hygiene.Methodology == "" ||
			(ev.Hygiene.Score < 100 && len(ev.Hygiene.Deductions) == 0) {
			t.Errorf("%s: hygiene = %+v", c.name, ev.Hygiene)
		}
	}

	// AC-05.1: the raw report is complete enough to render the detail page.
	var rep tlsprobe.Report
	e.call("GET", "/api/v1/scans/"+itoa(scans["hybrid"])+"/report", nil, &rep)
	if len(rep.Protocols) != 6 || len(rep.Suites) == 0 || len(rep.Groups) == 0 || len(rep.Certificates) == 0 || rep.Negotiated == nil {
		t.Errorf("report = protocols %d suites %d groups %d certs %d negotiated %v",
			len(rep.Protocols), len(rep.Suites), len(rep.Groups), len(rep.Certificates), rep.Negotiated)
	}
	if s, b, h := e.req("GET", "/api/v1/scans/"+itoa(scans["hybrid"])+"/report?download=1", nil, nil); s != 200 ||
		!strings.Contains(h.Get("Content-Disposition"), "attachment") || !json.Valid(b) {
		t.Errorf("download: %d %q", s, h.Get("Content-Disposition"))
	}

	// AC-04.2 / AC-06.x: the fleet view.
	var f store.Fleet
	e.call("GET", "/api/v1/summary", nil, &f)
	if f.Assets != 3 || f.Scanned != 3 || f.HNDLExposed != 2 {
		t.Errorf("fleet = assets %d scanned %d exposed %d", f.Assets, f.Scanned, f.HNDLExposed)
	}
	if f.Readiness[eval.LevelHybridNeg] != 1 || f.Readiness[eval.LevelExposed] != 1 || f.Readiness[eval.LevelNotReady] != 1 {
		t.Errorf("readiness distribution = %v", f.Readiness)
	}
	if len(f.Bands) == 0 || len(f.NeedsAttention) == 0 || len(f.Recent) != 3 || len(f.Trend) != 14 {
		t.Errorf("fleet = bands %v attention %d recent %d trend %d", f.Bands, len(f.NeedsAttention), len(f.Recent), len(f.Trend))
	}
	if f.HNDLExposed > 0 && len(f.NeedsAttention) == 0 {
		t.Error("exposed assets must appear under needs-attention")
	}
}

// ---- US-07: history and comparison --------------------------------------------------------------

// AC-07.1 to AC-07.4: an endpoint is changed between two scans, and the product says so.
func TestAC07_HistoryTrendAndDiff(t *testing.T) {
	e := newEnv(t)
	first := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13, Curves: []tls.CurveID{tls.X25519, tls.CurveP256}})
	a := e.addAsset(first.Addr)

	// Not enough history yet.
	if s, _ := e.do("GET", "/api/v1/assets/"+itoa(a.ID)+"/diff", nil); s != 409 {
		t.Errorf("diff with no scans: %d, want 409", s)
	}
	s1 := e.scanAndWait(a.ID)
	if s, _ := e.do("GET", "/api/v1/assets/"+itoa(a.ID)+"/diff", nil); s != 409 {
		t.Errorf("diff with one scan: %d, want 409", s)
	}

	// Someone enables the post-quantum hybrid on the same address.
	first.Close()
	time.Sleep(100 * time.Millisecond)
	testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Addr: first.Addr,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}})
	s2 := e.scanAndWait(a.ID)
	if s1.Level == nil || s2.Level == nil || *s1.Level != eval.LevelExposed || *s2.Level != eval.LevelHybridNeg {
		t.Fatalf("scan levels = %v then %v", s1.Level, s2.Level)
	}

	// AC-07.1 and 07.2
	var h []struct {
		ScanID int64  `json:"scanId"`
		Status string `json:"status"`
		Band   string `json:"band"`
		Level  *int   `json:"readinessLevel"`
		HNDL   bool   `json:"hndlExposed"`
	}
	e.call("GET", "/api/v1/assets/"+itoa(a.ID)+"/history", nil, &h)
	if len(h) != 2 || h[0].ScanID != s1.ID || h[1].ScanID != s2.ID || *h[0].Level != 1 || *h[1].Level != 3 || !h[0].HNDL || h[1].HNDL {
		t.Errorf("history (oldest first) = %+v", h)
	}

	// AC-07.3: default comparison is latest vs previous.
	var d struct {
		From scanJSON  `json:"from"`
		To   scanJSON  `json:"to"`
		Diff eval.Diff `json:"diff"`
	}
	if s := e.call("GET", "/api/v1/assets/"+itoa(a.ID)+"/diff", nil, &d); s != 200 {
		t.Fatalf("diff: %d", s)
	}
	if d.From.ID != s1.ID || d.To.ID != s2.ID || d.Diff.Better == 0 {
		t.Errorf("diff = from %d to %d %+v", d.From.ID, d.To.ID, d.Diff)
	}
	var sawReadiness, sawGroup, sawTLS12 bool
	for _, c := range d.Diff.Changes {
		switch {
		case c.Area == "readiness" && c.Impact == eval.Better && strings.Contains(c.Before, "L1") && strings.Contains(c.After, "L3"):
			sawReadiness = true
		case c.Area == "group" && c.Kind == "added" && strings.Contains(c.Subject, "X25519MLKEM768") && c.Impact == eval.Better:
			sawGroup = true
		case c.Area == "protocol" && c.Kind == "added" && c.Subject == "TLSv1.2":
			sawTLS12 = true
		}
	}
	if !sawReadiness || !sawGroup || !sawTLS12 {
		t.Errorf("diff missed the change: readiness=%v group=%v tls12=%v\n%+v", sawReadiness, sawGroup, sawTLS12, d.Diff.Changes)
	}
	// Explicit from/to, and reversed (the regression).
	var rev struct{ Diff eval.Diff }
	e.call("GET", "/api/v1/assets/"+itoa(a.ID)+"/diff?from="+itoa(s2.ID)+"&to="+itoa(s1.ID), nil, &rev)
	if rev.Diff.Worse == 0 {
		t.Errorf("the reverse comparison must be worse: %+v", rev.Diff)
	}
	if s, _ := e.do("GET", "/api/v1/assets/"+itoa(a.ID)+"/diff?from=1&to=999", nil); s != 404 {
		t.Errorf("diff with a missing scan: %d", s)
	}

	// AC-07.4: any past scan opens in full.
	oldEv := e.evaluation(s1.ID)
	if oldEv.Readiness.Level != eval.LevelExposed || oldEv.Version == "" {
		t.Errorf("stored old evaluation = %+v", oldEv.Readiness)
	}

	// The fleet trend reflects the change today.
	var f store.Fleet
	e.call("GET", "/api/v1/summary?days=3", nil, &f)
	if len(f.Trend) != 3 || f.Trend[2].Levels[3] != 1 {
		t.Errorf("trend = %+v", f.Trend)
	}
}

// ---- US-08: scheduling -----------------------------------------------------------------------------

func TestAC08_ScheduledRescans(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	e := newEnv(t, withClock(clock), withScheduler(30*time.Millisecond))
	srv := classicalServer(t)
	a := e.addAsset(srv.Addr)

	var up assetJSON
	if s := e.call("PATCH", "/api/v1/assets/"+itoa(a.ID), map[string]any{"intervalSeconds": 3600}, &up); s != 200 ||
		up.Interval != 3600 || up.Next == nil {
		t.Fatalf("schedule: %d %+v", s, up)
	}
	// Not due yet: nothing happens.
	time.Sleep(200 * time.Millisecond)
	if n := scansOf(e, a.ID); n != 0 {
		t.Fatalf("%d scans ran before the interval elapsed", n)
	}

	clock.Advance(61 * time.Minute)
	deadline := time.Now().Add(30 * time.Second)
	var sched scanJSON
	for time.Now().Before(deadline) {
		var list []scanJSON
		e.call("GET", "/api/v1/scans?assetId="+itoa(a.ID), nil, &list)
		if len(list) > 0 {
			sched = list[0]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sched.ID == 0 || sched.Trigger != "scheduled" {
		t.Fatalf("no scheduled scan appeared: %+v", sched)
	}
	if done := e.wait(sched.ID); done.Status != "done" {
		t.Errorf("scheduled scan: %+v", done)
	}
	// It rescheduled itself from the completion time.
	var after assetJSON
	e.call("GET", "/api/v1/assets/"+itoa(a.ID), nil, &after)
	if after.Next == nil {
		t.Error("next scan not rescheduled")
	} else if nt, _ := time.Parse(time.RFC3339Nano, *after.Next); !nt.After(clock.Now()) {
		t.Errorf("next scan %v is not in the future (now %v)", nt, clock.Now())
	}

	// Turning it off stops the schedule.
	e.call("PATCH", "/api/v1/assets/"+itoa(a.ID), map[string]any{"intervalSeconds": 0}, &up)
	before := scansOf(e, a.ID)
	clock.Advance(48 * time.Hour)
	time.Sleep(300 * time.Millisecond)
	if scansOf(e, a.ID) != before {
		t.Error("a schedule that was turned off still fired")
	}
}

func scansOf(e *env, assetID int64) int {
	var list []scanJSON
	e.call("GET", "/api/v1/scans?assetId="+strconv.FormatInt(assetID, 10), nil, &list)
	return len(list)
}
