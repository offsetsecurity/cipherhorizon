package server_test

import (
	"encoding/csv"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/server"
	"github.com/example/cipherhorizon/internal/store"
)

// PRD-007 REQ-AC-2 (audit L-02): every state-changing route is accounted for, and each audited
// route, called successfully, adds exactly one row naming who did what to which object.
func TestEveryChangeIsAudited(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode))
	cookie := setupAdmin(t, e)

	// 1. Coverage over the real route table: a new mutating route cannot slip through.
	covered := map[string]bool{}
	for _, route := range e.srv.Routes() {
		if strings.HasPrefix(route, "GET ") {
			if server.AuditCoverage(route) != "" {
				t.Errorf("%s reads only, yet is listed as audited", route)
			}
			continue
		}
		covered[route] = true
		if server.AuditCoverage(route) == "" {
			t.Errorf("%s changes state but is in neither audit table (server/audit.go)", route)
		}
	}

	// 2. Each audited route, for real.
	count := func() int {
		list, err := e.st.Activity(store.ActivityFilter{Source: "change", Limit: 5000})
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	newest := func(n int) []store.ActivityEntry {
		list, _ := e.st.Activity(store.ActivityFilter{Source: "change", Limit: n})
		return list
	}
	call := func(method, path string, body any, wantStatus ...int) []byte {
		t.Helper()
		s, b, _ := e.as(cookie, method, path, body)
		for _, w := range wantStatus {
			if s == w {
				return b
			}
		}
		t.Fatalf("%s %s: %d %s", method, path, s, b)
		return nil
	}
	tls12 := tls12Server(t)
	hybrid := hybridServer(t)
	var a, b assetJSON
	slow := slowProxy(t, hybrid.Addr, 300*time.Millisecond)
	var running scanJSON
	var done scanJSON
	var findingKey string
	facts := "cipherhorizon-machine-facts\t1\nscript\tlinux-sh\t1.0.0\nhost\tname\taudit-host\nhost\tos\tlinux\nhost\tprivilege\tuser\n" +
		"package-manager\tdpkg\npackage\tdpkg\topenssl\t3.0.13-1\tamd64\n"

	steps := []struct {
		route string
		do    func() int64 // performs the call; returns the object id the row must name (0: any)
	}{
		{"POST /api/v1/assets", func() int64 {
			mustJSON(t, call("POST", "/api/v1/assets", map[string]any{"target": tls12.Addr}, 201), &a)
			return a.ID
		}},
		{"POST /api/v1/assets/bulk", func() int64 {
			call("POST", "/api/v1/assets/bulk", map[string]any{"text": hybrid.Addr + "\n" + slow}, 200)
			list := []assetJSON{}
			mustJSON(t, call("GET", "/api/v1/assets", nil, 200), &list)
			for _, x := range list {
				if x.Address == hybrid.Addr || x.Host+":"+itoa(int64(x.Port)) == hybrid.Addr {
					b = x
				}
			}
			return 0
		}},
		{"PATCH /api/v1/assets/{id}", func() int64 {
			call("PATCH", "/api/v1/assets/"+itoa(a.ID), map[string]any{"name": "renamed"}, 200)
			return a.ID
		}},
		{"POST /api/v1/assets/{id}/scan", func() int64 {
			var out struct {
				Scan scanJSON `json:"scan"`
			}
			mustJSON(t, call("POST", "/api/v1/assets/"+itoa(a.ID)+"/scan", nil, 202, 200), &out)
			done = e.waitAs(cookie, out.Scan.ID)
			fs := e.getAssetFindingsAs(cookie, a.ID)
			if len(fs) == 0 {
				t.Fatal("a TLS 1.2-only server must have findings")
			}
			findingKey = fs[0]
			return a.ID
		}},
		{"PUT /api/v1/assets/{id}/findings/{key}/status", func() int64 {
			call("PUT", "/api/v1/assets/"+itoa(a.ID)+"/findings/"+findingKey+"/status", map[string]any{"status": "acknowledged"}, 204)
			return a.ID
		}},
		{"DELETE /api/v1/assets/{id}/findings/{key}/status", func() int64 {
			call("DELETE", "/api/v1/assets/"+itoa(a.ID)+"/findings/"+findingKey+"/status", nil, 204)
			return a.ID
		}},
		{"PUT /api/v1/assets/{id}/links/{otherId}", func() int64 {
			call("PUT", "/api/v1/assets/"+itoa(a.ID)+"/links/"+itoa(b.ID), nil, 204, 200)
			return a.ID
		}},
		{"DELETE /api/v1/assets/{id}/links/{otherId}", func() int64 {
			call("DELETE", "/api/v1/assets/"+itoa(a.ID)+"/links/"+itoa(b.ID), nil, 204, 200)
			return a.ID
		}},
		{"POST /api/v1/scans/{id}/reevaluate", func() int64 {
			call("POST", "/api/v1/scans/"+itoa(done.ID)+"/reevaluate", nil, 200)
			return done.ID
		}},
		{"POST /api/v1/scans", func() int64 {
			var out struct {
				Scans []scanJSON `json:"scans"`
			}
			list := []assetJSON{}
			mustJSON(t, call("GET", "/api/v1/assets", nil, 200), &list)
			var slowID int64
			for _, x := range list {
				if x.ID != a.ID && x.ID != b.ID {
					slowID = x.ID
				}
			}
			mustJSON(t, call("POST", "/api/v1/scans", map[string]any{"assetIds": []int64{slowID}}, 202), &out)
			running = out.Scans[0]
			return 0
		}},
		{"POST /api/v1/scans/{id}/cancel", func() int64 {
			call("POST", "/api/v1/scans/"+itoa(running.ID)+"/cancel", nil, 200)
			return running.ID
		}},
		{"POST /api/v1/hosts/ingest", func() int64 {
			s, body, _ := e.req("POST", "/api/v1/hosts/ingest", facts, map[string]string{"Content-Type": "text/plain; charset=utf-8",
				"Cookie": "ch_session=" + cookie, "Authorization": ""})
			if s != 200 && s != 201 {
				t.Fatalf("ingest: %d %s", s, body)
			}
			return 0
		}},
		{"DELETE /api/v1/assets/{id}", func() int64 {
			call("DELETE", "/api/v1/assets/"+itoa(b.ID), nil, 204)
			return b.ID
		}},
	}
	tested := map[string]bool{}
	for _, st := range steps {
		before := count()
		wantID := st.do()
		// Exactly one row is this route's own; a route whose change also reshapes systems (a link
		// merges them) adds the store's more detailed row too.
		kind, action := server.AuditActionOf(st.route)
		if count() == before {
			t.Errorf("%s: no audit row", st.route)
			continue
		}
		var mine []store.ActivityEntry
		for _, x := range newest(count() - before) {
			if x.ObjectKind == kind && x.Action == action {
				mine = append(mine, x)
			}
		}
		if len(mine) != 1 {
			t.Errorf("%s: %d rows of its own (%s %s), want exactly 1", st.route, len(mine), kind, action)
			continue
		}
		row := mine[0]
		if row.Actor != "ana" {
			t.Errorf("%s: actor %q, want ana", st.route, row.Actor)
		}
		if row.Action == "" || row.ObjectKind == "" {
			t.Errorf("%s: row %+v names no action or object", st.route, row)
		}
		if wantID != 0 && row.ObjectID != wantID {
			t.Errorf("%s: object %d, want %d", st.route, row.ObjectID, wantID)
		}
		tested[st.route] = true
	}
	for route := range covered {
		if server.AuditCoverage(route) == "audited" && !tested[route] {
			t.Errorf("%s is audited but this test never calls it", route)
		}
	}

	// A refused call writes nothing.
	before := count()
	if s, _, _ := e.as(cookie, "POST", "/api/v1/assets", map[string]any{"target": "not a target!"}); s != 400 {
		t.Fatalf("a bad target: %d", s)
	}
	if count() != before {
		t.Error("a refused change was recorded")
	}
}

// waitAs polls a scan with a session cookie until it finishes.
func (e *env) waitAs(cookie string, id int64) scanJSON {
	e.t.Helper()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var out struct {
			Scan scanJSON `json:"scan"`
		}
		_, b, _ := e.as(cookie, "GET", "/api/v1/scans/"+itoa(id), nil)
		mustJSON(e.t, b, &out)
		switch out.Scan.Status {
		case "done", "failed", "canceled":
			return out.Scan
		}
	}
	e.t.Fatalf("scan %d did not finish", id)
	return scanJSON{}
}

// getAssetFindingsAs lists an asset's finding keys with a session cookie.
func (e *env) getAssetFindingsAs(cookie string, id int64) []string {
	e.t.Helper()
	var out []struct {
		Key string `json:"key"`
	}
	_, b, _ := e.as(cookie, "GET", "/api/v1/assets/"+itoa(id)+"/findings", nil)
	mustJSON(e.t, b, &out)
	keys := make([]string, 0, len(out))
	for _, f := range out {
		keys = append(keys, f.Key)
	}
	return keys
}

// REQ-AC-3: the Activity list and its CSV are for administrators only, hold sign-ins and changes
// together, filter by person and kind, and are safe to open in a spreadsheet.
func TestAuditExportIsAdminOnly(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode), withToken("an-automation-token-0123456789"))
	admin := setupAdmin(t, e)
	// A new account starts with a temporary password it must change; that change signs it in again.
	newUser := func(name, role string) string {
		t.Helper()
		if s, b, _ := e.as(admin, "POST", "/api/v1/users", map[string]any{"username": name, "role": role, "password": "temporary pass phrase one"}); s != 201 {
			t.Fatalf("create %s: %d %s", name, s, b)
		}
		_, c := login(t, e, name, "temporary pass phrase one")
		s, b, h := e.as(c, "POST", "/api/v1/auth/password", map[string]any{"current": "temporary pass phrase one", "new": "violet amber harbour"})
		if s != 204 {
			t.Fatalf("%s changes the password: %d %s", name, s, b)
		}
		return cookieOf(t, h)
	}
	viewer := newUser("vic", "viewer")
	analyst := newUser("alan", "analyst")
	// The analyst adds an endpoint whose name a spreadsheet would run as a formula.
	if s, b, _ := e.as(analyst, "POST", "/api/v1/assets", map[string]any{"target": "10.9.9.9:443", "name": "=HYPERLINK(\"http://x\")"}); s != 201 {
		t.Fatalf("analyst add: %d %s", s, b)
	}
	if s, _, _ := e.as(analyst, "PATCH", "/api/v1/assets/1", map[string]any{"name": "@SUM(1)"}); s != 200 {
		t.Fatalf("analyst edit: %d", s)
	}

	for _, path := range []string{"/api/v1/audit", "/api/v1/audit.csv"} {
		for who, c := range map[string]string{"viewer": viewer, "analyst": analyst} {
			if s, _, _ := e.as(c, "GET", path, nil); s != 403 {
				t.Errorf("%s as %s: %d, want 403", path, who, s)
			}
		}
		if s, _ := e.do("GET", path, nil); s != 403 { // the automation token acts as an analyst
			t.Errorf("%s with the automation token: %d, want 403", path, s)
		}
		if s, _, _ := e.req("GET", path, nil, map[string]string{"Authorization": ""}); s != 401 {
			t.Errorf("%s signed out: %d, want 401", path, s)
		}
	}

	var all struct {
		Entries []store.ActivityEntry `json:"entries"`
	}
	s, raw, _ := e.as(admin, "GET", "/api/v1/audit", nil)
	mustJSON(t, raw, &all)
	if s != 200 {
		t.Fatalf("admin: %d", s)
	}
	kinds := map[string]bool{}
	for _, x := range all.Entries {
		kinds[x.Source] = true
	}
	if !kinds["change"] || !kinds["sign-in"] {
		t.Errorf("the list holds %v; want changes and sign-ins together", kinds)
	}
	var mine struct {
		Entries []store.ActivityEntry `json:"entries"`
	}
	_, raw, _ = e.as(admin, "GET", "/api/v1/audit?person=alan&source=change", nil)
	mustJSON(t, raw, &mine)
	if len(mine.Entries) != 2 {
		t.Errorf("alan's changes: %d entries, want 2: %+v", len(mine.Entries), mine.Entries)
	}
	for _, x := range mine.Entries {
		if x.Actor != "alan" || x.Source != "change" {
			t.Errorf("filter leaked %+v", x)
		}
	}
	if s, _, _ := e.as(admin, "GET", "/api/v1/audit?source=nonsense", nil); s != 400 {
		t.Errorf("a bad source filter: %d, want 400", s)
	}

	s, body, h := e.as(admin, "GET", "/api/v1/audit.csv", nil)
	if s != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/csv") || !strings.Contains(h.Get("Content-Disposition"), "attachment") {
		t.Fatalf("csv: %d %v", s, h)
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil || len(rows) < 3 || rows[0][0] != "at" {
		t.Fatalf("csv: %v %v", err, rows)
	}
	for _, r := range rows[1:] {
		for _, cell := range r {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Errorf("a cell a spreadsheet would run: %q", cell)
			}
		}
	}
	_ = http.StatusOK
}

// REQ-AC-4: a scan records who started it: a person, the automation token, or the schedule.
func TestScanRecordsWhoStartedIt(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	fc := &fakeClock{t: time.Now()}
	e := newEnv(t, withLogin(setupCode), withToken("an-automation-token-0123456789"), withClock(fc), withScheduler(20*time.Millisecond))
	admin := setupAdmin(t, e)
	srv := hybridServer(t)
	var a assetJSON
	_, raw, _ := e.as(admin, "POST", "/api/v1/assets", map[string]any{"target": srv.Addr})
	mustJSON(t, raw, &a)

	var out struct {
		Scan scanJSON `json:"scan"`
	}
	_, raw, _ = e.as(admin, "POST", "/api/v1/assets/"+itoa(a.ID)+"/scan", nil)
	mustJSON(t, raw, &out)
	e.wait(out.Scan.ID)
	byToken := e.scanAndWait(a.ID) // e.req sends the automation token

	if s := e.call("PATCH", "/api/v1/assets/"+itoa(a.ID), map[string]any{"intervalSeconds": 3600}, nil); s != 200 {
		t.Fatalf("set schedule: %d", s)
	}
	fc.Advance(2 * time.Hour)
	var scheduled store.ScanSummary
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		list, err := e.st.ListScans(store.ScanFilter{AssetID: a.ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, sc := range list {
			if sc.Trigger == "scheduled" {
				scheduled = sc.ScanSummary
			}
		}
		if scheduled.ID != 0 {
			break
		}
	}
	got := map[int64]string{}
	list, _ := e.st.ListScans(store.ScanFilter{AssetID: a.ID})
	for _, sc := range list {
		got[sc.ID] = sc.StartedBy
	}
	if got[out.Scan.ID] != "ana" || got[byToken.ID] != "api-token" || scheduled.ID == 0 || got[scheduled.ID] != "schedule" {
		t.Fatalf("started by: %v (person %d, token %d, schedule %d)", got, out.Scan.ID, byToken.ID, scheduled.ID)
	}
	var viaAPI struct {
		Scan struct {
			StartedBy string `json:"startedBy"`
		} `json:"scan"`
	}
	if e.call("GET", "/api/v1/scans/"+itoa(out.Scan.ID), nil, &viaAPI); viaAPI.Scan.StartedBy != "ana" {
		t.Errorf("the API does not show who started it: %+v", viaAPI)
	}
}
