package server_test

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"
)

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../testing/golden/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// AC-10.1: a CBOM produced by `cipherhorizon run` becomes a host asset with cited verdicts.
func TestAC10_HostCBOMIngest(t *testing.T) {
	e := newEnv(t)
	cbom := golden(t, "ubuntu-24.04.cbom.json")

	var out struct {
		Created    bool  `json:"created"`
		SnapshotID int64 `json:"snapshotId"`
		Asset      assetJSON
		Summary    struct {
			Name         string   `json:"name"`
			Producer     string   `json:"producer"`
			Packages     int      `json:"packages"`
			Vulnerable   int      `json:"vulnerable"`
			Safe         int      `json:"safe"`
			Unclassified []string `json:"unclassified"`
			Algorithms   []struct {
				Name       string   `json:"name"`
				Class      string   `json:"class"`
				MatchedBy  string   `json:"matchedBy"`
				Rationale  string   `json:"rationale"`
				ProvidedBy []string `json:"providedBy"`
				Basis      []struct{ Title, URL string }
			} `json:"algorithms"`
		} `json:"summary"`
	}
	status, raw, _ := e.req("POST", "/api/v1/hosts/ingest", cbom, nil)
	if status != 201 {
		t.Fatalf("ingest: %d %s", status, raw)
	}
	e.call("GET", "/api/v1/hosts", nil, nil) // smoke
	mustJSON(t, raw, &out)
	if !out.Created || out.Asset.Name != "fixture-host" || out.Summary.Vulnerable != 6 || out.Summary.Safe != 4 || out.Summary.Packages != 7 {
		t.Errorf("ingest result = created %v name %q vulnerable %d safe %d packages %d",
			out.Created, out.Asset.Name, out.Summary.Vulnerable, out.Summary.Safe, out.Summary.Packages)
	}
	if !strings.Contains(out.Summary.Producer, "cipherhorizon") {
		t.Errorf("producer = %q", out.Summary.Producer)
	}
	var rsa bool
	for _, a := range out.Summary.Algorithms {
		if len(a.Basis) == 0 || a.Rationale == "" || a.MatchedBy == "" {
			t.Errorf("algorithm %s has no basis/rationale", a.Name)
		}
		if a.Name == "RSA" {
			rsa = true
			joined := strings.Join(a.ProvidedBy, ",")
			if a.Class != "quantum-vulnerable" || !strings.Contains(joined, "libssl3t64 3.0.13-0ubuntu3.4") || !strings.Contains(joined, "gpg 2.4.4-2ubuntu17") {
				t.Errorf("RSA = %+v", a)
			}
		}
	}
	if !rsa {
		t.Error("RSA not in the summary")
	}

	// Uploading again updates the same host and keeps both snapshots.
	status, raw, _ = e.req("POST", "/api/v1/hosts/ingest", cbom, nil)
	if status != 200 {
		t.Fatalf("second ingest: %d", status)
	}
	mustJSON(t, raw, &out)
	if out.Created || out.Asset.ID == 0 {
		t.Errorf("second ingest = %+v", out)
	}

	var hosts []struct {
		Name      string `json:"name"`
		Snapshots int    `json:"snapshots"`
		Summary   struct{ Vulnerable int }
	}
	e.call("GET", "/api/v1/hosts", nil, &hosts)
	if len(hosts) != 1 || hosts[0].Snapshots != 2 || hosts[0].Summary.Vulnerable != 6 {
		t.Errorf("hosts = %+v", hosts)
	}
	var detail struct {
		History []struct{ Vulnerable, Safe int } `json:"history"`
	}
	if s := e.call("GET", "/api/v1/hosts/"+itoa(out.Asset.ID), nil, &detail); s != 200 || len(detail.History) != 2 {
		t.Errorf("host detail: %d %+v", s, detail)
	}

	// A host is not a scannable endpoint, and does not show up among TLS endpoints.
	if s, _ := e.do("POST", "/api/v1/assets/"+itoa(out.Asset.ID)+"/scan", nil); s != 400 {
		t.Errorf("scanning a host: %d, want 400", s)
	}
	var tlsAssets []assetJSON
	e.call("GET", "/api/v1/assets?kind=tls-endpoint", nil, &tlsAssets)
	if len(tlsAssets) != 0 {
		t.Errorf("a host appears among TLS endpoints: %+v", tlsAssets)
	}

	// The PQ-capable fixture: OpenSSL 3.5 brings post-quantum algorithms.
	var deb struct {
		Summary struct{ Vulnerable, Safe int }
	}
	e.call("POST", "/api/v1/hosts/ingest", golden(t, "debian-13.cbom.json"), &deb)
	if deb.Summary.Vulnerable != 5 || deb.Summary.Safe != 22 {
		t.Errorf("debian-13 summary = %+v", deb.Summary)
	}
}

func TestAC10_IngestRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		path, body string
		want       int
	}{
		"not json":           {"/api/v1/hosts/ingest", "this is not json", 400},
		"json but not a bom": {"/api/v1/hosts/ingest", `{"hello":"world"}`, 400},
		"wrong bomFormat":    {"/api/v1/hosts/ingest", `{"bomFormat":"SPDX","specVersion":"1.6"}`, 400},
		"no host name":       {"/api/v1/hosts/ingest", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`, 400},
		"control chars name": {"/api/v1/hosts/ingest?name=a%0Ab", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`, 400},
		"name via query":     {"/api/v1/hosts/ingest?name=custom-host", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`, 201},
		"bidi override name": {"/api/v1/hosts/ingest?name=a%E2%80%AEb", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`, 400},
		"invalid utf-8 name": {"/api/v1/hosts/ingest?name=a%FFb", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`, 400},
		"name too long":      {"/api/v1/hosts/ingest?name=" + strings.Repeat("a", 101), `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`, 400},
	} {
		if s, b, _ := e.req("POST", tc.path, tc.body, nil); s != tc.want {
			t.Errorf("%s: %d, want %d (%s)", name, s, tc.want, b)
		}
	}
	// An empty CBOM is a valid host with nothing found.
	var hosts []struct {
		Name    string
		Summary struct{ Vulnerable, Safe, Packages int }
	}
	e.call("GET", "/api/v1/hosts", nil, &hosts)
	if len(hosts) != 1 || hosts[0].Name != "custom-host" || hosts[0].Summary.Packages != 0 {
		t.Errorf("hosts = %+v", hosts)
	}
}

// AC-09.1
func TestAC09_Export(t *testing.T) {
	e := newEnv(t)
	good := e.addAsset(hybridServer(t).Addr)
	bad := e.addAsset(classicalServer(t).Addr)
	e.scanAndWait(good.ID)
	e.scanAndWait(bad.ID)
	// A spreadsheet must not run a formula smuggled in through a name.
	var up assetJSON
	e.call("PATCH", "/api/v1/assets/"+itoa(bad.ID), map[string]any{"name": `=HYPERLINK("http://evil.example","click")`, "tags": []string{"@sum", "+x"}}, &up)
	e.addAsset("unscanned.example")

	status, raw, h := e.req("GET", "/api/v1/export/assets.csv", nil, nil)
	if status != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/csv") || !strings.Contains(h.Get("Content-Disposition"), "assets.csv") {
		t.Fatalf("export: %d %v", status, h)
	}
	rows, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("not valid CSV: %v\n%s", err, raw)
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want header + 3", len(rows))
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	for _, want := range []string{"name", "address", "tags", "hygiene_band", "pqc_level", "pqc_label", "hndl_exposed", "critical", "high", "cert_expires", "last_scan", "status", "rescan_interval_seconds", "hygiene_score"} {
		if _, ok := col[want]; !ok {
			t.Errorf("column %q missing from %v", want, rows[0])
		}
	}
	byAddr := map[string][]string{}
	for _, r := range rows[1:] {
		byAddr[r[col["address"]]] = r
	}
	if r := byAddr[good.Address]; r[col["pqc_level"]] != "3" || r[col["pqc_label"]] != "Hybrid negotiated" || r[col["hndl_exposed"]] != "false" || r[col["status"]] != "done" || r[col["cert_expires"]] == "" {
		t.Errorf("hybrid row = %v", r)
	}
	if r := byAddr[bad.Address]; r[col["pqc_level"]] != "1" || r[col["hndl_exposed"]] != "true" {
		t.Errorf("classical row = %v", r)
	}
	if r := byAddr["unscanned.example:443"]; r[col["hygiene_band"]] != "" || r[col["pqc_level"]] != "" {
		t.Errorf("unscanned row must have empty result columns: %v", r)
	}
	// Formula injection defused: every dangerous leading character is neutralised.
	for _, r := range rows[1:] {
		for _, cell := range r {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Errorf("cell %q could be executed as a formula", cell)
			}
		}
	}
	if r := byAddr[bad.Address]; !strings.HasPrefix(r[col["name"]], "'=") {
		t.Errorf("name cell = %q", r[col["name"]])
	}

	// About: the UI shows the limits and the notice.
	var about map[string]any
	e.call("GET", "/api/v1/about", nil, &about)
	if about["version"] != "test" || about["registryRetrieved"] != "2026-09-21" || !strings.Contains(about["notice"].(string), "authorised") ||
		about["authRequired"] != false || about["allowLoopback"] != true {
		t.Errorf("about = %v", about)
	}
}
