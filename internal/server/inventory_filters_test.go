package server_test

import (
	"net/url"
	"testing"
)

// TestInventoryFiltersByQuantumAndPurpose is PRD-009 REQ-CHT-2: every figure the dashboard draws
// opens a list whose length is that figure, because the list filters by the dashboard's own
// buckets.
func TestInventoryFiltersByQuantumAndPurpose(t *testing.T) {
	e := newEnv(t)
	for _, a := range []assetJSON{e.addAsset(hybridServer(t).Addr), e.addAsset(classicalServer(t).Addr)} {
		if sc := e.scanAndWait(a.ID); sc.Status != "done" {
			t.Fatalf("scan %+v", sc)
		}
	}
	var d struct {
		Quantum   map[string]int `json:"quantum"`
		ByPurpose []struct {
			Purpose    string `json:"purpose"`
			Vulnerable int    `json:"vulnerable"`
			Safe       int    `json:"safe"`
			Unknown    int    `json:"unknown"`
		} `json:"byPurpose"`
	}
	if s := e.call("GET", "/api/v1/inventory/dashboard", nil, &d); s != 200 {
		t.Fatalf("dashboard: %d", s)
	}
	if len(d.ByPurpose) == 0 {
		t.Fatal("the dashboard has no purposes to check")
	}
	for _, p := range d.ByPurpose {
		for bucket, want := range map[string]int{"vulnerable": p.Vulnerable, "safe": p.Safe, "unknown": p.Unknown} {
			q := "kind=algorithm&imported=1&purpose=" + url.QueryEscape(p.Purpose) + "&quantum=" + bucket
			if got := len(e.inventoryRows(q)); got != want {
				t.Errorf("%s, %s: the dashboard says %d, the list holds %d", p.Purpose, bucket, want, got)
			}
		}
	}
	// The ring counts algorithms and keys together; the two lists add up to it.
	for bucket, want := range d.Quantum {
		got := len(e.inventoryRows("kind=algorithm&imported=1&quantum="+bucket)) + len(e.inventoryRows("kind=key&imported=1&quantum="+bucket))
		if got != want {
			t.Errorf("quantum %s: the dashboard says %d, the lists hold %d", bucket, want, got)
		}
	}
	// vulnerable=1 still works, as quantum=vulnerable.
	if a, b := len(e.inventoryRows("kind=algorithm&vulnerable=1")), len(e.inventoryRows("kind=algorithm&quantum=vulnerable")); a != b || a == 0 {
		t.Errorf("vulnerable=1 gives %d rows, quantum=vulnerable %d", a, b)
	}
	for _, bad := range []string{"quantum=maybe", "purpose=Dancing"} {
		if s, _ := e.do("GET", "/api/v1/inventory?kind=algorithm&"+bad, nil); s != 400 {
			t.Errorf("%s: %d, want 400", bad, s)
		}
	}
}

// PRD-010 REQ-STR-6: inventory rows carry their classical strength: bits with a source, or a
// cited broken status; a key takes the strength of its algorithm at its size.
func TestInventoryRowsCarryClassicalStrength(t *testing.T) {
	e := newEnv(t)
	if sc := e.scanAndWait(e.addAsset(hybridServer(t).Addr).ID); sc.Status != "done" {
		t.Fatalf("scan %+v", sc)
	}
	type row struct {
		Name     string `json:"name"`
		Strength *struct {
			Bits   int    `json:"bits"`
			Status string `json:"status"`
			Basis  string `json:"basis"`
		} `json:"classicalStrength"`
	}
	var out struct {
		Rows []row `json:"rows"`
	}
	for _, kind := range []string{"algorithm", "key"} {
		if s := e.call("GET", "/api/v1/inventory?kind="+kind, nil, &out); s != 200 {
			t.Fatalf("%s: %d", kind, s)
		}
		if len(out.Rows) == 0 {
			t.Fatalf("no %s rows", kind)
		}
		for _, r := range out.Rows {
			if r.Strength == nil || r.Strength.Status == "" || r.Strength.Basis == "" {
				t.Errorf("%s %s has no classical strength", kind, r.Name)
			}
		}
	}
	e.call("GET", "/api/v1/inventory?kind=algorithm", nil, &out)
	got := map[string]int{}
	for _, r := range out.Rows {
		got[r.Name] = r.Strength.Bits
	}
	for name, want := range map[string]int{"X25519": 128, "X25519MLKEM768": 192, "AES-128-GCM": 128} {
		if got[name] != want {
			t.Errorf("%s: %d bits, want %d (rows: %v)", name, got[name], want, got)
		}
	}
}

// PRD-011 REQ-CLS-7: every algorithm and key row has a class, and ?class= keeps only that class.
func TestInventoryFiltersByClass(t *testing.T) {
	e := newEnv(t)
	if sc := e.scanAndWait(e.addAsset(hybridServer(t).Addr).ID); sc.Status != "done" {
		t.Fatalf("scan %+v", sc)
	}
	type row struct {
		Name  string `json:"name"`
		Class string `json:"class"`
	}
	var out struct {
		Rows []row `json:"rows"`
	}
	for _, kind := range []string{"algorithm", "key"} {
		e.call("GET", "/api/v1/inventory?kind="+kind, nil, &out)
		for _, r := range out.Rows {
			if r.Class == "" {
				t.Errorf("%s %s has no class", kind, r.Name)
			}
		}
	}
	seen := map[string]string{}
	for _, class := range []string{"asymmetric", "symmetric", "hash"} {
		if s := e.call("GET", "/api/v1/inventory?kind=algorithm&class="+class, nil, &out); s != 200 {
			t.Fatalf("class %s: %d", class, s)
		}
		for _, r := range out.Rows {
			if r.Class != class {
				t.Errorf("class=%s listed %s (%s)", class, r.Name, r.Class)
			}
			seen[r.Name] = class
		}
	}
	for name, want := range map[string]string{"X25519": "asymmetric", "X25519MLKEM768": "asymmetric", "AES-128-GCM": "symmetric"} {
		if seen[name] != want {
			t.Errorf("%s is in class %q, want %q", name, seen[name], want)
		}
	}
	if s := e.call("GET", "/api/v1/inventory?kind=algorithm&class=quantum", nil, nil); s != 400 {
		t.Errorf("an unknown class answered %d, want 400", s)
	}
}
