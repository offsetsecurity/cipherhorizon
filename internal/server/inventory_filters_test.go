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
