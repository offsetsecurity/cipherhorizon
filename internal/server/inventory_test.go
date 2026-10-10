package server_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
)

type invRow struct {
	Name    string `json:"name"`
	Detail  string `json:"detail"`
	Quantum string `json:"quantum"`
	Places  []struct {
		Label string    `json:"label"`
		Kind  string    `json:"kind"`
		When  time.Time `json:"when"`
	} `json:"places"`
	LastSeen *time.Time `json:"lastSeen"`
}

func (e *env) inventoryRows(query string) []invRow {
	e.t.Helper()
	var out struct {
		Rows []invRow `json:"rows"`
	}
	if s := e.call("GET", "/api/v1/inventory?"+query, nil, &out); s != 200 {
		e.t.Fatalf("inventory %s: %d", query, s)
	}
	return out.Rows
}

func rowNamed(rows []invRow, name string) *invRow {
	for i := range rows {
		if rows[i].Name == name {
			return &rows[i]
		}
	}
	return nil
}

// TestInventoryIsTheMergedCBOM is PRD-005 REQ-INV-1..5/7: the inventory lists what the scans
// saw with its cited quantum status and where, filters work, and the whole-inventory CBOM is
// one valid CycloneDX document in both versions, with imported CBOMs only when asked for.
func TestInventoryIsTheMergedCBOM(t *testing.T) {
	e := newEnv(t)
	hy := e.addAsset(hybridServer(t).Addr)
	cl := e.addAsset(classicalServer(t).Addr)
	for _, a := range []assetJSON{hy, cl} {
		if sc := e.scanAndWait(a.ID); sc.Status != "done" {
			t.Fatalf("scan %+v", sc)
		}
	}

	algs := e.inventoryRows("kind=algorithm")
	if r := rowNamed(algs, "X25519MLKEM768"); r == nil || r.Quantum != "quantum-safe" || len(r.Places) != 1 || r.Places[0].Kind != "endpoint" {
		t.Errorf("hybrid group row: %+v", r)
	}
	if r := rowNamed(algs, "AES-128-GCM"); r == nil || r.Quantum != "quantum-safe" || len(r.Places) != 2 {
		t.Errorf("AES-128-GCM seen on both endpoints: %+v", r)
	} else if r.LastSeen == nil || r.Places[0].When.IsZero() || r.Places[1].When.IsZero() ||
		(!r.LastSeen.Equal(r.Places[0].When) && !r.LastSeen.Equal(r.Places[1].When)) {
		t.Errorf("a row is last seen when the latest of its places reported: %+v", r) // REQ-INV-3
	}
	if r := rowNamed(algs, "X25519"); r == nil || r.Quantum != "quantum-vulnerable" {
		t.Errorf("X25519: %+v", r)
	}
	if len(algs) == 0 || algs[0].Quantum != "quantum-vulnerable" {
		t.Errorf("quantum-vulnerable rows come first: %+v", algs)
	}
	for _, r := range e.inventoryRows("kind=algorithm&vulnerable=1") {
		if r.Quantum != "quantum-vulnerable" {
			t.Errorf("vulnerable filter let through %s (%s)", r.Name, r.Quantum)
		}
	}
	if rows := e.inventoryRows("kind=algorithm&q=gcm"); len(rows) == 0 || rowNamed(rows, "X25519") != nil {
		t.Errorf("text filter: %+v", rows)
	}
	if keys := e.inventoryRows("kind=key"); len(keys) == 0 || keys[0].Quantum != "quantum-vulnerable" {
		t.Errorf("keys take their algorithm's status: %+v", keys)
	}
	if protos := e.inventoryRows("kind=protocol"); rowNamed(protos, "TLSv1.3") == nil {
		t.Errorf("protocols: %+v", protos)
	}
	for _, bad := range []string{"kind=nope", "source=elsewhere"} {
		if s, _ := e.do("GET", "/api/v1/inventory?"+bad, nil); s != 400 {
			t.Errorf("%s: %d", bad, s)
		}
	}

	var sum map[string]int
	e.call("GET", "/api/v1/inventory/summary", nil, &sum)
	if sum["endpoints"] != 2 || sum["algorithm"] != len(algs) || sum["quantumVulnerable"] == 0 || sum["quantumSafe"] == 0 {
		t.Errorf("summary %v", sum)
	}

	// Import a CBOM: it is in the inventory only when asked for, under its own refs.
	if s, _, raw := upload(e, interop(t, "cbomlens-like-1.7.json"), "newSystem=imported"); s != 201 && s != 200 {
		t.Fatalf("import: %d %s", s, raw)
	}
	for _, spec := range []string{"1.6", "1.7"} {
		for _, imported := range []string{"0", "1"} {
			s, body, hdr := e.req("GET", "/api/v1/inventory/cbom?spec="+spec+"&imported="+imported+"&download=1", nil, nil)
			if s != 200 || !strings.Contains(hdr.Get("Content-Disposition"), "attachment") {
				t.Fatalf("cbom %s/%s: %d", spec, imported, s)
			}
			schematest.Validate(t, body)
			var doc struct {
				SpecVersion string `json:"specVersion"`
				Components  []struct {
					BOMRef     string `json:"bom-ref"`
					Properties []struct{ Name, Value string }
				} `json:"components"`
			}
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.SpecVersion != spec {
				t.Errorf("spec %s", doc.SpecVersion)
			}
			seen, fromImport := false, false
			refs := map[string]bool{}
			for _, c := range doc.Components {
				if refs[c.BOMRef] {
					t.Errorf("duplicate bom-ref %s", c.BOMRef)
				}
				refs[c.BOMRef] = true
				fromImport = fromImport || strings.HasPrefix(c.BOMRef, "import-")
				for _, p := range c.Properties {
					seen = seen || p.Name == "cipherhorizon:seen-in" && strings.Contains(p.Value, "(endpoint)")
				}
			}
			if !seen {
				t.Errorf("%s: no component says where it was seen", spec)
			}
			if fromImport != (imported == "1") {
				t.Errorf("%s imported=%s: components from the import present=%v", spec, imported, fromImport)
			}
		}
	}
	if s, _ := e.do("GET", "/api/v1/inventory/cbom?spec=2.0", nil); s != 400 {
		t.Errorf("bad spec: %d", s)
	}
}
