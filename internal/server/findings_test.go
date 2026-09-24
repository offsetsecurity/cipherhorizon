package server_test

import (
	"net/http"
	"testing"

	"github.com/example/cipherhorizon/internal/server"
)

// getAssetFindings fetches fresh into a new slice each time: json.Unmarshal
// into an existing slice/struct does not reset fields absent from the new
// payload (an omitempty field that becomes empty just isn't overwritten), so
// reusing one variable across calls silently keeps stale data.
func (e *env) getAssetFindings(assetID int64) []server.FlatFinding {
	e.t.Helper()
	var findings []server.FlatFinding
	if s := e.call("GET", "/api/v1/assets/"+itoa(assetID)+"/findings", nil, &findings); s != 200 {
		e.t.Fatalf("list findings: %d", s)
	}
	return findings
}

func findingByKey(findings []server.FlatFinding, key string) (server.FlatFinding, bool) {
	for _, f := range findings {
		if f.Key == key {
			return f, true
		}
	}
	return server.FlatFinding{}, false
}

func TestFindingsTriageLifecycle(t *testing.T) {
	e := newEnv(t)
	srv := tls12Server(t)
	a := e.addAsset(srv.Addr)
	e.scanAndWait(a.ID)

	findings := e.getAssetFindings(a.ID)
	if len(findings) == 0 {
		t.Fatal("a TLS1.2-only server must produce at least one finding to triage")
	}
	key := findings[0].Key
	if findings[0].Status != nil {
		t.Fatalf("a fresh finding must start untriaged: %+v", findings[0])
	}

	// Set triage.
	if s := e.call("PUT", "/api/v1/assets/"+itoa(a.ID)+"/findings/"+key+"/status",
		map[string]any{"status": "accepted-risk", "note": "known, tracked in TICKET-1"}, nil); s != http.StatusNoContent {
		t.Fatalf("set status: %d", s)
	}

	f, ok := findingByKey(e.getAssetFindings(a.ID), key)
	if !ok {
		t.Fatalf("triaged finding %q disappeared", key)
	}
	if f.Status == nil || f.Status.Status != "accepted-risk" || f.Status.Note != "known, tracked in TICKET-1" {
		t.Errorf("finding after triage = %+v", f)
	}

	// Clear triage.
	if s := e.call("DELETE", "/api/v1/assets/"+itoa(a.ID)+"/findings/"+key+"/status", nil, nil); s != http.StatusNoContent {
		t.Fatalf("clear status: %d", s)
	}
	f, ok = findingByKey(e.getAssetFindings(a.ID), key)
	if !ok {
		t.Fatalf("finding %q disappeared after clearing triage", key)
	}
	if f.Status != nil {
		t.Errorf("status should be cleared: %+v", f)
	}
}

func TestFindingsTriageRejectsBadStatus(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset(tls12Server(t).Addr)
	e.scanAndWait(a.ID)
	findings := e.getAssetFindings(a.ID)
	if len(findings) == 0 {
		t.Fatal("need at least one finding")
	}
	if s, _ := e.do("PUT", "/api/v1/assets/"+itoa(a.ID)+"/findings/"+findings[0].Key+"/status", map[string]any{"status": "resolved"}); s != http.StatusBadRequest {
		t.Errorf("\"resolved\" must be rejected as a settable status: got %d", s)
	}
}

// TestFleetFindingsSpansAssetKinds covers the whole fleet-wide findings view:
// a TLS endpoint's cited rule findings and a host's quantum-vulnerable
// algorithm findings must both appear, distinguishably (a host finding never
// claims a severity it doesn't have), and filters must work.
func TestFleetFindingsSpansAssetKinds(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset(tls12Server(t).Addr)
	e.scanAndWait(a.ID)

	cbom := golden(t, "ubuntu-24.04.cbom.json")
	if s, b := e.do("POST", "/api/v1/hosts/ingest", cbom); s != http.StatusCreated && s != http.StatusOK {
		t.Fatalf("ingest host: %d %s", s, b)
	}

	var all []server.FlatFinding
	if s := e.call("GET", "/api/v1/findings", nil, &all); s != 200 {
		t.Fatalf("fleet findings: %d", s)
	}
	var sawTLS, sawHost bool
	for _, f := range all {
		switch f.AssetKind {
		case "tls-endpoint":
			sawTLS = true
			if f.Severity == "" {
				t.Errorf("a TLS finding must carry a real severity: %+v", f)
			}
			if f.Class != "" {
				t.Errorf("a TLS finding must not carry a host Class: %+v", f)
			}
		case "host":
			sawHost = true
			if f.Class != "quantum-vulnerable" {
				t.Errorf("a host finding must carry Class=quantum-vulnerable, never a fabricated severity: %+v", f)
			}
			if f.Severity != "" {
				t.Errorf("a host finding must never claim a TLS severity tier: %+v", f)
			}
		}
	}
	if !sawTLS {
		t.Error("fleet findings should include the TLS endpoint's findings")
	}
	if !sawHost {
		t.Errorf("fleet findings should include the host's quantum-vulnerable algorithms; got %d findings total: %+v", len(all), all)
	}

	// Filter by kind.
	var hostOnly []server.FlatFinding
	e.call("GET", "/api/v1/findings?kind=host", nil, &hostOnly)
	for _, f := range hostOnly {
		if f.AssetKind != "host" {
			t.Errorf("kind=host filter leaked a %s finding", f.AssetKind)
		}
	}

	// Filter by status: nothing is triaged yet, so status=new must return everything, status=accepted-risk nothing.
	var newOnly []server.FlatFinding
	e.call("GET", "/api/v1/findings?status=new", nil, &newOnly)
	if len(newOnly) != len(all) {
		t.Errorf("status=new should match everything before any triage: %d vs %d", len(newOnly), len(all))
	}
	var acceptedOnly []server.FlatFinding
	e.call("GET", "/api/v1/findings?status=accepted-risk", nil, &acceptedOnly)
	if len(acceptedOnly) != 0 {
		t.Errorf("status=accepted-risk should match nothing before any triage: %d", len(acceptedOnly))
	}
}

func TestLinkAssetsAPI(t *testing.T) {
	e := newEnv(t)
	tlsAsset := e.addAsset(tls12Server(t).Addr)
	cbom := golden(t, "ubuntu-24.04.cbom.json")
	var ingested struct {
		Asset assetJSON `json:"asset"`
	}
	e.call("POST", "/api/v1/hosts/ingest", cbom, &ingested)

	fetchLinked := func() []int64 {
		t.Helper()
		var a assetJSON
		e.call("GET", "/api/v1/assets/"+itoa(tlsAsset.ID), nil, &a)
		return a.LinkedAssetIDs
	}

	if got := fetchLinked(); len(got) != 0 {
		t.Fatalf("should start unlinked: %v", got)
	}

	if s := e.call("PUT", "/api/v1/assets/"+itoa(tlsAsset.ID)+"/links/"+itoa(ingested.Asset.ID), nil, nil); s != http.StatusNoContent {
		t.Fatalf("link: %d", s)
	}
	if got := fetchLinked(); len(got) != 1 || got[0] != ingested.Asset.ID {
		t.Errorf("linked ids = %v", got)
	}

	// The list endpoint must also show the link (batch path).
	var list []assetJSON
	e.call("GET", "/api/v1/assets?kind=tls-endpoint", nil, &list)
	found := false
	for _, la := range list {
		if la.ID == tlsAsset.ID {
			found = true
			if len(la.LinkedAssetIDs) != 1 || la.LinkedAssetIDs[0] != ingested.Asset.ID {
				t.Errorf("list view linked ids = %v", la.LinkedAssetIDs)
			}
		}
	}
	if !found {
		t.Fatal("asset missing from list")
	}

	if s := e.call("DELETE", "/api/v1/assets/"+itoa(tlsAsset.ID)+"/links/"+itoa(ingested.Asset.ID), nil, nil); s != http.StatusNoContent {
		t.Fatalf("unlink: %d", s)
	}
	if got := fetchLinked(); len(got) != 0 {
		t.Errorf("should be unlinked: %v", got)
	}
}

func TestHostSnapshotCBOMDownload(t *testing.T) {
	e := newEnv(t)
	cbom := golden(t, "ubuntu-24.04.cbom.json")
	var ingested struct {
		Asset      assetJSON `json:"asset"`
		SnapshotID int64     `json:"snapshotId"`
	}
	if s := e.call("POST", "/api/v1/hosts/ingest", cbom, &ingested); s != http.StatusCreated {
		t.Fatalf("ingest: %d", s)
	}
	path := "/api/v1/hosts/" + itoa(ingested.Asset.ID) + "/snapshots/" + itoa(ingested.SnapshotID) + "/cbom?download=1"
	s, b, h := e.req("GET", path, nil, nil)
	if s != 200 {
		t.Fatalf("download: %d", s)
	}
	if got := h.Get("Content-Disposition"); got == "" {
		t.Error("expected an attachment Content-Disposition header")
	}
	var raw map[string]any
	mustJSON(t, b, &raw)
	if raw["bomFormat"] != "CycloneDX" {
		t.Errorf("downloaded content is not the raw CBOM: %s", b)
	}

	if s, _ := e.do("GET", "/api/v1/hosts/"+itoa(ingested.Asset.ID)+"/snapshots/999999/cbom", nil); s != http.StatusNotFound {
		t.Errorf("unknown snapshot should 404, got %d", s)
	}
}
