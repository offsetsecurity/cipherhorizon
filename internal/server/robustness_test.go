package server_test

import (
	"strings"
	"testing"
)

type panickingReader struct{}

func (panickingReader) Read([]byte) (int, error) { panic("prober bug") }

// A bug in the prober fails the scan it hit and leaves the server, and its workers, running.
func TestAProberPanicFailsOneScanAndTheServerCarriesOn(t *testing.T) {
	e := newEnv(t, withScanRand(panickingReader{}), withWorkers(1))
	srv := classicalServer(t)
	for i, target := range []string{srv.Addr, "localhost:" + itoa(int64(srv.Port))} {
		a := e.addAsset(target)
		sc := e.scanAndWait(a.ID)
		if sc.Status != "failed" || !strings.Contains(sc.Error, "internal error") {
			t.Fatalf("scan %d: status %q error %q, want failed with an internal error", i, sc.Status, sc.Error)
		}
		if strings.Contains(sc.Error, "prober bug") {
			t.Fatalf("the panic value reached the user: %q", sc.Error)
		}
	}
	if s, _, _ := e.req("GET", "/api/v1/health", nil, nil); s != 200 {
		t.Fatalf("health after two panicking scans: %d", s)
	}
}

// A host upload gets the same structural limits as an import, before anything is decoded.
func TestHostIngestAppliesTheImportLimits(t *testing.T) {
	e := newEnv(t)
	deep := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"h","type":"device"}},"x":` +
		strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`
	if s, b, _ := e.req("POST", "/api/v1/hosts/ingest", deep, nil); s != 413 || !strings.Contains(string(b), "nested") {
		t.Fatalf("a deeply nested upload: %d %s, want 413", s, b)
	}
}
