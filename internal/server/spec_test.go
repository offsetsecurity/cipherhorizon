package server_test

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/cdxschema"
)

// REQ-EXP-1: the scan CBOM is CycloneDX 1.7 unless 1.6 is asked for, each validates against its own
// schema, an unknown version is refused, and hostile text in the parameter is not echoed.
func TestScanCBOMDefaultsToOneDotSevenAndOffersOneDotSix(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset(hybridServer(t).Addr)
	id := itoa(e.wait(e.startScan(a.ID).ID).ID)
	base := "/api/v1/scans/" + id + "/cbom"

	s, def, _ := e.req("GET", base, nil, nil)
	if s != 200 || !strings.Contains(string(def), `"specVersion": "1.7"`) || strings.Contains(string(def), "subjectPublicKeyRef") {
		t.Fatalf("default: %d %.200s", s, def)
	}
	if p, err := cdxschema.Validate(def, "1.7", 5); err != nil || len(p) != 0 {
		t.Errorf("default is not valid 1.7: %v %v", p, err)
	}
	s, old, _ := e.req("GET", base+"?spec=1.6", nil, nil)
	if s != 200 || !strings.Contains(string(old), `"specVersion": "1.6"`) {
		t.Fatalf("1.6: %d %.200s", s, old)
	}
	if p, err := cdxschema.Validate(old, "1.6", 5); err != nil || len(p) != 0 {
		t.Errorf("1.6 output is not valid 1.6: %v %v", p, err)
	}
	if s, _, _ := e.req("GET", base+"?spec=1.5", nil, nil); s != 400 {
		t.Errorf("spec=1.5: %d", s)
	}
	if s, b, _ := e.req("GET", base+"?spec=%1b%00x", nil, nil); s != 400 || strings.ContainsAny(string(b), "\x1b\x00") {
		t.Errorf("hostile spec: %d %q", s, b)
	}
}
