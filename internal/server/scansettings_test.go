package server_test

import (
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

type scanningJSON struct {
	Scanning struct {
		HTTPChecks bool     `json:"httpChecks"`
		CRL        bool     `json:"crlLookups"`
		CRLPrivate bool     `json:"crlPrivate"`
		Overridden []string `json:"overridden"`
		Defaults   struct {
			HTTPChecks bool `json:"httpChecks"`
			CRL        bool `json:"crlLookups"`
		} `json:"defaults"`
	} `json:"scanning"`
}

// 0.5.1: the scan options are set in Settings and apply to the next scan; the command line only
// sets the starting values, and "default" hands back to it.
func TestScanOptionsAreSetInSettings(t *testing.T) {
	e := newEnv(t)
	var set scanningJSON
	if s := e.call("GET", "/api/v1/settings", nil, &set); s != 200 {
		t.Fatalf("settings: %d", s)
	}
	if set.Scanning.CRL || len(set.Scanning.Overridden) != 0 {
		t.Fatalf("a fresh server runs with the command line's values: %+v", set.Scanning)
	}
	if s, body := e.do("PUT", "/api/v1/settings/scanning", map[string]any{"crlLookups": "sometimes"}); s != 400 {
		t.Fatalf("a bad value: %d %s", s, body)
	}
	if s, body := e.do("PUT", "/api/v1/settings/scanning", map[string]any{"httpChecks": "off", "crlLookups": "on", "crlPrivate": "on"}); s != 200 {
		t.Fatalf("set: %d %s", s, body)
	}
	e.call("GET", "/api/v1/settings", nil, &set)
	sc := set.Scanning
	if sc.HTTPChecks || !sc.CRL || !sc.CRLPrivate || len(sc.Overridden) != 3 {
		t.Fatalf("after setting: %+v", sc)
	}
	// The runner reads the effective values (what About and the next scan use).
	if e.runner.HTTPChecks() || !e.runner.CRLLookups() {
		t.Fatalf("runner: http %v crl %v", e.runner.HTTPChecks(), e.runner.CRLLookups())
	}
	if v, _ := e.st.Setting(store.SettingCRL); v != "on" {
		t.Fatalf("stored as %q", v)
	}
	// "default" clears the override: the command line decides again.
	if s, body := e.do("PUT", "/api/v1/settings/scanning", map[string]any{"httpChecks": "default", "crlLookups": "default", "crlPrivate": "default"}); s != 200 {
		t.Fatalf("reset: %d %s", s, body)
	}
	e.call("GET", "/api/v1/settings", nil, &set)
	sc = set.Scanning
	if sc.HTTPChecks != sc.Defaults.HTTPChecks || sc.CRL != sc.Defaults.CRL || len(sc.Overridden) != 0 {
		t.Fatalf("after reset: %+v", sc)
	}
	if e.runner.HTTPChecks() != sc.Defaults.HTTPChecks || e.runner.CRLLookups() != sc.Defaults.CRL {
		t.Fatalf("runner after reset: http %v crl %v", e.runner.HTTPChecks(), e.runner.CRLLookups())
	}
}
