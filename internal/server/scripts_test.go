package server_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// TestInventoryScriptsAndFactsUpload: the server hands out the scripts as plain text with their
// SHA-256, and a facts file the scripts write uploads like a collector CBOM.
func TestInventoryScriptsAndFactsUpload(t *testing.T) {
	e := newEnv(t)
	var list struct {
		Scripts []struct {
			Name, SHA256, Run string
		} `json:"scripts"`
	}
	if s := e.call("GET", "/api/v1/collector/scripts", nil, &list); s != 200 || len(list.Scripts) != 2 {
		t.Fatalf("scripts: %d %+v", s, list)
	}
	for _, sc := range list.Scripts {
		status, body, hdr := e.req("GET", "/api/v1/collector/scripts/"+sc.Name+"?download=1", nil, nil)
		sum := sha256.Sum256(body)
		if status != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/plain") || hex.EncodeToString(sum[:]) != sc.SHA256 ||
			hdr.Get("X-Content-SHA256") != sc.SHA256 || !strings.Contains(hdr.Get("Content-Disposition"), sc.Name) {
			t.Errorf("%s: %d %q", sc.Name, status, hdr.Get("Content-Type"))
		}
	}
	var db struct {
		Version    string `json:"version"`
		Signatures []struct {
			ID, Platform, Capability, How string
		} `json:"signatures"`
	}
	if s := e.call("GET", "/api/v1/collector/signatures", nil, &db); s != 200 || db.Version == "" || len(db.Signatures) < 10 || db.Signatures[0].How == "" {
		t.Errorf("signature database: %d %+v", s, db)
	}
	for _, sc := range list.Scripts {
		_, body, _ := e.req("GET", "/api/v1/collector/scripts/"+sc.Name, nil, nil)
		for _, sig := range db.Signatures {
			want := (sig.Platform == "windows") == strings.HasSuffix(sc.Name, ".ps1")
			if strings.Contains(string(body), "sig	"+sig.ID+"	") != want {
				t.Errorf("%s and signature %s: served %v", sc.Name, sig.ID, !want)
			}
		}
	}
	if s, _ := e.do("GET", "/api/v1/collector/scripts/..%2Fserver.go", nil); s != 404 {
		t.Errorf("only listed scripts are served: %d", s)
	}

	facts := "cipherhorizon-machine-facts\t1\nscript\tlinux-sh\t1.0.0\nhost\tname\tweb-07\nhost\tos\tlinux\nhost\tprivilege\tuser\n" +
		"package-manager\tdpkg\npackage\tdpkg\topenssl\t3.0.13-1\tamd64\n"
	status, body, _ := e.req("POST", "/api/v1/hosts/ingest", facts, map[string]string{"Content-Type": "text/plain; charset=utf-8"})
	var ing struct {
		SourceClass string `json:"sourceClass"`
		Summary     struct {
			Name       string `json:"name"`
			Packages   int    `json:"packages"`
			Vulnerable int    `json:"vulnerable"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(body, &ing); status != 201 || err != nil || ing.SourceClass != "collector" || ing.Summary.Name != "web-07" || ing.Summary.Vulnerable == 0 {
		t.Fatalf("facts upload: %d %s", status, body)
	}
	if s, _, _ := e.req("POST", "/api/v1/hosts/ingest", "cipherhorizon-machine-facts\t1\nhost\tname\tx\n", map[string]string{"Content-Type": "text/plain"}); s != 400 {
		t.Errorf("a facts file naming no OS is refused: %d", s)
	}
	if s, _, _ := e.req("POST", "/api/v1/assets", `{"target":"example.com"}`, map[string]string{"Content-Type": "text/plain"}); s != 415 {
		t.Errorf("text/plain is accepted only by the inventory upload: %d", s)
	}
}
