package server_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

func interop(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type importJSON struct {
	Import struct {
		ID             int64          `json:"id"`
		SHA256         string         `json:"sha256"`
		Profile        string         `json:"profile"`
		Kind           string         `json:"kind"`
		ToolName       string         `json:"toolName"`
		SubjectClaim   string         `json:"subjectClaim"`
		SubmittedBy    string         `json:"submittedBy"`
		SystemID       int64          `json:"systemId"`
		SystemName     string         `json:"systemName"`
		Status         string         `json:"status"`
		Observations   int            `json:"observations"`
		NotInterpreted map[string]int `json:"notInterpreted"`
	} `json:"import"`
	ProfileLabel string `json:"profileLabel"`
	Duplicate    bool   `json:"duplicate"`
}

func upload(e *env, doc, query string) (int, importJSON, []byte) {
	e.t.Helper()
	status, raw, _ := e.req("POST", "/api/v1/imports?"+query, doc, nil)
	var out importJSON
	_ = json.Unmarshal(raw, &out) // a refusal is not an import record; the caller reads the raw reply
	return status, out, raw
}

func stats(e *env) (entities, bySource map[string]int) {
	e.t.Helper()
	var st struct {
		Entities     map[string]int `json:"entities"`
		Observations map[string]int `json:"observationsBySourceClass"`
	}
	e.call("GET", "/api/v1/graph/stats", nil, &st)
	return st.Entities, st.Observations
}

// AC-ING-1: real-shaped documents import; provenance is recorded; counts are what the projection made.
func TestThirdPartyDocumentsImportWithProvenance(t *testing.T) {
	e := newEnv(t)
	doc := interop(t, "cbomlens-like-1.7.json")
	status, rec, raw := upload(e, doc, "newSystem=edge-proxy")
	if status != 201 {
		t.Fatalf("upload: %d %s", status, raw)
	}
	sum := sha256.Sum256([]byte(doc))
	i := rec.Import
	if i.Profile != "cbom-lens" || i.Kind != "host" || i.SHA256 != hex.EncodeToString(sum[:]) || i.ToolName != "CBOM-Lens" ||
		i.SystemName != "edge-proxy" || i.Status != "active" || i.SubmittedBy != "local" || rec.ProfileLabel == "" {
		t.Errorf("record = %+v", rec)
	}
	if i.Observations == 0 || i.NotInterpreted["certificate without a SHA-256 hash"] != 1 || i.NotInterpreted["related crypto material: password (not modelled)"] != 1 {
		t.Errorf("observations %d, not interpreted %v", i.Observations, i.NotInterpreted)
	}
	ents, by := stats(e)
	if ents["certificate"] != 1 || ents["protocol"] != 1 || ents["suite"] != 1 || by["imported"] != i.Observations || by["collector"] != 0 || by["scanner"] != 0 {
		t.Errorf("graph: entities %v, observations by class %v", ents, by)
	}
	// The certificate is visible with its key size, and its places say it was imported.
	var list certListJSON
	e.call("GET", "/api/v1/certificates", nil, &list)
	if len(list.Certificates) != 1 || list.Certificates[0].KeyBits == nil || *list.Certificates[0].KeyBits != 2048 {
		t.Fatalf("certificates = %+v", list.Certificates)
	}
	var detail struct {
		Places []struct {
			SourceClass string `json:"sourceClass"`
			Stream      string `json:"stream"`
			Rung        string `json:"rung"`
		} `json:"places"`
	}
	e.call("GET", "/api/v1/certificates/"+list.Certificates[0].Fingerprint, nil, &detail)
	if len(detail.Places) != 2 {
		t.Fatalf("%d places, want one per occurrence", len(detail.Places))
	}
	for _, p := range detail.Places {
		if p.SourceClass != "imported" || p.Stream != "imported" || p.Rung != "provisioned" {
			t.Errorf("place = %+v", p)
		}
	}
	var all []struct {
		ID int64 `json:"id"`
	}
	e.call("GET", "/api/v1/imports", nil, &all)
	if len(all) != 1 || all[0].ID != i.ID {
		t.Errorf("imports = %+v", all)
	}
	if s, _ := e.do("GET", "/api/v1/imports/"+itoa(i.ID), nil); s != 200 {
		t.Errorf("get import: %d", s)
	}
}

// AC-ING-2, SR-04: the operator, not the document, decides where its data lands.
func TestTheSubjectIsChosenByTheOperatorNeverTheDocument(t *testing.T) {
	e := newEnv(t)
	e.addAsset("prod-db.example.test:443") // a system whose name the document will try to claim
	prod := e.systems()[0].ID

	doc := strings.Replace(interop(t, "theia-like-1.6.json"), `"name": "my application"`, `"name": "prod-db.example.test:443"`, 1)
	status, rec, raw := upload(e, doc, "newSystem=somewhere-else")
	if status != 201 {
		t.Fatalf("upload: %d %s", status, raw)
	}
	if rec.Import.SubjectClaim != "prod-db.example.test:443" {
		t.Errorf("the claim was not recorded: %q", rec.Import.SubjectClaim)
	}
	if rec.Import.SystemID == prod {
		t.Fatal("the document's claim placed its data on an existing system")
	}
	var obs []struct{}
	e.call("GET", "/api/v1/systems/"+itoa(prod)+"/observations", nil, &obs)
	if len(obs) != 0 {
		t.Errorf("the claimed system received %d observations", len(obs))
	}
	e.call("GET", "/api/v1/systems/"+itoa(rec.Import.SystemID)+"/observations", nil, &obs)
	if len(obs) == 0 {
		t.Error("the system the operator named received nothing")
	}
	// A document with no subject at all works the same way, and an existing system can be named.
	status, rec2, _ := upload(e, interop(t, "cbomkit-like-1.6.json"), "system="+itoa(prod))
	if status != 201 || rec2.Import.SystemID != prod || rec2.Import.SubjectClaim != "" {
		t.Errorf("no-subject document: %d %+v", status, rec2.Import)
	}
	for name, q := range map[string]string{"neither": "", "both": "system=1&newSystem=x", "bad id": "system=abc", "zero": "system=0"} {
		if s, _, _ := upload(e, interop(t, "unknown-producer-1.6.json"), q); s != 400 {
			t.Errorf("%s: %d, want 400", name, s)
		}
	}
	if s, _, _ := upload(e, interop(t, "unknown-producer-1.6.json"), "system=999999"); s != 404 {
		t.Errorf("a system that does not exist: %d, want 404", s)
	}
}

// REQ-ING-4/9: importing the same bytes again is idempotent; another system is refused; withdrawal
// removes the observations and keeps the record; the same bytes can be imported again afterwards.
func TestReimportingWithdrawingAndReactivating(t *testing.T) {
	e := newEnv(t)
	doc := interop(t, "cbomlens-like-1.7.json")
	_, first, _ := upload(e, doc, "newSystem=one")
	sys := first.Import.SystemID
	entsBefore, _ := stats(e)

	status, again, _ := upload(e, doc, "system="+itoa(sys))
	if status != 200 || !again.Duplicate || again.Import.ID != first.Import.ID {
		t.Errorf("re-import: %d %+v", status, again)
	}
	if ents, _ := stats(e); ents["certificate"] != entsBefore["certificate"] {
		t.Error("a duplicate import changed the graph")
	}
	e.addAsset("other.example.test:443")
	systems := e.systems()
	other := systems[len(systems)-1].ID
	for _, s := range systems {
		if s.Name == "other.example.test:443" {
			other = s.ID
		}
	}
	if s, _, _ := upload(e, doc, "system="+itoa(other)); s != 409 {
		t.Errorf("the same document for another system: %d, want 409", s)
	}

	var w struct {
		Status       string `json:"status"`
		Observations int    `json:"observations"`
	}
	if s := e.call("POST", "/api/v1/imports/"+itoa(first.Import.ID)+"/withdraw?reason=wrong+host", nil, &w); s != 200 || w.Status != "withdrawn" || w.Observations != 0 {
		t.Fatalf("withdraw: %d %+v", s, w)
	}
	if ents, by := stats(e); ents["certificate"] != 0 || by["imported"] != 0 {
		t.Errorf("after withdrawal: entities %v, by class %v", ents, by)
	}
	var log []struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	e.call("GET", "/api/v1/systems/"+itoa(sys)+"/audit", nil, &log)
	actions := map[string]string{}
	for _, l := range log {
		actions[l.Action] = l.Reason
	}
	if _, ok := actions["import"]; !ok || actions["withdraw-import"] != "wrong host" {
		t.Errorf("audit = %+v", log)
	}
	if s, _ := e.do("POST", "/api/v1/imports/999999/withdraw", nil); s != 404 {
		t.Errorf("withdrawing an unknown import: %d", s)
	}
	status, back, _ := upload(e, doc, "system="+itoa(other))
	if status != 201 || back.Import.Status != "active" || back.Import.SystemID != other || back.Import.Observations == 0 {
		t.Errorf("re-import after withdrawal: %d %+v", status, back.Import)
	}
}

// REQ-ING-8, SR-18, T-05: an imported document can add to the graph but not replace what a scan
// observed; where it disagrees the disagreement is recorded, and its claimed key size does not
// become the certificate's.
func TestAnImportCannotOverwriteWhatAScanObserved(t *testing.T) {
	e := newEnv(t)
	ec, _ := testserver.Certificates(t)
	sum := sha256.Sum256(ec.Certificate[0])
	fp := hex.EncodeToString(sum[:])

	srv := hybridServer(t)
	a := e.addAsset(srv.Addr)
	e.wait(e.startScan(a.ID).ID)

	// A forged document: the real certificate's fingerprint, a lie about its key.
	doc := strings.ReplaceAll(interop(t, "cbomlens-like-1.7.json"), strings.Repeat("ab", 32), fp)
	doc = strings.Replace(doc, `"size": 2048`, `"size": 512`, 1)
	doc = strings.Replace(doc, `"CN=leaf.example.test"`, `"CN=forged subject"`, 1)
	status, rec, raw := upload(e, doc, "newSystem=forger")
	if status != 201 {
		t.Fatalf("%d %s", status, raw)
	}

	var list certListJSON
	e.call("GET", "/api/v1/certificates", nil, &list)
	found := false
	for _, c := range list.Certificates {
		if c.Fingerprint != fp {
			continue
		}
		found = true
		if c.KeyBits == nil || *c.KeyBits != 256 || strings.Contains(c.Subject, "forged") {
			t.Errorf("the forged claim replaced the scan's facts: subject %q keyBits %v", c.Subject, c.KeyBits)
		}
		for _, f := range c.Findings {
			if f.ID == "CERT.WEAK-KEY" {
				t.Error("the forged 512-bit claim produced a weak-key finding on a 256-bit ECDSA certificate")
			}
		}
	}
	if !found {
		t.Fatalf("the certificate is missing: %+v", list.Certificates)
	}
	// The disagreement is on the record, on the import, in words.
	recorded := false
	for k := range rec.Import.NotInterpreted {
		recorded = recorded || strings.Contains(k, "conflict with first-party evidence") && strings.Contains(k, "keyBits")
	}
	if !recorded {
		t.Errorf("the conflict was not recorded: %v", rec.Import.NotInterpreted)
	}
	// Both sightings are shown side by side, each with its source.
	var detail struct {
		Places []struct {
			SourceClass string `json:"sourceClass"`
		} `json:"places"`
	}
	e.call("GET", "/api/v1/certificates/"+fp, nil, &detail)
	classes := map[string]int{}
	for _, p := range detail.Places {
		classes[p.SourceClass]++
	}
	if classes["scanner"] == 0 || classes["imported"] == 0 {
		t.Errorf("places by class = %v", classes)
	}
}

// AC-ING-4, SR-03: a document that says it is the collector's, uploaded through the import flow,
// is imported all the same.
func TestAForgedCollectorDocumentIsStillImported(t *testing.T) {
	e := newEnv(t)
	doc := strings.Replace(interop(t, "cbomkit-like-1.6.json"), `"sonar-cryptography"`, `"cipherhorizon-collector"`, 1)
	status, rec, _ := upload(e, doc, "newSystem=x")
	if status != 201 {
		t.Fatalf("%d", status)
	}
	if rec.Import.Profile != "cipherhorizon" {
		t.Errorf("profile = %s", rec.Import.Profile) // the label reflects the claim, for the person
	}
	if _, by := stats(e); by["collector"] != 0 || by["imported"] == 0 {
		t.Errorf("observations by class = %v: an uploaded document must never be first-party", by)
	}
}

// AC-ING-3: hostile documents are refused with a specific reason, and nothing is stored.
func TestHostileDocumentsAreRefusedAndStoreNothing(t *testing.T) {
	e := newEnv(t)
	deep := strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200)
	for name, c := range map[string]struct {
		doc    string
		status int
		text   string
	}{
		"not JSON":         {`nope`, 400, "not valid JSON"},
		"depth bomb":       {deep, 413, "nested"},
		"an older spec":    {`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`, 400, "no cryptographic assets"},
		"schema violation": {`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"widget"}}]}`, 400, "not valid CycloneDX"},
		"SPDX":             {`{"spdxVersion":"SPDX-2.3"}`, 400, "not a CycloneDX"},
	} {
		status, _, raw := upload(e, c.doc, "newSystem=x")
		if status != c.status || !strings.Contains(string(raw), c.text) {
			t.Errorf("%s: %d %s (want %d containing %q)", name, status, raw, c.status, c.text)
		}
	}
	var all []struct{}
	e.call("GET", "/api/v1/imports", nil, &all)
	if len(all) != 0 || len(e.systems()) != 0 {
		t.Errorf("a refused document left something behind: %d imports, %d systems", len(all), len(e.systems()))
	}
	big := strings.Repeat(" ", 33<<20)
	if s, _, _ := e.req("POST", "/api/v1/imports?newSystem=x", big, nil); s != http.StatusRequestEntityTooLarge {
		t.Errorf("a 33 MiB document: %d, want 413", s)
	}
}

// SR-02: hostile text in an imported document is stored and returned as data.
func TestHostileTextInAnImportIsInert(t *testing.T) {
	e := newEnv(t)
	doc := strings.Replace(interop(t, "cbomlens-like-1.7.json"), `"CN=Test CA"`, `"<img src=x onerror=alert(1)>"`, 1)
	if s, _, raw := upload(e, doc, "newSystem=%3Cscript%3Ealert(1)%3C/script%3E"); s != 201 {
		t.Fatalf("%d %s", s, raw)
	}
	for _, path := range []string{"/api/v1/certificates", "/api/v1/imports", "/api/v1/systems", "/api/v1/entities"} {
		_, body, hdr := e.req("GET", path, nil, nil)
		if strings.Contains(string(body), "<img") || strings.Contains(string(body), "<script") {
			t.Errorf("%s returned unescaped markup", path)
		}
		if !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") {
			t.Errorf("%s content type %q", path, hdr.Get("Content-Type"))
		}
	}
}

func TestImportRoutesAreGuardedLikeTheRest(t *testing.T) {
	e := newEnv(t, withToken("s3cret-token-0123456789"))
	doc := interop(t, "unknown-producer-1.6.json")
	e.token = ""
	if s, _, _ := e.req("POST", "/api/v1/imports?newSystem=x", doc, nil); s != 401 {
		t.Errorf("without a token: %d", s)
	}
	e.token = "s3cret-token-0123456789"
	if s, _, _ := e.req("POST", "/api/v1/imports?newSystem=x", doc, map[string]string{"X-Requested-With": ""}); s != 403 {
		t.Errorf("without the anti-forgery header: %d", s)
	}
	if s, _, _ := e.req("POST", "/api/v1/imports?newSystem=x", doc, nil); s != 201 {
		t.Errorf("a proper request: %d", s)
	}
	var recs []struct {
		SubmittedBy string `json:"submittedBy"`
	}
	e.call("GET", "/api/v1/imports", nil, &recs)
	if len(recs) != 1 || recs[0].SubmittedBy != "api-token" {
		t.Errorf("provenance = %+v", recs)
	}
}
