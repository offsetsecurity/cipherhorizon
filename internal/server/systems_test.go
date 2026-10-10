package server_test

import (
	"net/http"
	"strings"
	"testing"
)

type systemJSON struct {
	ID                int64    `json:"id"`
	Name              string   `json:"name"`
	Owner             string   `json:"owner"`
	Environment       string   `json:"environment"`
	Criticality       string   `json:"criticality"`
	Exposure          string   `json:"exposure"`
	DataLifetimeYears *int     `json:"dataLifetimeYears"`
	Notes             string   `json:"notes"`
	Provided          []string `json:"provided"`
	Assets            []struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
	} `json:"assets"`
}

func (e *env) systems() []systemJSON {
	e.t.Helper()
	var out struct {
		Systems []systemJSON        `json:"systems"`
		Enums   map[string][]string `json:"enums"`
	}
	if s := e.call("GET", "/api/v1/systems", nil, &out); s != 200 {
		e.t.Fatalf("list systems: %d", s)
	}
	if len(out.Enums["environment"]) == 0 {
		e.t.Error("the enums are missing, so a client cannot build a form")
	}
	return out.Systems
}

// REQ-SYS-1/2: a system is created with each asset, its fields are optional, and it
// says which ones a person provided.
func TestSystemsAreListedAndEdited(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset("shop.example.test:443")
	systems := e.systems()
	if len(systems) != 1 || systems[0].Name != "shop.example.test:443" || len(systems[0].Provided) != 0 || len(systems[0].Assets) != 1 {
		t.Fatalf("systems = %+v", systems)
	}
	id := systems[0].ID

	var got systemJSON
	if s := e.call("PATCH", "/api/v1/systems/"+itoa(id)+"?reason=onboarding", map[string]any{
		"owner": "payments", "environment": "production", "criticality": "high", "exposure": "internet", "dataLifetimeYears": 25,
	}, &got); s != 200 {
		t.Fatalf("patch: %d", s)
	}
	if got.Owner != "payments" || got.DataLifetimeYears == nil || *got.DataLifetimeYears != 25 || len(got.Provided) != 5 {
		t.Errorf("patched = %+v", got)
	}

	// The audit trail names what changed, why, and by whom.
	var log []struct {
		Actor  string `json:"actor"`
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if s := e.call("GET", "/api/v1/systems/"+itoa(id)+"/audit", nil, &log); s != 200 || len(log) != 1 || log[0].Reason != "onboarding" || log[0].Action != "update" || log[0].Actor != "local" {
		t.Errorf("audit = %+v (status %d)", log, s)
	}

	// The asset carries its system id.
	var asset struct {
		SystemID int64 `json:"systemId"`
	}
	e.call("GET", "/api/v1/assets/"+itoa(a.ID), nil, &asset)
	if asset.SystemID != id {
		t.Errorf("asset systemId = %d, want %d", asset.SystemID, id)
	}
}

func TestSystemPatchRefusesBadInput(t *testing.T) {
	e := newEnv(t)
	e.addAsset("shop.example.test:443")
	id := e.systems()[0].ID
	path := "/api/v1/systems/" + itoa(id)
	for name, body := range map[string]any{
		"unknown field":   map[string]any{"password": "x"},
		"bad enum":        map[string]any{"environment": "prod"},
		"empty patch":     map[string]any{},
		"not an object":   []any{1},
		"lifetime string": map[string]any{"dataLifetimeYears": "ten"},
		"notes too long":  map[string]any{"notes": strings.Repeat("x", 4001)},
	} {
		if s, _ := e.do("PATCH", path, body); s != 400 {
			t.Errorf("%s: status %d, want 400", name, s)
		}
	}
	if s, _ := e.do("PATCH", "/api/v1/systems/999999", map[string]any{"owner": "x"}); s != 404 {
		t.Errorf("unknown system: %d, want 404", s)
	}
	if s, _ := e.do("PATCH", "/api/v1/systems/abc", map[string]any{"owner": "x"}); s != 400 {
		t.Errorf("bad id: %d, want 400", s)
	}
	if s, _ := e.do("PATCH", path+"?reason="+strings.Repeat("r", 201), map[string]any{"owner": "x"}); s != 400 {
		t.Errorf("long reason: %d, want 400", s)
	}
	if s, _ := e.do("PATCH", path+"?reason=a%0Ab", map[string]any{"owner": "x"}); s != 400 {
		t.Errorf("newline in reason: %d, want 400", s)
	}
}

// SR-12: the new mutating routes sit behind the same guards as every other.
func TestSystemRoutesAreGuarded(t *testing.T) {
	e := newEnv(t, withToken("s3cret"))
	e.token = ""
	for _, r := range []struct{ method, path string }{
		{"GET", "/api/v1/systems"}, {"GET", "/api/v1/systems/1"}, {"PATCH", "/api/v1/systems/1"},
		{"GET", "/api/v1/systems/1/audit"}, {"GET", "/api/v1/systems/1/observations"}, {"GET", "/api/v1/systems/export.csv"},
		{"POST", "/api/v1/systems/import.csv"}, {"GET", "/api/v1/entities"}, {"GET", "/api/v1/graph/stats"},
	} {
		if s, _, _ := e.req(r.method, r.path, map[string]any{"owner": "x"}, nil); s != 401 {
			t.Errorf("%s %s without a token: %d, want 401", r.method, r.path, s)
		}
	}
	e.token = "s3cret"
	// With the token but without the anti-forgery header or from another origin.
	if s, _, _ := e.req("PATCH", "/api/v1/systems/1", map[string]any{"owner": "x"}, map[string]string{"X-Requested-With": ""}); s != 403 {
		t.Errorf("PATCH without X-Requested-With: %d, want 403", s)
	}
	if s, _, _ := e.req("PATCH", "/api/v1/systems/1", map[string]any{"owner": "x"}, map[string]string{"Origin": "https://evil.example"}); s != 403 {
		t.Errorf("PATCH from a foreign origin: %d, want 403", s)
	}
	if s, _, _ := e.req("POST", "/api/v1/systems/import.csv", "id,owner\n1,x\n", map[string]string{"X-Requested-With": "", "Content-Type": "text/csv"}); s != 403 {
		t.Errorf("CSV import without X-Requested-With: %d, want 403", s)
	}
	// text/csv is accepted only on the import route.
	if s, _, _ := e.req("PATCH", "/api/v1/systems/1", "owner=x", map[string]string{"Content-Type": "text/csv"}); s != 415 {
		t.Errorf("PATCH with text/csv: %d, want 415", s)
	}
	// The audit actor is the token, not a person.
	e.addAsset("shop.example.test:443")
	id := e.systems()[0].ID
	e.call("PATCH", "/api/v1/systems/"+itoa(id), map[string]any{"owner": "x"}, nil)
	var log []struct {
		Actor string `json:"actor"`
	}
	e.call("GET", "/api/v1/systems/"+itoa(id)+"/audit", nil, &log)
	if len(log) != 1 || log[0].Actor != "api-token" {
		t.Errorf("audit actor = %+v, want api-token", log)
	}
}

// REQ-SYS-2: the CSV round trip preserves every field, including values a spreadsheet
// would treat as a formula; bad rows are reported by line and nothing is applied.
func TestSystemsCSVRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.addAsset("a.example.test:443")
	e.addAsset("b.example.test:443")
	sys := e.systems()
	a, b := sys[0].ID, sys[1].ID
	e.call("PATCH", "/api/v1/systems/"+itoa(a), map[string]any{"owner": "=HYPERLINK(\"http://x\")", "notes": "line1\nline2, \"quoted\"", "dataLifetimeYears": 10}, nil)

	status, raw, hdr := e.req("GET", "/api/v1/systems/export.csv", nil, nil)
	if status != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") {
		t.Fatalf("export: %d %v", status, hdr)
	}
	csv := string(raw)
	if !strings.HasPrefix(csv, "id,name,owner,environment,criticality,exposure,dataLifetimeYears,fismaId,fips199,hvaId,hosting,hostingProvider,notes") {
		t.Errorf("header = %q", strings.SplitN(csv, "\n", 2)[0])
	}
	if !strings.Contains(csv, "'=HYPERLINK") {
		t.Error("a formula in a cell was exported live")
	}

	// Clear the fields, then import the exported file: everything comes back unchanged.
	e.call("PATCH", "/api/v1/systems/"+itoa(a), map[string]any{"owner": nil, "notes": nil, "dataLifetimeYears": nil}, nil)
	if s, body, _ := e.req("POST", "/api/v1/systems/import.csv", csv, map[string]string{"Content-Type": "text/csv"}); s != 200 {
		t.Fatalf("import: %d %s", s, body)
	}
	var got systemJSON
	e.call("GET", "/api/v1/systems/"+itoa(a), nil, &got)
	if got.Owner != `=HYPERLINK("http://x")` || got.Notes != "line1\nline2, \"quoted\"" || got.DataLifetimeYears == nil || *got.DataLifetimeYears != 10 {
		t.Errorf("after the round trip: %+v", got)
	}

	// Bad rows: every problem is named with its line, and nothing is applied.
	bad := "id,owner,environment,dataLifetimeYears\n" + itoa(a) + ",changed,production,5\n" + itoa(b) + ",x,nonsense,\n999999,y,,\nabc,z,,\n" + itoa(a) + ",dup,,\n"
	status, body, _ := e.req("POST", "/api/v1/systems/import.csv", bad, map[string]string{"Content-Type": "text/csv"})
	if status != 400 {
		t.Fatalf("bad import: %d %s", status, body)
	}
	for _, want := range []string{"line 3", "environment must be one of", "line 5", "not a system id", "appears twice"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the problem list lacks %q: %s", want, body)
		}
	}
	e.call("GET", "/api/v1/systems/"+itoa(a), nil, &got)
	if got.Owner == "changed" {
		t.Error("a rejected CSV was partly applied")
	}
	// A system that does not exist fails the whole import.
	if s, _, _ := e.req("POST", "/api/v1/systems/import.csv", "id,owner\n"+itoa(a)+",fine\n999999,x\n", map[string]string{"Content-Type": "text/csv"}); s != 400 {
		t.Errorf("unknown id: %d, want 400", s)
	}
	e.call("GET", "/api/v1/systems/"+itoa(a), nil, &got)
	if got.Owner == "fine" {
		t.Error("an import naming a missing system was partly applied")
	}
	for name, body := range map[string]string{
		"no id column":   "owner\nx\n",
		"unknown column": "id,secret\n1,x\n",
		"empty":          "",
		"duplicate col":  "id,owner,owner\n1,a,b\n",
	} {
		if s, _, _ := e.req("POST", "/api/v1/systems/import.csv", body, map[string]string{"Content-Type": "text/csv"}); s != 400 {
			t.Errorf("%s: %d, want 400", name, s)
		}
	}
	// An empty cell leaves the field alone.
	if s, _, _ := e.req("POST", "/api/v1/systems/import.csv", "id,owner,environment\n"+itoa(a)+",,staging\n", map[string]string{"Content-Type": "text/csv"}); s != 200 {
		t.Fatalf("partial import: %d", s)
	}
	e.call("GET", "/api/v1/systems/"+itoa(a), nil, &got)
	if got.Owner != `=HYPERLINK("http://x")` || got.Environment != "staging" {
		t.Errorf("an empty cell changed a field: %+v", got)
	}
}

// SR-13 / SR-02: hostile text in a system field is stored and returned as data.
func TestHostileSystemTextIsData(t *testing.T) {
	e := newEnv(t)
	e.addAsset("a.example.test:443")
	id := e.systems()[0].ID
	hostile := `<img src=x onerror=alert(1)>'); DROP TABLE systems;--`
	if s, _ := e.do("PATCH", "/api/v1/systems/"+itoa(id), map[string]any{"owner": hostile}); s != 200 {
		t.Fatalf("patch: %d", s)
	}
	_, raw, hdr := e.req("GET", "/api/v1/systems/"+itoa(id), nil, nil)
	if !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") || hdr.Get("X-Content-Type-Options") == "" {
		t.Errorf("headers = %v", hdr)
	}
	if strings.Contains(string(raw), "<img") {
		t.Errorf("markup was not escaped in the JSON response: %s", raw)
	}
	if len(e.systems()) != 1 {
		t.Error("the systems table did not survive")
	}
}

// REQ-MOD-6, SR-03: a document naming this product as its producer is attributed to the
// collector; any other producer is imported. The class is reported and drives the graph.
func TestHostUploadSourceClassFollowsTheProducer(t *testing.T) {
	e := newEnv(t)
	mk := func(tool string) string {
		return `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"device","name":"web-01"},` +
			`"tools":{"components":[{"type":"application","name":"` + tool + `","version":"1"}]}},"components":[` +
			`{"bom-ref":"lib","type":"library","name":"libfoo","version":"1.0"}]}`
	}
	var first, second struct {
		SourceClass string `json:"sourceClass"`
	}
	if s := e.call("POST", "/api/v1/hosts/ingest", mk("cipherhorizon-collector"), &first); s != 201 || first.SourceClass != "collector" {
		t.Errorf("first party: %d %+v", s, first)
	}
	if s := e.call("POST", "/api/v1/hosts/ingest?name=other-host", mk("cbomkit"), &second); s != 201 || second.SourceClass != "imported" {
		t.Errorf("third party: %d %+v", s, second)
	}
	var st struct {
		Entities     map[string]int `json:"entities"`
		Observations map[string]int `json:"observationsBySourceClass"`
		Stale        bool           `json:"stale"`
	}
	if s := e.call("GET", "/api/v1/graph/stats", nil, &st); s != 200 || st.Stale {
		t.Fatalf("stats: %d %+v", s, st)
	}
	if st.Observations["collector"] != 1 || st.Observations["imported"] != 1 || st.Entities["software"] != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// The graph is visible per system: a scan's certificate and a host's software.
func TestSystemObservationsShowSourceAndEvidence(t *testing.T) {
	e := newEnv(t)
	var ing struct {
		Asset struct {
			SystemID int64 `json:"systemId"`
		} `json:"asset"`
	}
	e.call("POST", "/api/v1/hosts/ingest", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"device","name":"web-01"}},"components":[{"bom-ref":"lib","type":"library","name":"libfoo","version":"1.0"}]}`, &ing)
	var obs []struct {
		SourceClass string `json:"sourceClass"`
		Stream      string `json:"stream"`
		Rung        string `json:"rung"`
		Quality     string `json:"methodQuality"`
		Entity      struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"entity"`
	}
	if s := e.call("GET", "/api/v1/systems/"+itoa(ing.Asset.SystemID)+"/observations?current=1", nil, &obs); s != 200 || len(obs) != 1 {
		t.Fatalf("observations: %d %+v", s, obs)
	}
	o := obs[0]
	if o.Entity.Kind != "software" || o.Entity.Name != "libfoo" || o.Stream != "host" || o.SourceClass != "imported" || o.Rung != "present" || o.Quality != "sampled" {
		t.Errorf("observation = %+v: a document with no evidence properties must read at the weakest reading", o)
	}
	if s, _ := e.do("GET", "/api/v1/systems/999999/observations", nil); s != 404 {
		t.Errorf("unknown system: %d", s)
	}
}

func TestHostIngestStillRefusesWhatItRefusedBefore(t *testing.T) {
	e := newEnv(t)
	if s, _ := e.do("POST", "/api/v1/hosts/ingest", `{"hello":"world"}`); s != http.StatusBadRequest {
		t.Errorf("not a BOM: %d", s)
	}
}
