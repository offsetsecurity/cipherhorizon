package server_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/example/cipherhorizon/internal/server"
)

type openAPIDoc struct {
	OpenAPI string `json:"openapi"`
	Paths   map[string]map[string]struct {
		Summary     string   `json:"summary"`
		OperationID string   `json:"operationId"`
		Tags        []string `json:"tags"`
		Parameters  []struct {
			Name string `json:"name"`
			In   string `json:"in"`
			Ref  string `json:"$ref"`
		} `json:"parameters"`
		Responses map[string]json.RawMessage `json:"responses"`
	} `json:"paths"`
}

func loadOpenAPI(t *testing.T, e *env) openAPIDoc {
	t.Helper()
	s, raw := e.do("GET", "/api/v1/openapi.json", nil)
	if s != 200 {
		t.Fatalf("openapi.json: %d", s)
	}
	var d openAPIDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("openapi.json is not JSON: %v", err)
	}
	return d
}

// REQ-EXP-5 / AC-EXP-5: the document describes exactly the registered routes. A route added without
// documentation, or documentation for a route that does not exist, fails here.
func TestOpenAPIDescribesExactlyTheRegisteredRoutes(t *testing.T) {
	e := newEnv(t)
	d := loadOpenAPI(t, e)
	if d.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q", d.OpenAPI)
	}
	documented := map[string]bool{}
	for p, ms := range d.Paths {
		for m := range ms {
			documented[strings.ToUpper(m)+" "+p] = true
		}
	}
	registered := map[string]bool{}
	for _, r := range e.srv.Routes() {
		registered[r] = true
	}
	var missing, extra []string
	for r := range registered {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	for r := range documented {
		if !registered[r] {
			extra = append(extra, r)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("routes with no OpenAPI entry: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("OpenAPI entries for routes that do not exist: %v", extra)
	}
}

// Every operation is described well enough to use: a summary, a unique operation id, its responses, and
// every {placeholder} in its path declared as a parameter.
func TestEveryOpenAPIOperationIsComplete(t *testing.T) {
	e := newEnv(t)
	d := loadOpenAPI(t, e)
	ids := map[string]string{}
	for p, ms := range d.Paths {
		for m, o := range ms {
			where := strings.ToUpper(m) + " " + p
			if strings.TrimSpace(o.Summary) == "" || o.OperationID == "" || len(o.Responses) == 0 || len(o.Tags) == 0 {
				t.Errorf("%s: incomplete (%+v)", where, o)
			}
			if prev, dup := ids[o.OperationID]; dup {
				t.Errorf("%s and %s share operationId %q", where, prev, o.OperationID)
			}
			ids[o.OperationID] = where
			declared := map[string]bool{}
			for _, pr := range o.Parameters {
				if pr.Ref == "#/components/parameters/id" {
					declared["id"] = true
				}
				if pr.In == "path" {
					declared[pr.Name] = true
				}
			}
			for _, seg := range strings.Split(p, "/") {
				if strings.HasPrefix(seg, "{") && !declared[strings.Trim(seg, "{}")] {
					t.Errorf("%s: path parameter %s is not declared", where, seg)
				}
			}
			if strings.ToUpper(m) != "GET" || server.PublicAPI(p) {
				continue
			}
			if _, ok := o.Responses["401"]; !ok {
				t.Errorf("%s: a token-guarded route must document 401", where)
			}
		}
	}
}

// The documented response codes are the ones the server returns: every GET route, called with a
// placeholder id, answers with a status its entry lists.
func TestEveryDocumentedGETStatusIsOneTheServerReturns(t *testing.T) {
	e := newEnv(t)
	d := loadOpenAPI(t, e)
	for p, ms := range d.Paths {
		o, ok := ms["get"]
		if !ok {
			continue
		}
		path := fill(p)
		if strings.Contains(p, "{fingerprint}") {
			path = strings.Replace(p, "{fingerprint}", strings.Repeat("ab", 32), 1)
			path = fill(path)
		}
		s, _, _ := e.req("GET", path, nil, nil)
		if _, ok := o.Responses[itoa(int64(s))]; !ok {
			t.Errorf("GET %s answered %d, which the OpenAPI entry does not list (%v)", p, s, keysOf(o.Responses))
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
