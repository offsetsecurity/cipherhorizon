package server_test

import (
	"strings"
	"testing"
)

type estateJSON struct {
	Version string `json:"version"`
	Ranking []struct {
		Rank         int      `json:"rank"`
		SystemID     int64    `json:"systemId"`
		Name         string   `json:"name"`
		Tier         string   `json:"tier"`
		Missing      []string `json:"missing"`
		EvidenceOnly bool     `json:"evidenceOnly"`
		Basis        string   `json:"basis"`
		Evidence     string   `json:"evidence"`
		Reasons      []struct {
			Rule      string `json:"rule"`
			Text      string `json:"text"`
			Citations []struct {
				Title string `json:"title"`
				URL   string `json:"url"`
			} `json:"citations"`
		} `json:"reasons"`
	} `json:"ranking"`
	Rules []struct {
		ID string `json:"id"`
	} `json:"rules"`
}

func ranking(e *env) estateJSON {
	e.t.Helper()
	var out estateJSON
	if s := e.call("GET", "/api/v1/estate", nil, &out); s != 200 {
		e.t.Fatalf("estate: %d", s)
	}
	return out
}

// AC-PRI-1 / AC-PRI-2 end to end: real scans, real metadata, the ranking follows the published rules,
// every row says why, and it says when it rests on evidence alone. Changing an input changes the order.
func TestTheEstateIsRankedByTheRulesAndEveryRowSaysWhy(t *testing.T) {
	e := newEnv(t)
	exposedA := e.addAsset(classicalServer(t).Addr) // TLS 1.3 without a post-quantum group: recorded traffic is exposed
	exposedB := e.addAsset(classicalServer(t).Addr)
	safe := e.addAsset(hybridServer(t).Addr) // a current client negotiates a hybrid group
	for _, a := range []assetJSON{exposedA, exposedB, safe} {
		e.wait(e.startScan(a.ID).ID)
	}
	sysOf := func(a assetJSON) int64 {
		var x struct {
			SystemID int64 `json:"systemId"`
		}
		e.call("GET", "/api/v1/assets/"+itoa(a.ID), nil, &x)
		return x.SystemID
	}

	r := ranking(e)
	if len(r.Ranking) != 3 || r.Version != "priority/1" || len(r.Rules) != 4 {
		t.Fatalf("ranking = %+v", r)
	}
	// Both exposed systems rank above the safe one; nothing was entered, and every row says so.
	if r.Ranking[2].SystemID != sysOf(safe) {
		t.Errorf("the system with a hybrid key exchange is not last: %+v", r.Ranking)
	}
	for _, row := range r.Ranking {
		if !row.EvidenceOnly || !strings.Contains(row.Basis, "evidence only") || len(row.Reasons) != 4 {
			t.Errorf("%s: %+v", row.Name, row)
		}
	}
	top := r.Ranking[0]
	if len(top.Reasons[0].Citations) == 0 || !strings.Contains(top.Reasons[0].Text, "not post-quantum") || !strings.Contains(strings.Join(top.Missing, ","), "data lifetime") {
		t.Errorf("the harvest reason: %+v (missing %v)", top.Reasons[0], top.Missing)
	}

	// A person says B's data must stay secret for 25 years: it moves to the top tier and the row says why.
	e.call("PATCH", "/api/v1/systems/"+itoa(sysOf(exposedB)), map[string]any{"dataLifetimeYears": 25, "exposure": "internet", "criticality": "high"}, nil)
	r = ranking(e)
	if r.Ranking[0].SystemID != sysOf(exposedB) || r.Ranking[0].EvidenceOnly || !strings.Contains(r.Ranking[0].Reasons[0].Text, "past 2030") {
		t.Errorf("after entering a data lifetime: %+v", r.Ranking[0])
	}
	if strings.Contains(r.Ranking[0].Reasons[0].Text, "not provided") {
		t.Errorf("the top row still says its lifetime is not provided: %q", r.Ranking[0].Reasons[0].Text)
	}
}

// A system known only from an imported document is ranked, after what was observed, and says so.
func TestAnImportedOnlySystemIsALeadNotAFinding(t *testing.T) {
	e := newEnv(t)
	e.wait(e.startScan(e.addAsset(classicalServer(t).Addr).ID).ID)
	if s, _, raw := upload(e, interop(t, "cbomlens-like-1.7.json"), "newSystem=only-imported"); s != 201 {
		t.Fatalf("%d %s", s, raw)
	}
	r := ranking(e)
	if len(r.Ranking) != 2 || r.Ranking[1].Name != "only-imported" {
		t.Fatalf("ranking = %+v", r.Ranking)
	}
	if r.Ranking[0].Evidence != "observed" || r.Ranking[1].Evidence != "imported" {
		t.Errorf("evidence kinds = %q, %q; want observed, imported", r.Ranking[0].Evidence, r.Ranking[1].Evidence)
	}
	if !strings.Contains(r.Ranking[1].Reasons[3].Text, "imported documents") || !strings.Contains(r.Ranking[1].Reasons[3].Text, "not verified") {
		t.Errorf("evidence reason = %q", r.Ranking[1].Reasons[3].Text)
	}
	// The imported certificate is an end-entity certificate of that system and is counted in its defects.
	if !strings.Contains(r.Ranking[1].Reasons[2].Text, "certificate finding") && !strings.Contains(r.Ranking[1].Reasons[2].Text, "no certificate") {
		t.Errorf("defect reason = %q", r.Ranking[1].Reasons[2].Text)
	}
}

func TestTheEstateRouteIsGuarded(t *testing.T) {
	e := newEnv(t, withToken("s3cret-token-0123456789"))
	e.token = ""
	if s, _, _ := e.req("GET", "/api/v1/estate", nil, nil); s != 401 {
		t.Errorf("without a token: %d", s)
	}
}
