package server_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

type hook struct {
	mu     sync.Mutex
	got    []map[string]any
	sigs   []string
	bodies [][]byte
	status int
}

func newHook(t *testing.T) (*hook, *httptest.Server) {
	h := &hook{status: 200}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		h.got = append(h.got, m)
		h.sigs = append(h.sigs, r.Header.Get("X-CipherHorizon-Signature"))
		h.bodies = append(h.bodies, b)
		w.WriteHeader(h.status)
	}))
	t.Cleanup(ts.Close)
	return h, ts
}

func (h *hook) events() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, m := range h.got {
		out = append(out, m["event"].(string))
	}
	return out
}

type eventJSON struct {
	Key, Kind, Severity, Title, Detail, Link string
	WorkID                                   int64 `json:"workId"`
}

func events(t *testing.T, e *env) []eventJSON {
	t.Helper()
	var out []eventJSON
	if s := e.call("GET", "/api/v1/lifecycle/events", nil, &out); s != 200 {
		t.Fatalf("events: %d", s)
	}
	return out
}

func hasKind(evs []eventJSON, kind string) *eventJSON {
	for i := range evs {
		if evs[i].Kind == kind {
			return &evs[i]
		}
	}
	return nil
}

// REQ-LC-1..4: the monitor finds work that is overdue or due soon and certificates about to expire,
// sends each event once to the webhook with an HMAC signature, and retries a failed delivery a
// bounded number of times. The secret is read from the environment and never shown.
func TestTheMonitorSendsEachEventOnceSigned(t *testing.T) {
	t.Setenv("CH_TEST_HOOK_SECRET", "a long webhook secret value")
	e := newEnv(t)
	cert, _ := selfSigned(t, time.Now().Add(5*24*time.Hour))
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{cert}})
	a := e.addAsset(srv.Addr)
	e.scanAndWait(a.ID)
	systemID := firstSystem(t, e)
	for _, due := range []string{"2001-02-03", time.Now().Add(24 * time.Hour).UTC().Format(time.DateOnly)} {
		if s := e.call("POST", "/api/v1/work", map[string]any{"title": "Retire the old VPN profile", "workflow": "manual", "due": due,
			"subject": map[string]any{"kind": "system", "systemId": systemID}}, nil); s != 201 {
			t.Fatalf("create: %d", s)
		}
	}
	evs := events(t, e)
	for kind, sev := range map[string]string{"work.overdue": "high", "work.due-soon": "medium", "certificate.expiring": "high"} {
		ev := hasKind(evs, kind)
		if ev == nil || ev.Severity != sev || ev.Link == "" {
			t.Errorf("%s: %+v (all: %+v)", kind, ev, evs)
		}
	}

	// No destination yet: events are recorded as not sent.
	var res server.MonitorResult
	if s := e.call("POST", "/api/v1/lifecycle/check", nil, &res); s != 200 || res.New != len(evs) || res.Delivered != 0 {
		t.Fatalf("check without a webhook: %d %+v", s, res)
	}

	h, hookSrv := newHook(t)
	bad := map[string]any{"expiryWarnDays": 30, "expiryCriticalDays": 7, "dueSoonDays": 3, "webhookUrl": "https://user:pw@example.com/x", "webhookFormat": "json"}
	if s := e.call("PUT", "/api/v1/settings/lifecycle", bad, nil); s != 400 {
		t.Fatalf("a webhook with credentials in its address: %d", s)
	}
	bad["webhookUrl"], bad["webhookSecretEnv"] = hookSrv.URL, "not a name"
	if s := e.call("PUT", "/api/v1/settings/lifecycle", bad, nil); s != 400 {
		t.Fatalf("a bad environment variable name: %d", s)
	}
	set := map[string]any{"expiryWarnDays": 30, "expiryCriticalDays": 7, "dueSoonDays": 3, "webhookUrl": hookSrv.URL, "webhookFormat": "json",
		"webhookSecretEnv": "CH_TEST_HOOK_SECRET"}
	s, body := e.do("PUT", "/api/v1/settings/lifecycle", set)
	if s != 200 || strings.Contains(string(body), "a long webhook secret value") || !strings.Contains(string(body), `"secretSet":true`) {
		t.Fatalf("settings: %d %s", s, body)
	}

	// A new event after the destination was set is sent; events seen before stay not-sent.
	e.call("POST", "/api/v1/work", map[string]any{"title": "Rotate the jump host keys", "workflow": "manual", "due": "2001-03-04",
		"subject": map[string]any{"kind": "system", "systemId": systemID}}, nil)
	ctx := context.Background()
	res, err := e.srv.RunMonitor(ctx)
	if err != nil || res.Delivered != 1 || res.New != 1 {
		t.Fatalf("first pass: %+v %v", res, err)
	}
	if got := h.events(); len(got) != 1 || got[0] != "work.overdue" {
		t.Fatalf("delivered: %v", got)
	}
	mac := hmac.New(sha256.New, []byte("a long webhook secret value"))
	mac.Write(h.bodies[0])
	if h.sigs[0] != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature %q does not match the body", h.sigs[0])
	}
	if res, _ := e.srv.RunMonitor(ctx); res.Delivered != 0 || res.New != 0 {
		t.Fatalf("a second pass sent again: %+v", res)
	}

	// A destination that fails is retried, then given up on.
	h.status = 500
	e.call("POST", "/api/v1/work", map[string]any{"title": "Replace the lab CA", "workflow": "manual", "due": "2001-05-06",
		"subject": map[string]any{"kind": "system", "systemId": systemID}}, nil)
	for i := 0; i < 6; i++ {
		_, _ = e.srv.RunMonitor(ctx)
	}
	var ns []store.Notification
	e.call("GET", "/api/v1/lifecycle/notifications", nil, &ns)
	failed := 0
	for _, n := range ns {
		if n.Status == store.NotifyFailed {
			failed++
			if n.Attempts != 5 || !strings.Contains(n.LastError, "500") {
				t.Errorf("failed notification: %+v", n)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("%d failed notifications, want 1: %+v", failed, ns)
	}

	// The integration registry shows the webhook's health and never the secret.
	s, body = e.do("GET", "/api/v1/integrations", nil)
	if s != 200 || strings.Contains(string(body), "a long webhook secret value") || !strings.Contains(string(body), "last delivery failed") ||
		!strings.Contains(string(body), `"status":"planned"`) {
		t.Fatalf("integrations: %d %s", s, body)
	}
}

// The webhook cannot be pointed at a cloud-metadata or link-local address.
func TestTheWebhookObeysTheAddressGuard(t *testing.T) {
	e := newEnv(t)
	if s := e.call("PUT", "/api/v1/settings/lifecycle", map[string]any{"expiryWarnDays": 30, "expiryCriticalDays": 7, "dueSoonDays": 3,
		"webhookUrl": "http://169.254.169.254/latest/meta-data/", "webhookFormat": "chat"}, nil); s != 200 {
		t.Fatalf("settings: %d", s)
	}
	s, body := e.do("POST", "/api/v1/lifecycle/test-webhook", nil)
	if s != 502 || !strings.Contains(string(body), "not allowed") {
		t.Fatalf("test message to the metadata address: %d %s", s, body)
	}
}

// REQ-LC-5: verified work that a later scan contradicts is reported as a regression; a certificate that
// changed with no work naming it is reported as an unplanned change.
func TestRegressionsAndUnplannedCertificateChanges(t *testing.T) {
	e := newEnv(t)
	quick := map[string]any{
		"id": "quick-fix", "title": "Quick fix", "subjects": []string{"finding"},
		"stages": []map[string]any{
			{"id": "open", "label": "Open", "marker": "requested"},
			{"id": "changed", "label": "Changed", "marker": "executed"},
			{"id": "verified", "label": "Verified", "marker": "verified"},
			{"id": "done", "label": "Done", "marker": "complete", "terminal": true},
		},
		"transitions": []map[string]any{
			{"id": "change", "label": "Change", "from": []string{"open"}, "to": "changed"},
			{"id": "verify", "label": "Verify", "from": []string{"changed"}, "to": "verified", "verify": true},
			{"id": "close", "label": "Close", "from": []string{"verified"}, "to": "done"},
		},
	}
	if s := e.call("POST", "/api/v1/workflows", quick, nil); s != 201 {
		t.Fatalf("workflow: %d", s)
	}
	oldCert, _ := selfSigned(t, time.Now().Add(300*24*time.Hour))
	newCert, _ := selfSigned(t, time.Now().Add(400*24*time.Hour))
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Chain: []tls.Certificate{oldCert}})
	a := e.addAsset(srv.Addr)
	e.scanAndWait(a.ID)
	var w workJSON
	if s := e.call("POST", "/api/v1/work", map[string]any{"title": "Enable TLS 1.3", "workflow": "quick-fix",
		"subject": map[string]any{"kind": "finding", "assetId": a.ID, "findingKey": "PROTO.NO-TLS13"}}, &w); s != 201 {
		t.Fatalf("create: %d", s)
	}
	move(t, e, "", w.ID, map[string]any{"transition": "change"})
	srv = restartWith(t, srv, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{oldCert}})
	e.scanAndWait(a.ID)
	for _, tr := range []string{"verify", "close"} {
		if s, b := move(t, e, "", w.ID, map[string]any{"transition": tr}); s != 200 {
			t.Fatalf("%s: %d %s", tr, s, b)
		}
	}
	if ev := hasKind(events(t, e), "work.regressed"); ev != nil {
		t.Fatalf("a regression before anything regressed: %+v", ev)
	}

	// Someone turns TLS 1.3 off again, and swaps the certificate without telling anyone.
	restartWith(t, srv, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Chain: []tls.Certificate{newCert}})
	e.scanAndWait(a.ID)
	evs := events(t, e)
	reg := hasKind(evs, "work.regressed")
	if reg == nil || reg.Severity != "critical" || reg.WorkID != w.ID || !strings.Contains(reg.Detail, "still finds PROTO.NO-TLS13") {
		t.Fatalf("regression: %+v", reg)
	}
	if un := hasKind(evs, "certificate.unplanned-change"); un == nil || un.Severity != "high" {
		t.Fatalf("unplanned change: %+v (all %+v)", un, evs)
	}
	if evs[0].Kind != "work.regressed" {
		t.Fatalf("the most severe event comes first: %+v", evs[0])
	}
}

func restartWith(t *testing.T, old *testserver.Server, cfg testserver.Config) *testserver.Server {
	t.Helper()
	old.Close()
	time.Sleep(100 * time.Millisecond)
	cfg.Addr = old.Addr
	return testserver.Start(t, cfg)
}

// REQ-PLAN-1, REQ-PLAN-2: suggestions come from the scans, cite their basis and disappear once work is
// opened; the summary counts readiness out of what was scanned and keeps the unscanned apart.
func TestSuggestionsAndTheSummaryAreHonest(t *testing.T) {
	e := newEnv(t)
	classical := e.addAsset(classicalServer(t).Addr)
	hybrid := e.addAsset(hybridServer(t).Addr)
	e.addAsset(deadPort(t)) // never scanned successfully: unknown, not "not ready"
	e.scanAndWait(classical.ID)
	e.scanAndWait(hybrid.ID)

	var sugg []struct {
		Key, Severity, Title, Workflow string
		Subject                        struct {
			Kind        string `json:"kind"`
			AssetID     int64  `json:"assetId"`
			TargetLevel int    `json:"targetLevel"`
		}
		Basis *struct{ Milestone, Document, URL string }
	}
	e.call("GET", "/api/v1/work/suggestions", nil, &sugg)
	var found bool
	for _, sg := range sugg {
		if sg.Subject.AssetID == hybrid.ID && sg.Subject.Kind == "readiness" {
			t.Fatalf("an endpoint at L3 got a hybrid suggestion: %+v", sg)
		}
		if sg.Subject.AssetID == classical.ID && sg.Subject.Kind == "readiness" {
			found = sg.Workflow == "pq-key-exchange" && sg.Subject.TargetLevel == 3 && sg.Basis != nil &&
				sg.Basis.Milestone == "ir8547.key-establishment-deprecated" && strings.HasPrefix(sg.Basis.URL, "https://") && sg.Severity == "high"
		}
	}
	if !found {
		t.Fatalf("no cited hybrid suggestion for the classical endpoint: %+v", sugg)
	}

	// Accepting the suggestion creates the work, and it is no longer suggested.
	target := 3
	if s := e.call("POST", "/api/v1/work", map[string]any{"title": "Hybrid on the API gateway", "workflow": "pq-key-exchange", "project": "PQC wave 1",
		"subject": map[string]any{"kind": "readiness", "assetId": classical.ID, "targetLevel": target}}, nil); s != 201 {
		t.Fatalf("create: %d", s)
	}
	sugg = nil
	e.call("GET", "/api/v1/work/suggestions", nil, &sugg)
	for _, sg := range sugg {
		if sg.Subject.AssetID == classical.ID && sg.Subject.Kind == "readiness" {
			t.Fatalf("still suggested after work was opened: %+v", sg)
		}
	}

	var sum struct {
		Total, Open, AwaitingVerification int
		Readiness                         struct{ Endpoints, Scanned, AtL3, BelowL3, WithWork int }
		Projects                          []struct {
			Project     string
			Total, Open int
		}
		Definitions map[string]string
	}
	if s := e.call("GET", "/api/v1/work/summary", nil, &sum); s != 200 {
		t.Fatalf("summary: %d", s)
	}
	r := sum.Readiness
	if sum.Total != 1 || sum.Open != 1 || r.Endpoints != 3 || r.Scanned != 2 || r.AtL3 != 1 || r.BelowL3 != 1 || r.WithWork != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	if len(sum.Projects) != 1 || sum.Projects[0].Project != "PQC wave 1" || sum.Projects[0].Open != 1 {
		t.Fatalf("projects: %+v", sum.Projects)
	}
	for _, k := range []string{"open", "verified", "readiness.scanned", "readiness.atL3"} {
		if !strings.Contains(sum.Definitions[k], "out of") && !strings.Contains(sum.Definitions[k], "in the inventory") {
			t.Errorf("definition of %s names no denominator: %q", k, sum.Definitions[k])
		}
	}
}

// REQ-LC-6: an owner and renewal method are recorded per certificate, audited, and validated.
func TestCertificateOwnershipIsRecorded(t *testing.T) {
	e := newEnv(t)
	cert, fp := selfSigned(t, time.Now().Add(90*24*time.Hour))
	a := e.addAsset(testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{cert}}).Addr)
	e.scanAndWait(a.ID)
	path := "/api/v1/certificates/" + fp + "/lifecycle"
	if s := e.call("PUT", path, map[string]any{"owner": "payments platform", "renewal": "teleport"}, nil); s != 400 {
		t.Fatalf("an unknown renewal method: %d", s)
	}
	if s := e.call("PUT", "/api/v1/certificates/"+strings.Repeat("ab", 32)+"/lifecycle", map[string]any{"owner": "x"}, nil); s != 404 {
		t.Fatalf("a certificate not in the inventory: %d", s)
	}
	if s := e.call("PUT", path+"?reason=handover", map[string]any{"owner": "payments platform", "renewal": "acme", "notes": "step-ca, 24h certs"}, nil); s != 200 {
		t.Fatalf("put: %d", s)
	}
	var got struct {
		Lifecycle store.CertLifecycle
		Work      []workJSON
	}
	if s := e.call("GET", path, nil, &got); s != 200 || got.Lifecycle.Owner != "payments platform" || got.Lifecycle.Renewal != "acme" || got.Lifecycle.UpdatedBy != "local" {
		t.Fatalf("get: %d %+v", s, got)
	}
	acts, _ := e.st.Activity(store.ActivityFilter{Source: "change", Limit: 10})
	if len(acts) == 0 || acts[0].Action != "lifecycle edited" || acts[0].Reason != "handover" {
		t.Fatalf("not audited: %+v", acts)
	}
}

// REQ-WEX-1: the exports carry every piece of work; the CSV defuses formulas; the evidence pack has the
// history and a verification computed at export time.
func TestWorkExports(t *testing.T) {
	e := newEnv(t)
	e.addAsset(tls12Server(t).Addr)
	systemID := firstSystem(t, e)
	var w workJSON
	e.call("POST", "/api/v1/work", map[string]any{"title": "=HYPERLINK(\"x\")", "workflow": "manual", "subject": map[string]any{"kind": "system", "systemId": systemID}}, &w)
	move(t, e, "", w.ID, map[string]any{"transition": "start"})
	s, body := e.do("GET", "/api/v1/work/export.csv", nil)
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if s != 200 || err != nil || len(rows) != 2 || rows[1][1] != `'=HYPERLINK("x")` {
		t.Fatalf("csv: %d %v %q", s, err, rows)
	}
	var ev struct {
		CatalogVersion string
		Definitions    map[string]string
		Work           []struct {
			History         []struct{ Action string }
			VerificationNow struct{ Status string } `json:"verificationNow"`
		}
	}
	if s := e.call("GET", "/api/v1/work/evidence.json", nil, &ev); s != 200 || ev.CatalogVersion == "" || len(ev.Work) != 1 ||
		len(ev.Work[0].History) != 2 || ev.Work[0].VerificationNow.Status != "not-verifiable" || len(ev.Definitions) == 0 {
		t.Fatalf("evidence: %d %+v", s, ev)
	}
}

// Running the monitor and sending a test message are for administrators.
func TestLifecycleAdministrationNeedsAnAdministrator(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode))
	ana := setupAdmin(t, e)
	bob := person(t, e, ana, "bob", "analyst")
	for _, p := range []string{"/api/v1/lifecycle/check", "/api/v1/lifecycle/test-webhook"} {
		if s, _, _ := e.as(bob, "POST", p, nil); s != 403 {
			t.Errorf("an analyst called %s: %d", p, s)
		}
	}
	if s, _, _ := e.as(bob, "GET", "/api/v1/settings/lifecycle", nil); s != 403 {
		t.Errorf("an analyst read the lifecycle settings: %d", s)
	}
	if s, _, _ := e.as(bob, "GET", "/api/v1/lifecycle/events", nil); s != 200 {
		t.Errorf("an analyst cannot read events: %d", s)
	}
	if s, _, _ := e.as(ana, "POST", "/api/v1/lifecycle/check", nil); s != 200 {
		t.Errorf("an administrator ran the check: %d", s)
	}
}
