package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

type workJSON struct {
	ID               int64           `json:"id"`
	Title            string          `json:"title"`
	Workflow         string          `json:"workflow"`
	WorkflowVersion  int             `json:"workflowVersion"`
	Stage            string          `json:"stage"`
	Marker           string          `json:"marker"`
	CreatedBy        string          `json:"createdBy"`
	Approvers        []string        `json:"approvers"`
	ExecutedAt       *string         `json:"executedAt"`
	ClosedAt         *string         `json:"closedAt"`
	ExceptionUntil   *string         `json:"exceptionUntil"`
	Overdue          bool            `json:"overdue"`
	Verification     json.RawMessage `json:"verification"`
	Transitions      []struct{ ID string }
	Dependencies     []struct{ ID int64 }
	History          []struct{ Action, Actor, Reason string }
	ExceptionExpired bool `json:"exceptionExpired"`
}

type verificationJSON struct {
	Status   string   `json:"status"`
	Detail   string   `json:"detail"`
	Evidence []string `json:"evidence"`
}

type refusalJSON struct {
	Error        string            `json:"error"`
	Code         string            `json:"code"`
	Verification *verificationJSON `json:"verification"`
}

// person adds an account and returns a session for it, past the forced first password change.
func person(t *testing.T, e *env, admin, name, role string) string {
	t.Helper()
	pw := strings.Repeat("x", len(name)) + " seven" // must not contain the username
	if s, b, _ := e.as(admin, "POST", "/api/v1/users", map[string]any{"username": name, "role": role, "password": "temporary pass phrase " + pw}); s != 201 {
		t.Fatalf("add %s: %d %s", name, s, b)
	}
	_, c := login(t, e, name, "temporary pass phrase "+pw)
	s, b, h := e.as(c, "POST", "/api/v1/auth/password", map[string]any{"current": "temporary pass phrase " + pw, "new": "own long phrase for " + pw})
	if s != 204 {
		t.Fatalf("password of %s: %d %s", name, s, b)
	}
	return cookieOf(t, h)
}

// move asks for a transition as cookie ("" for the env's own credentials) and returns the status and body.
func move(t *testing.T, e *env, cookie string, id int64, body map[string]any) (int, []byte) {
	t.Helper()
	path := "/api/v1/work/" + itoa(id) + "/transitions"
	if cookie == "" {
		return e.do("POST", path, body)
	}
	s, b, _ := e.as(cookie, "POST", path, body)
	return s, b
}

func wantRefusal(t *testing.T, status int, body []byte, wantStatus int, wantCode string) refusalJSON {
	t.Helper()
	var r refusalJSON
	_ = json.Unmarshal(body, &r)
	if status != wantStatus || r.Code != wantCode {
		t.Fatalf("got %d %s, want %d with code %q", status, body, wantStatus, wantCode)
	}
	if strings.TrimSpace(r.Error) == "" {
		t.Fatal("a refusal must say why")
	}
	return r
}

func verificationOf(t *testing.T, e *env, id int64) verificationJSON {
	t.Helper()
	var v verificationJSON
	if s := e.call("GET", "/api/v1/work/"+itoa(id)+"/verification", nil, &v); s != 200 {
		t.Fatalf("verification: %d", s)
	}
	return v
}

// REQ-WF-6, REQ-WF-7, REQ-WF-8, REQ-WF-10: a finding on an endpoint goes through a workflow with an
// approval by a second person, and is marked verified only after a scan made after the change no longer
// finds it. A rescan that still finds it says so.
func TestAFindingIsVerifiedOnlyByAScanAfterTheChange(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode), withToken("automation-token-for-tests"))
	ana := setupAdmin(t, e)
	bo := person(t, e, ana, "bob", "analyst")
	vic := person(t, e, ana, "vic", "viewer")

	target := tls12Server(t)
	a := e.addAsset(target.Addr)
	e.scanAndWait(a.ID)

	create := map[string]any{"title": "Enable TLS 1.3 on the payroll gateway", "workflow": "tls-configuration-change", "owner": "bob", "due": "2099-01-31",
		"subject": map[string]any{"kind": "finding", "assetId": a.ID, "findingKey": "PROTO.NO-TLS13"}}
	if s, b, _ := e.as(vic, "POST", "/api/v1/work", create); s != 403 {
		t.Fatalf("a viewer created work: %d %s", s, b)
	}
	wrong := map[string]any{"title": "x", "workflow": "tls-configuration-change", "subject": map[string]any{"kind": "finding", "assetId": a.ID, "findingKey": "CIPHER.RC4"}}
	if s, b, _ := e.as(ana, "POST", "/api/v1/work", wrong); s != 400 || !strings.Contains(string(b), "not among the current findings") {
		t.Fatalf("work on a finding the endpoint does not have: %d %s", s, b)
	}
	mismatch := map[string]any{"title": "x", "workflow": "certificate-renewal", "subject": map[string]any{"kind": "finding", "assetId": a.ID, "findingKey": "PROTO.NO-TLS13"}}
	if s, b, _ := e.as(ana, "POST", "/api/v1/work", mismatch); s != 400 || !strings.Contains(string(b), "applies to") {
		t.Fatalf("a workflow used for a subject it does not apply to: %d %s", s, b)
	}
	var w workJSON
	s, b, _ := e.as(ana, "POST", "/api/v1/work", create)
	if s != 201 {
		t.Fatalf("create: %d %s", s, b)
	}
	mustJSON(t, b, &w)
	if w.Stage != "requested" || w.Marker != "requested" || w.CreatedBy != "ana" || w.WorkflowVersion != 1 {
		t.Fatalf("created: %+v", w)
	}

	if s, b := move(t, e, ana, w.ID, map[string]any{"transition": "plan"}); s != 200 {
		t.Fatalf("plan: %d %s", s, b)
	}
	s, b = move(t, e, ana, w.ID, map[string]any{"transition": "approve"})
	wantRefusal(t, s, b, 409, "approval") // the requester
	s, b = move(t, e, "", w.ID, map[string]any{"transition": "approve"})
	wantRefusal(t, s, b, 409, "approval") // the automation token is nobody in particular
	if s, b := move(t, e, bo, w.ID, map[string]any{"transition": "approve"}); s != 200 {
		t.Fatalf("approval by a second person: %d %s", s, b)
	}
	s, b = move(t, e, bo, w.ID, map[string]any{"transition": "verify"})
	wantRefusal(t, s, b, 409, "wrong-stage")
	s, b = move(t, e, bo, w.ID, map[string]any{"transition": "change"})
	wantRefusal(t, s, b, 400, "missing-field")
	s, b = move(t, e, bo, w.ID, map[string]any{"transition": "change", "note": "ssl_protocols TLSv1.2 TLSv1.3 on the gateway"})
	if s != 200 {
		t.Fatalf("change: %d %s", s, b)
	}
	mustJSON(t, b, &w)
	if w.Marker != "executed" || w.ExecutedAt == nil {
		t.Fatalf("after the change: %+v", w)
	}

	// No scan since the change: waiting, and the verified stage stays shut.
	if v := verificationOf(t, e, w.ID); v.Status != "waiting" {
		t.Fatalf("before any rescan: %+v", v)
	}
	s, b = move(t, e, bo, w.ID, map[string]any{"transition": "verify"})
	if r := wantRefusal(t, s, b, 409, "not-verified"); r.Verification == nil || r.Verification.Status != "waiting" {
		t.Fatalf("a refused verification returns what it found: %s", b)
	}

	// The change did not take: a rescan still finds it.
	e.scanAndWait(a.ID)
	if v := verificationOf(t, e, w.ID); v.Status != "not-verified" || !strings.Contains(v.Detail, "still finds PROTO.NO-TLS13") || len(v.Evidence) != 1 {
		t.Fatalf("rescan of the unchanged endpoint: %+v", v)
	}

	// Now it is really changed: the endpoint offers TLS 1.3.
	target.Close()
	time.Sleep(100 * time.Millisecond)
	testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Addr: target.Addr})
	e.scanAndWait(a.ID)
	if v := verificationOf(t, e, w.ID); v.Status != "verified" {
		t.Fatalf("after the real change: %+v", v)
	}
	if s, b := move(t, e, bo, w.ID, map[string]any{"transition": "verify"}); s != 200 {
		t.Fatalf("verify: %d %s", s, b)
	}
	s, b = move(t, e, bo, w.ID, map[string]any{"transition": "close"})
	if s != 200 {
		t.Fatalf("close: %d %s", s, b)
	}
	mustJSON(t, b, &w)
	if w.Marker != "complete" || w.ClosedAt == nil || len(w.Approvers) != 1 || w.Approvers[0] != "bob" {
		t.Fatalf("closed: %+v", w)
	}

	// The history: every accepted step, in order, with who; refused attempts change nothing.
	s, b, _ = e.as(ana, "GET", "/api/v1/work/"+itoa(w.ID), nil)
	if s != 200 {
		t.Fatalf("get: %d %s", s, b)
	}
	mustJSON(t, b, &w)
	var actions []string
	for i := len(w.History) - 1; i >= 0; i-- {
		actions = append(actions, w.History[i].Action+"/"+w.History[i].Actor)
	}
	if got, want := strings.Join(actions, " "), "created/ana plan/ana approve/bob change/bob verify/bob close/bob"; got != want {
		t.Fatalf("history %q, want %q", got, want)
	}
	if len(w.Transitions) != 0 {
		t.Fatalf("closed work still offers %v", w.Transitions)
	}
	var verified struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Verification, &verified); err != nil || verified.Status != "verified" {
		t.Fatalf("the verification behind the verify step is kept on the work: %s", w.Verification)
	}
}

// selfSigned makes a certificate for 127.0.0.1 valid until notAfter.
func selfSigned(t *testing.T, notAfter time.Time) (tls.Certificate, string) {
	t.Helper()
	return selfSignedFrom(t, time.Now().Add(-time.Hour), notAfter)
}

// selfSignedFrom makes a certificate for 127.0.0.1 valid from notBefore until notAfter.
func selfSignedFrom(t *testing.T, notBefore, notAfter time.Time) (tls.Certificate, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "pay.test"},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: []string{"pay.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}, hex.EncodeToString(sum[:])
}

func restart(t *testing.T, old *testserver.Server, cert tls.Certificate) *testserver.Server {
	t.Helper()
	old.Close()
	time.Sleep(100 * time.Millisecond)
	return testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Addr: old.Addr, Chain: []tls.Certificate{cert}})
}

// REQ-WF-8: a certificate replacement is verified only when every endpoint that served the old
// certificate now serves a different one that is valid for longer. Approval after the fact needs a
// signed-in person, so with sign-in off it is refused.
func TestACertificateReplacementIsVerifiedOnEveryEndpoint(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	oldCert, oldFP := selfSigned(t, now.Add(10*24*time.Hour))
	// The replacement lives for less time than the old one (a move to short-lived certificates): still a
	// replacement, because it was issued later. An older certificate put back is not.
	newCert, _ := selfSignedFrom(t, now.Add(-10*time.Minute), now.Add(5*24*time.Hour))
	older, _ := selfSignedFrom(t, now.Add(-48*time.Hour), now.Add(300*24*time.Hour))
	srvA := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{oldCert}})
	srvB := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{oldCert}})
	a, b := e.addAsset(srvA.Addr), e.addAsset(srvB.Addr)
	e.scanAndWait(a.ID)
	e.scanAndWait(b.ID)

	var w workJSON
	if s := e.call("POST", "/api/v1/work", map[string]any{"title": "Replace the leaked payroll certificate", "workflow": "emergency-certificate-replacement",
		"subject": map[string]any{"kind": "certificate", "certificate": strings.ToUpper(oldFP)}}, &w); s != 201 {
		t.Fatalf("create: %d", s)
	}
	if s := e.call("POST", "/api/v1/work", map[string]any{"title": "x", "workflow": "certificate-renewal",
		"subject": map[string]any{"kind": "certificate", "certificate": strings.Repeat("ab", 32)}}, nil); s != 400 {
		t.Fatalf("work on a certificate not in the inventory: %d", s)
	}
	if s, b := move(t, e, "", w.ID, map[string]any{"transition": "replace", "note": "new key from the HSM, deployed on both"}); s != 200 {
		t.Fatalf("replace: %d %s", s, b)
	}
	if v := verificationOf(t, e, w.ID); v.Status != "waiting" {
		t.Fatalf("before any rescan: %+v", v)
	}

	srvA = restart(t, srvA, newCert)
	e.scanAndWait(a.ID)
	if v := verificationOf(t, e, w.ID); v.Status != "waiting" || !strings.Contains(v.Detail, b.Name) {
		t.Fatalf("one endpoint rescanned, the other not: %+v", v)
	}
	e.scanAndWait(b.ID)
	if v := verificationOf(t, e, w.ID); v.Status != "not-verified" || !strings.Contains(v.Detail, "still presents it") {
		t.Fatalf("the second endpoint still serves the old certificate: %+v", v)
	}
	srvB = restart(t, srvB, older)
	e.scanAndWait(b.ID)
	if v := verificationOf(t, e, w.ID); v.Status != "not-verified" || !strings.Contains(v.Detail, "not a replacement") {
		t.Fatalf("an older certificate put back: %+v", v)
	}
	restart(t, srvB, newCert)
	e.scanAndWait(b.ID)
	v := verificationOf(t, e, w.ID)
	if v.Status != "verified" || len(v.Evidence) != 2 {
		t.Fatalf("both endpoints serve the new certificate: %+v", v)
	}
	if s, b := move(t, e, "", w.ID, map[string]any{"transition": "verify"}); s != 200 {
		t.Fatalf("verify: %d %s", s, b)
	}
	s, body := move(t, e, "", w.ID, map[string]any{"transition": "review"})
	wantRefusal(t, s, body, 409, "approval")
	_ = srvA
}

// REQ-WF-4, REQ-WF-8: an administrator adds a custom workflow (validated, versioned, built-in ids
// reserved); work keeps the version it was created with; a readiness target is verified by the level a
// later scan reaches.
func TestCustomWorkflowsAndAReadinessTarget(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode), withToken("automation-token-for-tests"))
	ana := setupAdmin(t, e)
	bo := person(t, e, ana, "bob", "analyst")

	quick := map[string]any{
		"id": "quick-hybrid", "title": "Quick hybrid", "purpose": "Lab endpoints: enable and verify.", "subjects": []string{"readiness"},
		"stages": []map[string]any{
			{"id": "open", "label": "Open", "marker": "requested"},
			{"id": "enabled", "label": "Enabled", "marker": "executed"},
			{"id": "verified", "label": "Verified", "marker": "verified"},
			{"id": "done", "label": "Done", "marker": "complete", "terminal": true},
		},
		"transitions": []map[string]any{
			{"id": "enable", "label": "Enable", "from": []string{"open"}, "to": "enabled"},
			{"id": "verify", "label": "Verify", "from": []string{"enabled"}, "to": "verified", "verify": true},
			{"id": "close", "label": "Close", "from": []string{"verified"}, "to": "done"},
		},
	}
	if s, b, _ := e.as(bo, "POST", "/api/v1/workflows", quick); s != 403 {
		t.Fatalf("an analyst added a workflow: %d %s", s, b)
	}
	builtin := map[string]any{}
	for k, v := range quick {
		builtin[k] = v
	}
	builtin["id"] = "manual"
	if s, b, _ := e.as(ana, "POST", "/api/v1/workflows", builtin); s != 409 {
		t.Fatalf("a built-in id was replaced: %d %s", s, b)
	}
	shortcut := map[string]any{}
	for k, v := range quick {
		shortcut[k] = v
	}
	shortcut["transitions"] = []map[string]any{
		{"id": "enable", "label": "Enable", "from": []string{"open"}, "to": "enabled"},
		{"id": "verify", "label": "Mark verified", "from": []string{"enabled"}, "to": "verified"},
		{"id": "close", "label": "Close", "from": []string{"verified"}, "to": "done"},
	}
	if s, b, _ := e.as(ana, "POST", "/api/v1/workflows", shortcut); s != 400 || !strings.Contains(string(b), "without requiring verification") {
		t.Fatalf("a workflow that marks work verified without verification: %d %s", s, b)
	}
	if s, b, _ := e.as(ana, "POST", "/api/v1/workflows", quick); s != 201 {
		t.Fatalf("add: %d %s", s, b)
	}

	target := classicalServer(t)
	a := e.addAsset(target.Addr)
	scan := func() { t.Helper(); e.scanAndWait(a.ID) }
	scan()

	var w workJSON
	s, b, _ := e.as(bo, "POST", "/api/v1/work", map[string]any{"title": "Hybrid on the lab endpoint", "workflow": "quick-hybrid",
		"subject": map[string]any{"kind": "readiness", "assetId": a.ID, "targetLevel": 3}})
	if s != 201 {
		t.Fatalf("create: %d %s", s, b)
	}
	mustJSON(t, b, &w)

	// A second version of the template does not change work already under way.
	quick["title"] = "Quick hybrid (v2)"
	if s, b, _ := e.as(ana, "POST", "/api/v1/workflows", quick); s != 201 || !strings.Contains(string(b), `"version":2`) {
		t.Fatalf("second version: %d %s", s, b)
	}
	if w.WorkflowVersion != 1 {
		t.Fatalf("work was created on version %d", w.WorkflowVersion)
	}

	if s, b := move(t, e, bo, w.ID, map[string]any{"transition": "enable"}); s != 200 {
		t.Fatalf("enable: %d %s", s, b)
	}
	scan()
	s, b = move(t, e, bo, w.ID, map[string]any{"transition": "verify"})
	if r := wantRefusal(t, s, b, 409, "not-verified"); !strings.Contains(r.Verification.Detail, "target is L3") {
		t.Fatalf("still classical: %s", b)
	}
	target.Close()
	time.Sleep(100 * time.Millisecond)
	testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Addr: target.Addr, Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}})
	scan()
	if s, b := move(t, e, bo, w.ID, map[string]any{"transition": "verify"}); s != 200 {
		t.Fatalf("verify after hybrid is enabled: %d %s", s, b)
	}

	var list []map[string]any
	s, b, _ = e.as(bo, "GET", "/api/v1/workflows", nil)
	mustJSON(t, b, &list)
	found := false
	for _, x := range list {
		if x["id"] == "quick-hybrid" {
			found = x["version"] == float64(2) && x["builtIn"] == false && x["verifies"] == true
		}
	}
	if s != 200 || len(list) != 11 || !found {
		t.Fatalf("workflows: %d, %d entries, custom latest found=%v", s, len(list), found)
	}
}

// REQ-WF-6, REQ-WF-9: prerequisites block a step that says the change was made; cycles are refused;
// an exception needs an administrator and an end date in the future; overdue work says so.
func TestDependenciesExceptionsAndDueDates(t *testing.T) {
	e := newEnv(t)
	e.addAsset(tls12Server(t).Addr)
	systemID := firstSystem(t, e)
	mk := func(title, due string) workJSON {
		t.Helper()
		var w workJSON
		if s := e.call("POST", "/api/v1/work", map[string]any{"title": title, "workflow": "manual", "due": due,
			"subject": map[string]any{"kind": "system", "systemId": systemID}}, &w); s != 201 {
			t.Fatalf("create %s: %d", title, s)
		}
		return w
	}
	first, second := mk("Upgrade the CA", ""), mk("Reissue every certificate", "2001-01-01")
	if !second.Overdue || first.Overdue {
		t.Fatalf("overdue flags: %v %v", first.Overdue, second.Overdue)
	}
	if s, _ := e.do("PUT", "/api/v1/work/"+itoa(second.ID)+"/dependencies/"+itoa(first.ID), nil); s != 204 {
		t.Fatalf("add dependency: %d", s)
	}
	if s, _ := e.do("PUT", "/api/v1/work/"+itoa(first.ID)+"/dependencies/"+itoa(second.ID), nil); s != 409 {
		t.Fatalf("a cycle was accepted: %d", s)
	}
	if s, b := move(t, e, "", second.ID, map[string]any{"transition": "start"}); s != 200 {
		t.Fatalf("starting is not blocked: %d %s", s, b)
	}
	s, b := move(t, e, "", second.ID, map[string]any{"transition": "finish", "note": "done"})
	if r := wantRefusal(t, s, b, 409, "blocked"); !strings.Contains(r.Error, "#"+itoa(first.ID)) {
		t.Fatalf("the refusal names the prerequisite: %s", r.Error)
	}
	if s, b := move(t, e, "", first.ID, map[string]any{"transition": "finish", "note": "upgraded"}); s != 200 {
		t.Fatalf("finish the prerequisite: %d %s", s, b)
	}
	if s, b := move(t, e, "", second.ID, map[string]any{"transition": "finish", "note": "reissued"}); s != 200 {
		t.Fatalf("finish once unblocked: %d %s", s, b)
	}
	var open []workJSON
	if s := e.call("GET", "/api/v1/work?marker=open", nil, &open); s != 200 || len(open) != 0 {
		t.Fatalf("open work after both finished: %d %d", s, len(open))
	}

	// Exceptions (TLS configuration change on a finding).
	var assets []assetJSON
	e.call("GET", "/api/v1/assets", nil, &assets)
	e.scanAndWait(assets[0].ID)
	var w workJSON
	if s := e.call("POST", "/api/v1/work", map[string]any{"title": "Legacy client needs TLS 1.2 only", "workflow": "tls-configuration-change",
		"subject": map[string]any{"kind": "finding", "assetId": assets[0].ID, "findingKey": "PROTO.NO-TLS13"}}, &w); s != 201 {
		t.Fatalf("create: %d", s)
	}
	inSixMonths := time.Now().AddDate(0, 6, 0).UTC().Format(time.DateOnly)
	s, b = move(t, e, "", w.ID, map[string]any{"transition": "accept-risk", "note": "legacy scanner", "until": "2099-06-30"})
	wantRefusal(t, s, b, 400, "until") // longer than a year
	s, b = move(t, e, "", w.ID, map[string]any{"transition": "accept-risk", "note": "legacy scanner", "until": "2001-01-01"})
	wantRefusal(t, s, b, 400, "until")
	s, b = move(t, e, "", w.ID, map[string]any{"transition": "accept-risk", "note": "legacy scanner", "until": inSixMonths})
	if s != 200 {
		t.Fatalf("accept the risk: %d %s", s, b)
	}
	mustJSON(t, b, &w)
	if w.Marker != "exception" || w.ExceptionUntil == nil || !strings.HasPrefix(*w.ExceptionUntil, inSixMonths) || w.ExceptionExpired {
		t.Fatalf("exception: %+v", w)
	}
	if s, _ := e.do("POST", "/api/v1/work/"+itoa(w.ID)+"/transitions", "not json"); s != 400 {
		t.Fatalf("a malformed body: %d", s)
	}
	if s, _ := e.do("POST", "/api/v1/work/999999/transitions", map[string]any{"transition": "start"}); s != 404 {
		t.Fatalf("missing work: %d", s)
	}
}

// REQ-WF-10: an edit is audited with before, after and reason; text fields refuse control characters.
func TestWorkEditsAreAuditedAndCleaned(t *testing.T) {
	e := newEnv(t)
	e.addAsset(tls12Server(t).Addr)
	systemID := firstSystem(t, e)
	var w workJSON
	if s := e.call("POST", "/api/v1/work", map[string]any{"title": "x", "workflow": "manual", "subject": map[string]any{"kind": "system", "systemId": systemID}}, &w); s != 201 {
		t.Fatalf("create: %d", s)
	}
	if s, _ := e.do("POST", "/api/v1/work", map[string]any{"title": "bad\x1btitle", "workflow": "manual", "subject": map[string]any{"kind": "system", "systemId": systemID}}); s != 400 {
		t.Fatalf("a control character in a title: %d", s)
	}
	if s, b := e.do("PATCH", "/api/v1/work/"+itoa(w.ID)+"?reason=handover", map[string]any{"owner": "platform team", "due": "2099-03-01"}); s != 200 {
		t.Fatalf("patch: %d %s", s, b)
	}
	if s, b := e.do("PATCH", "/api/v1/work/"+itoa(w.ID), map[string]any{"due": ""}); s != 200 {
		t.Fatalf("clear due: %d %s", s, b)
	}
	if s, _ := e.do("PATCH", "/api/v1/work/"+itoa(w.ID), map[string]any{"title": ""}); s != 400 {
		t.Fatalf("an empty title: %d", s)
	}
	log, err := e.st.Audit(store.WorkObject, w.ID, 10)
	if err != nil || len(log) != 3 || log[1].Action != "edited" || log[1].Reason != "handover" || !strings.Contains(string(log[1].After), "platform team") {
		t.Fatalf("audit: %v %+v", err, log)
	}
}

func firstSystem(t *testing.T, e *env) int64 {
	t.Helper()
	var out struct {
		Systems []struct {
			ID int64 `json:"id"`
		} `json:"systems"`
	}
	if s := e.call("GET", "/api/v1/systems", nil, &out); s != 200 || len(out.Systems) == 0 {
		t.Fatalf("systems: %d %d", s, len(out.Systems))
	}
	return out.Systems[0].ID
}

// REQ-POL-4: the policy catalog is served.
func TestThePolicyCatalogIsServed(t *testing.T) {
	e := newEnv(t)
	var c struct {
		Version    string `json:"version"`
		Documents  []struct{ ID, Status string }
		Milestones []struct{ ID, Date string }
		Profiles   []struct{ ID string }
	}
	if s := e.call("GET", "/api/v1/policy/catalog", nil, &c); s != 200 || c.Version == "" || len(c.Documents) == 0 || len(c.Milestones) == 0 || len(c.Profiles) == 0 {
		t.Fatalf("catalog: %d %+v", s, c)
	}
}
