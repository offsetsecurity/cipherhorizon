package mcpserver_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/mcpserver"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
	sshtest "github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	tlstest "github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// connect builds a server with opts and a client talking to it in memory.
func connect(t *testing.T, opts mcpserver.Options) *mcp.ClientSession {
	t.Helper()
	if opts.Version == "" {
		opts.Version = "test"
	}
	if opts.Verdict == nil {
		opts.Verdict = func(w io.Writer, target string, ev eval.Evaluation) error {
			_, err := fmt.Fprintf(w, "VERDICT %s %s", target, ev.Readiness.Label)
			return err
		}
	}
	srv := mcpserver.New(opts)
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func structured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structured content: %v\n%s", err, raw)
	}
	return out
}

func loopback() mcpserver.ScanOptions {
	return mcpserver.ScanOptions{Guard: server.Guard{AllowLoopback: true}, Timeout: 5 * time.Second, Concurrency: 8}
}

// REQ-MCP-7: the tool list is fixed and ordered; --read-only and --no-scan remove what they say.
func TestToolInventory(t *testing.T) {
	fleet := &mcpserver.Fleet{Base: "http://127.0.0.1:1"}
	cases := []struct {
		name string
		opts mcpserver.Options
		want []string
	}{
		{"scan only", mcpserver.Options{}, []string{"tls_scan", "ssh_scan"}},
		{"with fleet", mcpserver.Options{Fleet: fleet}, []string{"tls_scan", "ssh_scan", "fleet_summary", "endpoints_list", "endpoint_get",
			"endpoint_add", "scan_start", "scan_get", "findings_list", "standards_summary", "machines_list", "machine_get", "inventory_summary", "cbom_get"}},
		{"read-only", mcpserver.Options{Fleet: fleet, ReadOnly: true}, []string{"tls_scan", "ssh_scan", "fleet_summary", "endpoints_list", "endpoint_get",
			"scan_get", "findings_list", "standards_summary", "machines_list", "machine_get", "inventory_summary", "cbom_get"}},
		{"no scan, read-only", mcpserver.Options{Fleet: fleet, ReadOnly: true, NoScan: true}, []string{"fleet_summary", "endpoints_list", "endpoint_get",
			"scan_get", "findings_list", "standards_summary", "machines_list", "machine_get", "inventory_summary", "cbom_get"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := connect(t, tc.opts)
			got := toolNames(t, cs)
			want := append([]string(nil), tc.want...)
			sort.Strings(want) // the SDK lists tools by name, which is the deterministic order the spec asks for
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("tools\n got %v\nwant %v", got, tc.want)
			}
			res, err := cs.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, tool := range res.Tools {
				a := tool.Annotations
				if a == nil {
					t.Errorf("%s: no annotations", tool.Name)
					continue
				}
				mutating := tool.Name == "endpoint_add" || tool.Name == "scan_start"
				if a.ReadOnlyHint == mutating {
					t.Errorf("%s: readOnlyHint %v", tool.Name, a.ReadOnlyHint)
				}
				if a.DestructiveHint == nil || *a.DestructiveHint {
					t.Errorf("%s: destructiveHint should be false", tool.Name)
				}
				network := strings.HasSuffix(tool.Name, "_scan")
				if a.OpenWorldHint == nil || *a.OpenWorldHint != network {
					t.Errorf("%s: openWorldHint %v, want %v", tool.Name, a.OpenWorldHint, network)
				}
				if len(tool.Description) < 80 {
					t.Errorf("%s: description too short to guide a model: %q", tool.Name, tool.Description)
				}
			}
		})
	}
}

// REQ-MCP-8: the resources and prompts.
func TestResourcesAndPrompts(t *testing.T) {
	cs := connect(t, mcpserver.Options{Fleet: &mcpserver.Fleet{Base: "http://127.0.0.1:1"}})
	ctx := context.Background()
	rs, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Resources) != 4 {
		t.Fatalf("resources: %d", len(rs.Resources))
	}
	for _, r := range rs.Resources {
		got, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: r.URI})
		if err != nil {
			t.Fatalf("%s: %v", r.URI, err)
		}
		if len(got.Contents) != 1 || got.Contents[0].Text == "" || got.Contents[0].MIMEType != r.MIMEType {
			t.Errorf("%s: contents %+v", r.URI, got.Contents)
		}
	}
	std, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "cipherhorizon://standards"})
	if err != nil {
		t.Fatal(err)
	}
	var stds []struct {
		ID           string `json:"id"`
		Requirements []struct {
			Clause string `json:"clause"`
		} `json:"requirements"`
	}
	if err := json.Unmarshal([]byte(std.Contents[0].Text), &stds); err != nil || len(stds) != len(eval.Standards()) || len(stds[0].Requirements) == 0 {
		t.Errorf("standards resource: %v, %d standards", err, len(stds))
	}
	scale, _ := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "cipherhorizon://readiness-scale"})
	for _, want := range []string{"L0", "L4", "Excellent", "Failing", "HNDL", "meets"} {
		if !strings.Contains(scale.Contents[0].Text, want) {
			t.Errorf("readiness scale lacks %q", want)
		}
	}
	if _, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "cipherhorizon://nothing"}); err == nil {
		t.Error("unknown resource read without error")
	}
	ps, err := cs.ListPrompts(ctx, nil)
	if err != nil || len(ps.Prompts) != 2 {
		t.Fatalf("prompts: %v, %d", err, len(ps.Prompts))
	}
	p, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "assess_endpoint", Arguments: map[string]string{"target": "ssh://bastion:22"}})
	if err != nil {
		t.Fatal(err)
	}
	if msg := p.Messages[0].Content.(*mcp.TextContent).Text; !strings.Contains(msg, "ssh_scan") {
		t.Errorf("an ssh:// target should route to ssh_scan: %s", msg)
	}
}

// REQ-MCP-3: tls_scan runs the probe and the evaluation and returns both halves.
func TestTLSScan(t *testing.T) {
	srv := tlstest.Start(t, tlstest.Config{MinVersion: tls.VersionTLS12, Cert: tlstest.CertECDSA,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}})
	cs := connect(t, mcpserver.Options{Scan: loopback()})

	res := call(t, cs, "tls_scan", map[string]any{"target": srv.Addr, "httpChecks": false})
	if res.IsError {
		t.Fatalf("error: %s", text(res))
	}
	out := structured[mcpserver.ScanResult](t, res)
	if !out.Scanned || out.Protocol != "tls" || out.Readiness == nil || out.Readiness.Level != 3 || out.Hygiene == nil || out.Hygiene.Score < 0 {
		t.Fatalf("result %+v", out)
	}
	if len(out.Standards) == 0 || out.Findings != nil || out.Full != nil {
		t.Errorf("verdict detail: standards %d, findings %d, full %v", len(out.Standards), len(out.Findings), out.Full != nil)
	}
	if !strings.HasPrefix(text(res), "VERDICT "+srv.Addr) {
		t.Errorf("text: %q", text(res))
	}

	res = call(t, cs, "tls_scan", map[string]any{"target": srv.Addr, "detail": "full", "httpChecks": false})
	out = structured[mcpserver.ScanResult](t, res)
	if len(out.Findings) == 0 || out.Full == nil {
		t.Errorf("full detail: findings %d, evaluation present %v", len(out.Findings), out.Full != nil)
	}
	raw, _ := json.Marshal(out.Full)
	var ev eval.Evaluation
	if err := json.Unmarshal(raw, &ev); err != nil || ev.Version != eval.Version {
		t.Errorf("evaluation: %v %q", err, ev.Version)
	}
}

// Input errors are tool results the model can act on, not protocol errors (REQ-MCP-7).
func TestTLSScanRefusals(t *testing.T) {
	cs := connect(t, mcpserver.Options{Scan: mcpserver.ScanOptions{Guard: server.Guard{}}})
	for name, args := range map[string]map[string]any{
		"bad detail":   {"target": "example.com", "detail": "everything"},
		"bad target":   {"target": "example.com:notaport"},
		"metadata":     {"target": "169.254.169.254"},
		"loopback":     {"target": "127.0.0.1:443"},
		"empty":        {"target": ""},
		"bad starttls": {"target": "mail.example.com:25", "starttls": "telnet"},
	} {
		res := call(t, cs, "tls_scan", args)
		if !res.IsError || text(res) == "" {
			t.Errorf("%s: want a tool error, got %+v", name, res)
		}
	}
	// A scope that does not cover the target names the refusal.
	scope, err := server.ParseScope([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	cs = connect(t, mcpserver.Options{Scan: mcpserver.ScanOptions{Guard: server.Guard{Scope: scope, AllowLoopback: true}}})
	res := call(t, cs, "tls_scan", map[string]any{"target": "127.0.0.1:443"})
	if !res.IsError || !strings.Contains(text(res), "cannot be scanned from here") {
		t.Errorf("scope: %+v", res)
	}
}

// A target that answers nothing is a result, not an error: the model is told it could not be scanned.
func TestTLSScanDeadPort(t *testing.T) {
	cs := connect(t, mcpserver.Options{Scan: loopback()})
	res := call(t, cs, "tls_scan", map[string]any{"target": "127.0.0.1:1"})
	if res.IsError {
		t.Fatalf("a dead port is a result: %s", text(res))
	}
	out := structured[mcpserver.ScanResult](t, res)
	if out.Scanned || out.Error == "" || !strings.Contains(text(res), "Could not be scanned") {
		t.Errorf("%+v / %q", out, text(res))
	}
}

// REQ-MCP-3: ssh_scan, with the baseline.
func TestSSHScan(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeCurve25519, ssh.KeyExchangeMLKEM768X25519}, Keys: []string{sshtest.KeyEd25519}})
	cs := connect(t, mcpserver.Options{Scan: loopback()})
	res := call(t, cs, "ssh_scan", map[string]any{"target": "ssh://" + srv.Addr, "detail": "findings"})
	if res.IsError {
		t.Fatalf("error: %s", text(res))
	}
	out := structured[mcpserver.ScanResult](t, res)
	if !out.Scanned || out.Protocol != "ssh" || out.Hygiene != nil || out.Baseline == nil || !out.Baseline.Judged || out.Readiness == nil || out.Readiness.Level != 3 {
		t.Fatalf("result %+v", out)
	}
	res = call(t, cs, "ssh_scan", map[string]any{"target": srv.Addr, "baseline": "no-such-baseline"})
	if !res.IsError || !strings.Contains(text(res), eval.BaselineDefault) {
		t.Errorf("unknown baseline should name the known ones: %s", text(res))
	}
}

// ---- fleet ---------------------------------------------------------------------------------------

// fakeAPI is enough of the CipherHorizon API for the fleet tools, recording what it was asked.
type fakeAPI struct {
	t        *testing.T
	token    string
	requests []string
	eval     eval.Evaluation
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":"a valid bearer token is required"}`)
		return
	}
	if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "cipherhorizon" {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"error":"missing X-Requested-With"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	level := 1
	done := map[string]any{"id": 7, "assetId": 1, "status": "done", "score": 80, "band": "Good", "readinessLevel": level, "hndlExposed": true, "critical": 0, "high": 1}
	switch {
	case r.URL.Path == "/api/v1/summary":
		write(map[string]any{"assets": 2, "days": r.URL.Query().Get("days")})
	case r.URL.Path == "/api/v1/assets" && r.Method == http.MethodGet:
		write([]map[string]any{
			{"id": 1, "kind": "tls-endpoint", "protocol": "tls", "name": "web", "address": "web.example.net:443", "host": "web.example.net", "port": 443, "tags": []string{"prod"}, "lastDone": done},
			{"id": 2, "kind": "ssh-endpoint", "protocol": "ssh", "name": "bastion", "address": "bastion.example.net:22", "host": "bastion.example.net", "port": 22, "tags": []string{}},
		})
	case r.URL.Path == "/api/v1/assets" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["target"] == "dup.example.net" {
			w.WriteHeader(409)
			_, _ = io.WriteString(w, `{"error":"dup.example.net:443 is already added"}`)
			return
		}
		w.WriteHeader(201)
		write(map[string]any{"id": 3, "kind": "tls-endpoint", "protocol": "tls", "name": body["target"], "address": body["target"].(string) + ":443", "tags": []string{}})
	case r.URL.Path == "/api/v1/assets/3/scan":
		w.WriteHeader(202)
		write(map[string]any{"scan": map[string]any{"id": 9, "assetId": 3, "status": "queued"}, "alreadyActive": false})
	case r.URL.Path == "/api/v1/assets/1":
		write(map[string]any{"id": 1, "kind": "tls-endpoint", "protocol": "tls", "name": "web", "address": "web.example.net:443", "tags": []string{"prod"}, "lastDone": done})
	case r.URL.Path == "/api/v1/assets/1/history":
		write([]map[string]any{{"id": 7, "at": "2026-11-10T00:00:00Z", "score": 80}})
	case r.URL.Path == "/api/v1/assets/99":
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":"not found"}`)
	case r.URL.Path == "/api/v1/scans" && r.Method == http.MethodPost:
		w.WriteHeader(202)
		write(map[string]any{"queued": 1, "alreadyActive": 0, "missing": 0, "scans": []map[string]any{{"id": 10, "assetId": 1, "status": "queued"}}})
	case r.URL.Path == "/api/v1/scans/7":
		write(map[string]any{"scan": done, "events": []map[string]any{{"message": "scan started"}}, "asset": map[string]any{"id": 1, "name": "web", "address": "web.example.net:443"}})
	case r.URL.Path == "/api/v1/scans/7/evaluation":
		write(f.eval)
	case r.URL.Path == "/api/v1/scans/7/cbom":
		write(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.7"})
	case r.URL.Path == "/api/v1/findings":
		write([]map[string]any{{"assetId": 1, "assetName": "web", "assetKind": "tls-endpoint", "key": "PROTO.TLS10", "title": "TLS 1.0", "severity": "high"}})
	case r.URL.Path == "/api/v1/standards/summary":
		write(map[string]any{"standards": []map[string]any{{"id": "bcp195", "meets": 1, "fails": 0}}})
	case r.URL.Path == "/api/v1/hosts":
		write([]map[string]any{{"id": 5, "kind": "host", "name": "web-01", "summary": map[string]any{"big": "tables"}}})
	case r.URL.Path == "/api/v1/hosts/5":
		write(map[string]any{"host": map[string]any{"id": 5, "name": "web-01"}, "history": []any{}})
	case r.URL.Path == "/api/v1/inventory/summary":
		write(map[string]any{"algorithm": 12, "quantumVulnerable": 4})
	case r.URL.Path == "/api/v1/inventory/dashboard":
		write(map[string]any{"ok": true})
	default:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":"no such API endpoint"}`)
	}
}

func fleetSession(t *testing.T, readOnly bool) (*mcp.ClientSession, *fakeAPI) {
	t.Helper()
	ev := eval.Evaluation{Version: eval.Version, Readiness: eval.Readiness{Level: 1, Label: eval.LevelLabel(1), HNDLExposed: true},
		Hygiene: eval.Hygiene{Score: 80, Band: "Good"}, Counts: map[eval.Severity]int{eval.High: 1},
		Findings: []eval.Finding{{ID: "PROTO.TLS10", Title: "TLS 1.0 accepted", Severity: eval.High, Remediation: "Turn it off"}}, FixFirst: []string{"PROTO.TLS10"},
		Standards: []eval.StandardResult{{ID: "bcp195", Title: "BCP 195", Verdict: eval.StdFails, MustFailures: 1,
			Requirements: []eval.RequirementResult{{Clause: "3.1.1", Text: "No TLS 1.0", Level: eval.LevelMust, Status: eval.ReqNotMet}}}}}
	api := &fakeAPI{t: t, token: "secret-token", eval: ev}
	hs := httptest.NewServer(api)
	t.Cleanup(hs.Close)
	cs := connect(t, mcpserver.Options{NoScan: true, ReadOnly: readOnly, Fleet: &mcpserver.Fleet{Base: hs.URL, Token: "secret-token"}})
	return cs, api
}

// REQ-MCP-5: the fleet tools are thin, typed calls on the API, bounded and paged.
func TestFleetTools(t *testing.T) {
	cs, api := fleetSession(t, false)

	res := call(t, cs, "fleet_summary", map[string]any{"days": 7})
	if res.IsError || structured[map[string]any](t, res)["days"] != "7" {
		t.Errorf("fleet_summary: %+v", res)
	}

	res = call(t, cs, "endpoints_list", map[string]any{"limit": 1})
	list := structured[mcpserver.ListResult[map[string]any]](t, res)
	if list.Total != 2 || len(list.Items) != 1 || !list.Truncated || list.Items[0]["name"] != "web" {
		t.Errorf("endpoints_list page: %+v", list)
	}
	res = call(t, cs, "endpoints_list", map[string]any{"only": "never-scanned"})
	list = structured[mcpserver.ListResult[map[string]any]](t, res)
	if list.Total != 1 || list.Items[0]["name"] != "bastion" {
		t.Errorf("never-scanned: %+v", list)
	}
	res = call(t, cs, "endpoints_list", map[string]any{"only": "hndl-exposed", "tag": "prod", "protocol": "tls"})
	if list = structured[mcpserver.ListResult[map[string]any]](t, res); list.Total != 1 {
		t.Errorf("filters: %+v", list)
	}
	if res = call(t, cs, "endpoints_list", map[string]any{"only": "best"}); !res.IsError {
		t.Error("bad only accepted")
	}

	res = call(t, cs, "endpoint_get", map[string]any{"id": 1, "detail": "findings"})
	if res.IsError {
		t.Fatalf("endpoint_get: %s", text(res))
	}
	ep := structured[mcpserver.EndpointResult](t, res)
	if ep.Verdict == nil || ep.Verdict.Readiness.Level != 1 || ep.Verdict.Hygiene.Score != 80 || len(ep.Verdict.Findings) != 1 || len(ep.Verdict.Clauses) != 1 || len(ep.History) != 1 {
		t.Errorf("endpoint_get: %+v", ep)
	}
	if !strings.HasPrefix(text(res), "VERDICT web.example.net:443") {
		t.Errorf("endpoint_get text: %q", text(res))
	}
	if res = call(t, cs, "endpoint_get", map[string]any{"id": 99}); !res.IsError || !strings.Contains(text(res), "not found") {
		t.Errorf("missing endpoint: %+v", res)
	}

	res = call(t, cs, "endpoint_add", map[string]any{"target": "new.example.net", "scan": true})
	if res.IsError || !strings.Contains(text(res), "Scan 9 queued") {
		t.Errorf("endpoint_add: %s", text(res))
	}
	if res = call(t, cs, "endpoint_add", map[string]any{"target": "dup.example.net"}); !res.IsError || !strings.Contains(text(res), "already added") {
		t.Errorf("duplicate: %s", text(res))
	}

	res = call(t, cs, "scan_start", map[string]any{"endpointIds": []int64{1}})
	if st := structured[mcpserver.ScanStartResult](t, res); res.IsError || st.Queued != 1 {
		t.Errorf("scan_start: %+v", res)
	}
	if res = call(t, cs, "scan_start", map[string]any{}); !res.IsError {
		t.Error("scan_start with nothing selected accepted")
	}

	res = call(t, cs, "scan_get", map[string]any{"id": 7, "detail": "verdict"})
	sg := structured[mcpserver.ScanGetResult](t, res)
	if res.IsError || sg.Scan.Status != "done" || sg.Verdict == nil || sg.Verdict.Readiness.Level != 1 || len(sg.Events) != 1 {
		t.Errorf("scan_get: %+v %s", sg, text(res))
	}

	res = call(t, cs, "findings_list", map[string]any{"severity": "high", "protocol": "tls"})
	fl := structured[mcpserver.ListResult[mcpserver.FlatFinding]](t, res)
	if fl.Total != 1 || fl.Items[0].Key != "PROTO.TLS10" {
		t.Errorf("findings_list: %+v", fl)
	}
	if res = call(t, cs, "standards_summary", map[string]any{}); res.IsError {
		t.Errorf("standards_summary: %s", text(res))
	}
	res = call(t, cs, "machines_list", map[string]any{"query": "web"})
	ml := structured[mcpserver.ListResult[map[string]any]](t, res)
	if ml.Total != 1 || ml.Items[0]["summary"] != nil {
		t.Errorf("machines_list should drop the per-machine tables: %+v", ml)
	}
	if res = call(t, cs, "machine_get", map[string]any{"id": 5}); res.IsError {
		t.Errorf("machine_get: %s", text(res))
	}
	res = call(t, cs, "inventory_summary", map[string]any{})
	if inv := structured[map[string]any](t, res); res.IsError || inv["dashboard"] == nil {
		t.Errorf("inventory_summary: %+v", inv)
	}
	res = call(t, cs, "cbom_get", map[string]any{"scanId": 7})
	if cb := structured[mcpserver.CBOMResult](t, res); res.IsError || cb.MIMEType != "application/vnd.cyclonedx+json" || cb.Document == nil {
		t.Errorf("cbom_get: %+v", cb)
	}
	if res = call(t, cs, "cbom_get", map[string]any{}); !res.IsError {
		t.Error("cbom_get with nothing named accepted")
	}

	for _, want := range []string{"GET /api/v1/summary?days=7", "GET /api/v1/assets?kind=endpoint", "GET /api/v1/assets?kind=tls-endpoint",
		"POST /api/v1/assets", "POST /api/v1/assets/3/scan", "POST /api/v1/scans", "GET /api/v1/findings?kind=tls-endpoint&severity=high"} {
		if !contains(api.requests, want) {
			t.Errorf("the API never saw %q; it saw %v", want, api.requests)
		}
	}
}

// REQ-MCP-6: read-only leaves nothing that can write, and the token error is explained.
func TestFleetReadOnlyAndAuth(t *testing.T) {
	cs, _ := fleetSession(t, true)
	for _, name := range toolNames(t, cs) {
		if name == "endpoint_add" || name == "scan_start" {
			t.Errorf("%s offered in read-only mode", name)
		}
	}
	ctx := context.Background()
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "scan_start", Arguments: map[string]any{"all": true}}); err == nil {
		t.Error("scan_start callable although not offered")
	}

	hs := httptest.NewServer(&fakeAPI{t: t, token: "right"})
	defer hs.Close()
	bad := connect(t, mcpserver.Options{NoScan: true, Fleet: &mcpserver.Fleet{Base: hs.URL, Token: "wrong"}})
	res := call(t, bad, "fleet_summary", map[string]any{})
	if !res.IsError || !strings.Contains(text(res), "check the token") {
		t.Errorf("wrong token: %s", text(res))
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// REQ-MCP-2: the Streamable HTTP handler, with a key, end to end through the SDK's client.
func TestHTTPHandler(t *testing.T) {
	srv := mcpserver.New(mcpserver.Options{Version: "test", NoScan: true})
	hs := httptest.NewServer(srv.Handler(mcpserver.HTTPOptions{Key: "0123456789abcdef"}))
	defer hs.Close()

	post := func(h http.Header) int {
		req, _ := http.NewRequest(http.MethodPost, hs.URL+"/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for k, v := range h {
			req.Header[k] = v
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(nil); code != http.StatusUnauthorized {
		t.Errorf("no key: %d", code)
	}
	if code := post(http.Header{"Authorization": {"Bearer wrong-wrong-wrong"}}); code != http.StatusUnauthorized {
		t.Errorf("wrong key: %d", code)
	}
	if code := post(http.Header{"Authorization": {"Bearer 0123456789abcdef"}, "Origin": {"https://evil.example"}}); code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", code)
	}
	if code := post(http.Header{"Authorization": {"Bearer 0123456789abcdef"}, "Sec-Fetch-Site": {"cross-site"}}); code != http.StatusForbidden {
		t.Errorf("cross-site: %d", code)
	}

	client := &http.Client{Transport: headerTransport{key: "0123456789abcdef"}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: hs.URL, HTTPClient: client}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close() //nolint:errcheck // test
	names := toolNames(t, cs)
	if len(names) != 0 {
		t.Errorf("no-scan, no fleet: tools %v", names)
	}
	rs, err := cs.ListResources(context.Background(), nil)
	if err != nil || len(rs.Resources) != 4 {
		t.Errorf("resources over HTTP: %v %d", err, len(rs.Resources))
	}
}

type headerTransport struct{ key string }

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+h.key)
	return http.DefaultTransport.RoundTrip(r)
}

// REQ-MCP-9: with ForwardCredentials the fleet client sends the caller's own headers, not a token.
func TestForwardCredentials(t *testing.T) {
	var seen http.Header
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"assets":1}`)
	}))
	defer api.Close()
	srv := mcpserver.New(mcpserver.Options{Version: "test", NoScan: true, Fleet: &mcpserver.Fleet{Base: api.URL}})
	hs := httptest.NewServer(srv.Handler(mcpserver.HTTPOptions{ForwardCredentials: true}))
	defer hs.Close()
	client := &http.Client{Transport: cookieTransport{}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: hs.URL, HTTPClient: client}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close() //nolint:errcheck // test
	if res := call(t, cs, "fleet_summary", map[string]any{}); res.IsError {
		t.Fatalf("fleet_summary: %s", text(res))
	}
	if seen.Get("Cookie") != "ch_session=abc" || seen.Get("Authorization") != "Bearer caller" || seen.Get("X-Requested-With") != "cipherhorizon" {
		t.Errorf("the API saw %v", seen)
	}
}

type cookieTransport struct{}

func (cookieTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Cookie", "ch_session=abc")
	r.Header.Set("Authorization", "Bearer caller")
	return http.DefaultTransport.RoundTrip(r)
}
