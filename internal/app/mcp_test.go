package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// startMCPServe runs serve with the MCP flags and returns its base URL; the existing startServe
// helper stops it when the test ends.
func startMCPServe(t *testing.T, extra ...string) string {
	t.Helper()
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	return "http://" + startServe(t, append([]string{"--addr", "127.0.0.1:0", "--allow-loopback"}, extra...)...)
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func mcpClient(t *testing.T, base, token string) *mcp.ClientSession {
	t.Helper()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: &http.Client{Transport: bearer{token}}}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args any) (*mcp.CallToolResult, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return res, b.String()
}

// PRD-020 REQ-MCP-9: serve --mcp serves the fleet tools at /mcp behind the server's own token, and
// each tool's API call is made as the caller, so the whole flow (add, scan, follow, read) works
// through MCP alone against the real server.
func TestServeMCP(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Cert: testserver.CertECDSA,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}})
	base := startMCPServe(t, "--mcp", "--mcp-scan", "--token", "s3cret-token-0123456789", "--http-checks=false")

	// Without the token /mcp answers as the API does; with a bad one too.
	for _, tok := range []string{"", "wrong-token-0123456789"} {
		req, _ := http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: %d, want 401", tok, resp.StatusCode)
		}
	}
	// A foreign Origin is refused even with the token (a browser page cannot be an MCP client).
	req, _ := http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer s3cret-token-0123456789")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign origin: %d", resp.StatusCode)
	}

	cs := mcpClient(t, base, "s3cret-token-0123456789")
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"tls_scan", "ssh_scan", "fleet_summary", "endpoints_list", "endpoint_add", "scan_start", "scan_get", "cbom_get"} {
		if !names[want] {
			t.Errorf("tool %s missing; have %v", want, names)
		}
	}

	// Add the test server as an endpoint and queue its first scan.
	res, txt := callTool(t, cs, "endpoint_add", map[string]any{"target": srv.Addr, "name": "hybrid", "scan": true})
	if res.IsError {
		t.Fatalf("endpoint_add: %s", txt)
	}
	var added struct {
		Endpoint struct {
			ID     int64 `json:"id"`
			Latest *struct {
				ID int64 `json:"id"`
			} `json:"latest"`
		} `json:"endpoint"`
	}
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &added); err != nil || added.Endpoint.ID == 0 || added.Endpoint.Latest == nil {
		t.Fatalf("endpoint_add result: %v %s", err, raw)
	}
	if res, txt = callTool(t, cs, "endpoint_add", map[string]any{"target": srv.Addr}); !res.IsError || !strings.Contains(txt, "already added") {
		t.Errorf("duplicate add: %v %s", res.IsError, txt)
	}

	// Follow the scan to completion.
	var status string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		res, _ = callTool(t, cs, "scan_get", map[string]any{"id": added.Endpoint.Latest.ID})
		var got struct {
			Scan struct {
				Status string `json:"status"`
			} `json:"scan"`
		}
		raw, _ = json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(raw, &got)
		status = got.Scan.Status
		if status == "done" || status == "failed" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if status != "done" {
		t.Fatalf("scan ended %q", status)
	}
	res, txt = callTool(t, cs, "scan_get", map[string]any{"id": added.Endpoint.Latest.ID, "detail": "findings"})
	var sg struct {
		Verdict *struct {
			Readiness struct {
				Level int `json:"level"`
			} `json:"readiness"`
			Findings []any `json:"findings"`
		} `json:"verdict"`
	}
	raw, _ = json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &sg)
	if res.IsError || sg.Verdict == nil || sg.Verdict.Readiness.Level != 3 || !strings.Contains(txt, "L3") {
		t.Errorf("scan_get verdict: %v %s\n%s", res.IsError, raw, txt)
	}

	// The endpoint now carries the verdict; the list filters see it; the CBOM is the scan's.
	res, _ = callTool(t, cs, "endpoints_list", map[string]any{"only": "never-scanned"})
	raw, _ = json.Marshal(res.StructuredContent)
	if !bytes.Contains(raw, []byte(`"total":0`)) {
		t.Errorf("never-scanned after a scan: %s", raw)
	}
	res, txt = callTool(t, cs, "cbom_get", map[string]any{"scanId": added.Endpoint.Latest.ID})
	if res.IsError || !strings.Contains(txt, `"bomFormat"`) {
		t.Errorf("cbom_get: %v %.200s", res.IsError, txt)
	}
	if res, txt = callTool(t, cs, "fleet_summary", map[string]any{}); res.IsError {
		t.Errorf("fleet_summary: %s", txt)
	}

	// --mcp-scan: an ad-hoc scan from the server, within its scope (loopback allowed here).
	res, txt = callTool(t, cs, "tls_scan", map[string]any{"target": srv.Addr, "httpChecks": false})
	if res.IsError || !strings.Contains(txt, "L3") {
		t.Errorf("tls_scan through serve: %v %.300s", res.IsError, txt)
	}
	// The resources are there too.
	if rs, err := cs.ListResources(context.Background(), nil); err != nil || len(rs.Resources) != 4 {
		t.Errorf("resources: %v", err)
	}
}

// Without --mcp-scan the server offers no ad-hoc scan; without --mcp nothing is at /mcp.
func TestServeMCPOptions(t *testing.T) {
	base := startMCPServe(t, "--mcp", "--token", "s3cret-token-0123456789")
	cs := mcpClient(t, base, "s3cret-token-0123456789")
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if strings.HasSuffix(tool.Name, "_scan") {
			t.Errorf("%s offered without --mcp-scan", tool.Name)
		}
	}
	_ = cs.Close()

	base = startMCPServe(t)
	resp, err := http.Post(base+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Errorf("/mcp answered without --mcp: %d", resp.StatusCode)
	}
}

// The mcp command's own refusals and its stdio start.
func TestMCPCommandFlags(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	t.Setenv("CIPHERHORIZON_MCP_KEY", "")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"mcp", "extra"}, "takes no arguments"},
		{[]string{"mcp", "--server", "ftp://x"}, "http:// or https://"},
		{[]string{"mcp", "--server", "http://ch.example.net", "--token", "t"}, "unencrypted"},
		{[]string{"mcp", "--listen", "0.0.0.0:0"}, "no key is set"},
		{[]string{"mcp", "--listen", "127.0.0.1:0", "--key", "short"}, "at least 16 characters"},
		{[]string{"mcp", "--listen", "nonsense"}, "HOST:PORT"},
		{[]string{"mcp", "--scan-allow", "not a scope!"}, "scan scope"},
	}
	for _, tc := range cases {
		var errb bytes.Buffer
		code := app.Main(context.Background(), tc.args, app.Env{Stdout: io.Discard, Stderr: &errb})
		if code != app.ExitFatal || !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: exit %d, stderr %q; want %q", tc.args, code, errb.String(), tc.want)
		}
	}
	var out bytes.Buffer
	if code := app.Main(context.Background(), []string{"mcp", "-h"}, app.Env{Stdout: io.Discard, Stderr: &out}); code != app.ExitOK || !strings.Contains(out.String(), "claude mcp add") {
		t.Errorf("mcp -h: %d %q", code, out.String())
	}
}

// The HTTP transport of the mcp command, end to end with a key.
func TestMCPCommandListen(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	ctx, cancel := context.WithCancel(context.Background())
	errb := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- app.Main(ctx, []string{"mcp", "--listen", "127.0.0.1:0", "--key", "0123456789abcdef", "--allow-loopback"}, app.Env{Stdout: io.Discard, Stderr: errb})
	}()
	re := regexp.MustCompile(`http://(127\.0\.0\.1:\d+)/mcp`)
	var base string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(errb.String()); m != nil {
			base = "http://" + m[1]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if base == "" {
		cancel()
		t.Fatalf("no address announced: %s", errb.String())
	}
	if _, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: &http.Client{Transport: bearer{"wrong-wrong-wrong-wrong"}}}, nil); err == nil {
		t.Error("connected with a wrong key")
	}
	cs := mcpClient(t, base, "0123456789abcdef")
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 2 {
		t.Errorf("tools: %v %d", err, len(tools.Tools))
	}
	resp, err := http.Get(base + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Errorf("healthz: %v", err)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	cancel()
	select {
	case code := <-done:
		if code != app.ExitOK {
			t.Errorf("exit %d: %s", code, errb.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("did not stop")
	}
}
