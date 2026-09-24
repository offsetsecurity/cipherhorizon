package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/server"
	"github.com/example/cipherhorizon/internal/store"
	"github.com/example/cipherhorizon/internal/tlsprobe"
	"github.com/example/cipherhorizon/internal/tlsprobe/testserver"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type envCfg struct {
	token         string
	allowLoopback bool
	workers       int
	sched         time.Duration
	clock         *fakeClock
	allowedHosts  []string
}

type envOpt func(*envCfg)

func withToken(tok string) envOpt          { return func(c *envCfg) { c.token = tok } }
func noLoopback() envOpt                   { return func(c *envCfg) { c.allowLoopback = false } }
func withWorkers(n int) envOpt             { return func(c *envCfg) { c.workers = n } }
func withClock(fc *fakeClock) envOpt       { return func(c *envCfg) { c.clock = fc } }
func withScheduler(d time.Duration) envOpt { return func(c *envCfg) { c.sched = d } }

// env is a complete server: real store, real scanner, real HTTP.
type env struct {
	t      *testing.T
	st     *store.Store
	ts     *httptest.Server
	runner *server.Runner
	token  string
}

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	cfg := &envCfg{allowLoopback: true, workers: 2}
	for _, o := range opts {
		o(cfg)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	guard := server.Guard{AllowLoopback: cfg.allowLoopback}
	ro := server.RunnerOptions{Workers: cfg.workers, SchedulerInterval: cfg.sched,
		Scan: tlsprobe.Options{Timeout: 3 * time.Second, Concurrency: 8}}
	if cfg.clock != nil {
		ro.Now = cfg.clock.Now
		st.SetClock(cfg.clock.Now)
	}
	runner := server.NewRunner(st, guard, ro)
	ctx, cancel := context.WithCancel(context.Background())
	runner.Start(ctx)

	srv := server.New(server.Config{Store: st, Runner: runner, Guard: guard, Token: cfg.token, AllowedHosts: cfg.allowedHosts,
		Version: "test", RegistryRetrieved: "2026-09-21", EvalVersion: "eval/1", MaxConcurrentScans: cfg.workers})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		cancel()
		runner.Wait()
		_ = st.Close()
	})
	return &env{t: t, st: st, ts: ts, runner: runner, token: cfg.token}
}

func (e *env) req(method, path string, body any, hdr map[string]string) (int, []byte, http.Header) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = bytes.NewReader([]byte(s))
		} else {
			b, err := json.Marshal(body)
			if err != nil {
				e.t.Fatal(err)
			}
			rd = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, e.ts.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("X-Requested-With", "cipherhorizon")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (e *env) do(method, path string, body any) (int, []byte) {
	s, b, _ := e.req(method, path, body, nil)
	return s, b
}

// call performs a request and decodes a JSON response into out.
func (e *env) call(method, path string, body, out any) int {
	e.t.Helper()
	status, b := e.do(method, path, body)
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: response is not JSON: %v\n%s", method, path, err, b)
		}
	}
	return status
}

type assetJSON struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	Address        string    `json:"address"`
	Tags           []string  `json:"tags"`
	Notes          string    `json:"notes"`
	Interval       int       `json:"intervalSeconds"`
	Next           *string   `json:"nextScanAt"`
	Latest         *scanJSON `json:"latest"`
	LastDone       *scanJSON `json:"lastDone"`
	LinkedAssetIDs []int64   `json:"linkedAssetIds"`
}

type scanJSON struct {
	ID          int64  `json:"id"`
	AssetID     int64  `json:"assetId"`
	Status      string `json:"status"`
	Trigger     string `json:"trigger"`
	Stage       string `json:"stage"`
	ProgressPct int    `json:"progressPct"`
	Connections int    `json:"connections"`
	Error       string `json:"error"`
	Band        string `json:"band"`
	Level       *int   `json:"readinessLevel"`
	HNDL        bool   `json:"hndlExposed"`
	Critical    int    `json:"critical"`
	High        int    `json:"high"`
	Incomplete  bool   `json:"incomplete"`
}

func (e *env) addAsset(target string) assetJSON {
	e.t.Helper()
	var a assetJSON
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": target}, &a); s != http.StatusCreated {
		e.t.Fatalf("add %s: status %d", target, s)
	}
	return a
}

func (e *env) startScan(assetID int64) scanJSON {
	e.t.Helper()
	var out struct {
		Scan          scanJSON `json:"scan"`
		AlreadyActive bool     `json:"alreadyActive"`
	}
	if s := e.call("POST", "/api/v1/assets/"+itoa(assetID)+"/scan", nil, &out); s != http.StatusAccepted && s != http.StatusOK {
		e.t.Fatalf("scan asset %d: status %d", assetID, s)
	}
	return out.Scan
}

func (e *env) getScan(id int64) scanJSON {
	e.t.Helper()
	var out struct {
		Scan scanJSON `json:"scan"`
	}
	if s := e.call("GET", "/api/v1/scans/"+itoa(id), nil, &out); s != 200 {
		e.t.Fatalf("get scan %d: %d", id, s)
	}
	return out.Scan
}

// wait polls until the scan reaches a final status.
func (e *env) wait(id int64) scanJSON {
	e.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		sc := e.getScan(id)
		switch sc.Status {
		case "done", "failed", "canceled":
			return sc
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("scan %d did not finish", id)
	return scanJSON{}
}

// scanAndWait adds nothing: it scans an existing asset and waits.
func (e *env) scanAndWait(assetID int64) scanJSON { return e.wait(e.startScan(assetID).ID) }

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ---- target servers -------------------------------------------------------------------------------

func hybridServer(t *testing.T) *testserver.Server {
	return testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}})
}

func classicalServer(t *testing.T) *testserver.Server {
	return testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13, Curves: []tls.CurveID{tls.X25519, tls.CurveP256}})
}

func tls12Server(t *testing.T) *testserver.Server {
	return testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
}

// slowProxy forwards to target after a delay per connection, so a scan takes long
// enough to observe while it runs.
func slowProxy(t *testing.T, target string, delay time.Duration) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // test proxy
				time.Sleep(delay)
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close() //nolint:errcheck // test proxy
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return l.Addr().String()
}

func deadPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func mustJSON(t *testing.T, raw []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
}
