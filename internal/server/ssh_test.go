package server_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	sshtest "github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"golang.org/x/crypto/ssh"
)

type sshAssetJSON struct {
	assetJSON
	Kind     string `json:"kind"`
	Protocol string `json:"protocol"`
	StartTLS string `json:"starttls"`
}

// REQ-SHW-1: ssh://, port 22 with Automatic, and an explicit choice make an SSH endpoint; anything
// else stays TLS; STARTTLS and SSH do not mix.
func TestSSHTargetsAreRecognised(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		body           map[string]any
		kind, protocol string
		port           int
	}{
		{map[string]any{"target": "ssh://bastion.example.com"}, "ssh-endpoint", "ssh", 22},
		{map[string]any{"target": "ssh://bastion2.example.com:2222"}, "ssh-endpoint", "ssh", 2222},
		{map[string]any{"target": "jump.example.com:22"}, "ssh-endpoint", "ssh", 22},
		{map[string]any{"target": "git.example.com:2200", "protocol": "ssh"}, "ssh-endpoint", "ssh", 2200},
		{map[string]any{"target": "git2.example.com", "protocol": "ssh"}, "ssh-endpoint", "ssh", 22},
		{map[string]any{"target": "odd.example.com:22", "protocol": "tls"}, "tls-endpoint", "tls", 22},
		{map[string]any{"target": "web.example.com"}, "tls-endpoint", "tls", 443},
	} {
		var a sshAssetJSON
		if s := e.call("POST", "/api/v1/assets", tc.body, &a); s != 201 || a.Kind != tc.kind || a.Protocol != tc.protocol || a.Port != tc.port {
			t.Errorf("%v: %d %+v", tc.body, s, a)
		}
	}
	// The same host and port may be both a TLS and an SSH endpoint (two kinds), but not twice as SSH.
	if s, _ := e.do("POST", "/api/v1/assets", map[string]any{"target": "ssh://jump.example.com"}); s != 409 {
		t.Errorf("duplicate SSH endpoint: %d", s)
	}
	for _, bad := range []map[string]any{
		{"target": "ssh://x.example.com", "protocol": "tls"},
		{"target": "x.example.com", "protocol": "ssh", "starttls": "smtp"},
		{"target": "x.example.com", "protocol": "telnet"},
	} {
		if s, _ := e.do("POST", "/api/v1/assets", bad); s != 400 {
			t.Errorf("%v: %d, want 400", bad, s)
		}
	}
	// STARTTLS cannot be set on an SSH endpoint afterwards either.
	var a sshAssetJSON
	e.call("POST", "/api/v1/assets", map[string]any{"target": "ssh://patch.example.com"}, &a)
	if s, _ := e.do("PATCH", "/api/v1/assets/"+itoa(a.ID), map[string]any{"starttls": "smtp"}); s != 400 {
		t.Errorf("STARTTLS on an SSH endpoint: %d", s)
	}
	// Bulk add takes ssh:// lines.
	var bulk struct {
		Added int `json:"added"`
	}
	if s := e.call("POST", "/api/v1/assets/bulk", map[string]any{"text": "ssh://b1.example.com\nb2.example.com:22\nweb2.example.com"}, &bulk); s != 200 || bulk.Added != 3 {
		t.Errorf("bulk: %d %+v", s, bulk)
	}
}

// REQ-SHW-5, REQ-SHE-1, REQ-SHO-2/3: an SSH endpoint goes through the whole product: scan,
// list, report, evaluation, CBOM, PDF, findings, fleet, history, CSV.
func TestSSHEndpointWorkflow(t *testing.T) {
	e := newEnv(t)
	srv := sshtest.Start(t, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeCurve25519, ssh.InsecureKeyExchangeDH14SHA1},
		Ciphers: []string{ssh.CipherAES128CTR, ssh.InsecureCipherAES128CBC}, Keys: []string{sshtest.KeyEd25519, sshtest.KeyRSA}})
	var a sshAssetJSON
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "ssh://" + srv.Addr}, &a); s != 201 || a.Protocol != "ssh" {
		t.Fatalf("add: %d %+v", s, a)
	}
	sc := e.scanAndWait(a.ID)
	if sc.Status != "done" || sc.Level == nil || *sc.Level != eval.LevelExposed || !sc.HNDL {
		t.Fatalf("scan %+v", sc)
	}

	// The list shows the software and host key; the evaluation is the SSH shape.
	var list []struct {
		Protocol string `json:"protocol"`
		LastDone struct {
			Service string `json:"service"`
			HostKey string `json:"hostKey"`
		} `json:"lastDone"`
	}
	if s := e.call("GET", "/api/v1/assets?kind=endpoint", nil, &list); s != 200 || len(list) != 1 ||
		list[0].Protocol != "ssh" || list[0].LastDone.Service == "" || list[0].LastDone.HostKey == "" {
		t.Fatalf("list: %d %+v", s, list)
	}
	var ev eval.Evaluation
	if s := e.call("GET", "/api/v1/scans/"+itoa(sc.ID)+"/evaluation", nil, &ev); s != 200 || ev.Protocol != "ssh" {
		t.Fatalf("evaluation: %d protocol %q", s, ev.Protocol)
	}
	has := map[string]bool{}
	for _, f := range ev.Findings {
		has[f.ID] = true
	}
	for _, id := range []string{"SSH.KEX-SHA1", "SSH.CIPHER-CBC", "PQC.HNDL-EXPOSED"} {
		if !has[id] {
			t.Errorf("%s missing from %v", id, has)
		}
	}

	// CBOM and PDF.
	status, body := e.do("GET", "/api/v1/scans/"+itoa(sc.ID)+"/cbom", nil)
	if status != 200 || !strings.Contains(string(body), `"ssh"`) || !strings.Contains(string(body), "X25519") {
		t.Errorf("cbom: %d %.300s", status, body)
	}
	status, body = e.do("GET", "/api/v1/scans/"+itoa(sc.ID)+"/report.pdf", nil)
	if status != 200 || !bytes.HasPrefix(body, []byte("%PDF")) {
		t.Errorf("pdf: %d", status)
	}

	// Findings across the fleet, the summary, the inventory and the CSV include it.
	_, body = e.do("GET", "/api/v1/findings", nil)
	if !strings.Contains(string(body), "PQC.HNDL-EXPOSED") || !strings.Contains(string(body), "SSH.CIPHER-CBC") {
		t.Errorf("fleet findings: %.400s", body)
	}
	var fleet struct {
		Assets      int         `json:"assets"`
		Scanned     int         `json:"scanned"`
		HNDLExposed int         `json:"hndlExposed"`
		Readiness   map[int]int `json:"readiness"`
	}
	if s := e.call("GET", "/api/v1/summary", nil, &fleet); s != 200 || fleet.Assets != 1 || fleet.Scanned != 1 || fleet.HNDLExposed != 1 || fleet.Readiness[1] != 1 {
		t.Errorf("summary: %d %+v", s, fleet)
	}
	_, body = e.do("GET", "/api/v1/inventory/cbom", nil)
	if !strings.Contains(string(body), "protocol/ssh/2.0") {
		t.Errorf("inventory CBOM has no SSH protocol: %.300s", body)
	}
	_, body = e.do("GET", "/api/v1/export/assets.csv", nil)
	if !strings.Contains(string(body), ",ssh,") {
		t.Errorf("csv: %s", body)
	}

	// History: a second scan compares as SSH.
	e.scanAndWait(a.ID)
	var diff struct {
		Diff eval.Diff `json:"diff"`
	}
	if s := e.call("GET", "/api/v1/assets/"+itoa(a.ID)+"/diff", nil, &diff); s != 200 || diff.Diff.Summary == "" {
		t.Errorf("diff: %d %+v", s, diff)
	}
	// Re-evaluation keeps the SSH shape.
	if s, body := e.do("POST", "/api/v1/scans/"+itoa(sc.ID)+"/reevaluate", map[string]any{}); s != 200 || !strings.Contains(string(body), `"ssh"`) {
		t.Errorf("reevaluate: %d %.200s", s, body)
	}
}

// REQ-SHO-5: an SSH scan projects into the estate graph.
func TestSSHScanProjectsIntoTheGraph(t *testing.T) {
	e := newEnv(t)
	srv := sshtest.Start(t, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519}})
	a := e.addAsset("ssh://" + srv.Addr)
	if sc := e.scanAndWait(a.ID); sc.Status != "done" {
		t.Fatalf("%+v", sc)
	}
	_, body := e.do("GET", "/api/v1/entities?kind=protocol", nil)
	if !strings.Contains(string(body), "SSH-2.0") {
		t.Errorf("no SSH protocol entity: %.300s", body)
	}
	_, body = e.do("GET", "/api/v1/entities?kind=algorithm", nil)
	if !strings.Contains(string(body), "mlkem768x25519-sha256") {
		t.Errorf("no hybrid kex entity: %.300s", body)
	}
}

// A port that is not SSH fails with the reason, not a hang.
func TestSSHScanOfANonSSHPortFails(t *testing.T) {
	e := newEnv(t)
	tlsSrv := hybridServer(t)
	var a sshAssetJSON
	e.call("POST", "/api/v1/assets", map[string]any{"target": tlsSrv.Addr, "protocol": "ssh"}, &a)
	sc := e.scanAndWait(a.ID)
	if sc.Status != "failed" || !strings.Contains(sc.Error, "SSH identification") {
		t.Errorf("scan %+v", sc)
	}
}

// REQ-SHO-6: the API document describes SSH endpoints.
func TestOpenAPIDescribesSSH(t *testing.T) {
	e := newEnv(t)
	_, body := e.do("GET", "/api/v1/openapi.json", nil)
	for _, want := range []string{`"ssh-endpoint"`, `"protocol"`, "ssh-report/1", "ssh://"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("openapi.json lacks %s", want)
		}
	}
}
