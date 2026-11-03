package server_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pki/pkitest"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

type evalT1 struct {
	Version  string `json:"version"`
	Findings []struct {
		ID string `json:"id"`
	} `json:"findings"`
	PKI []struct {
		Private *struct {
			Trusted bool `json:"trusted"`
		} `json:"private"`
	} `json:"pki"`
	Sections []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"sections"`
}

func (ev evalT1) has(id string) bool {
	for _, f := range ev.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// TestPrivateCATrustAnchors is REQ-TTRS-2 / SR-20 end to end: a scan of an
// endpoint with a private CA is untrusted; adding the CA to the system's bundle
// re-evaluates it as trusted without a rescan; removing it reverses that; key
// blocks and non-CA certificates are refused.
func TestPrivateCATrustAnchors(t *testing.T) {
	e := newEnv(t)
	root := pkitest.NewRoot(t, "Corp Root", pkitest.CAOpts{NotBefore: pkitest.Epoch.AddDate(-5, 0, 0), NotAfter: pkitest.Epoch.AddDate(20, 0, 0)})
	leaf := root.TLS(t, pkitest.LeafOpts{IPs: []net.IP{net.ParseIP("127.0.0.1")}, DNS: []string{"leaf.test"},
		NotBefore: pkitest.Epoch.AddDate(-1, 0, 0).AddDate(0, 4, 0), NotAfter: pkitest.Epoch.AddDate(2, 0, 0)})
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{leaf}})
	a := e.addAsset(srv.Addr)
	sc := e.scanAndWait(a.ID)
	if sc.Status != "done" {
		t.Fatalf("scan %+v", sc)
	}
	evaluation := func() evalT1 {
		var ev evalT1
		if s := e.call("GET", "/api/v1/scans/"+itoa(sc.ID)+"/evaluation", nil, &ev); s != 200 {
			t.Fatalf("evaluation: %d", s)
		}
		return ev
	}
	if ev := evaluation(); ev.Version != eval.Version || !ev.has("CERT.UNTRUSTED") || len(ev.Sections) == 0 {
		t.Fatalf("before the bundle: %+v", ev)
	}

	// REQ-TCRT-7: the extension facts reach the estate's certificate entity and its API.
	var cert struct {
		Certificate struct {
			ExtKeyUsage  string `json:"extKeyUsage"`
			LifetimeDays string `json:"lifetimeDays"`
		} `json:"certificate"`
	}
	fp := pemFingerprint(leaf.Leaf)
	if s := e.call("GET", "/api/v1/certificates/"+fp, nil, &cert); s != 200 || cert.Certificate.ExtKeyUsage != "serverAuth" || cert.Certificate.LifetimeDays == "" {
		t.Errorf("certificate entity facts: %d %+v", s, cert)
	}

	asset, err := e.st.GetAsset(a.ID)
	if err != nil || asset.SystemID == 0 {
		t.Fatalf("asset has no system: %+v %v", asset, err)
	}
	path := "/api/v1/systems/" + itoa(asset.SystemID) + "/trust-anchors"

	// Refusals: a key block anywhere, a non-CA certificate, nothing at all, too big.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kder, _ := x509.MarshalECPrivateKey(k)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
	for name, body := range map[string]string{
		"key block":     pemOf(root.Cert) + keyPEM,
		"leaf (not CA)": pemOf(leaf.Leaf),
		"no blocks":     "hello",
	} {
		var out map[string]any
		if s := e.call("POST", path, map[string]string{"pem": body}, &out); s != http.StatusBadRequest {
			t.Errorf("%s: status %d (%v)", name, s, out)
		}
	}
	if s, _ := e.do("POST", path, map[string]string{"pem": strings.Repeat("A", 70<<10)}); s != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized upload: %d", s)
	}
	if list, _ := e.st.TrustAnchors(asset.SystemID); len(list) != 0 {
		t.Fatalf("a refused upload stored anchors: %+v", list)
	}

	var added struct {
		Added       []store.TrustAnchor `json:"added"`
		Reevaluated int                 `json:"reevaluated"`
	}
	if s := e.call("POST", path, map[string]string{"pem": pemOf(root.Cert)}, &added); s != 200 || len(added.Added) != 1 || added.Reevaluated != 1 {
		t.Fatalf("add: %d %+v", s, added)
	}
	ev := evaluation()
	if ev.has("CERT.UNTRUSTED") || len(ev.PKI) == 0 || ev.PKI[0].Private == nil || !ev.PKI[0].Private.Trusted {
		t.Fatalf("after the bundle: %+v", ev)
	}
	// Adding the same CA again is a no-op.
	if s := e.call("POST", path, map[string]string{"pem": pemOf(root.Cert)}, &added); s != 200 || len(added.Added) != 0 {
		t.Errorf("re-add: %d %+v", s, added)
	}

	var list struct {
		Anchors []store.TrustAnchor `json:"anchors"`
	}
	e.call("GET", path, nil, &list)
	if len(list.Anchors) != 1 || !strings.Contains(list.Anchors[0].Subject, "Corp Root") {
		t.Fatalf("list %+v", list)
	}
	if s, _ := e.do("DELETE", path+"/"+list.Anchors[0].SHA256, nil); s != 200 {
		t.Fatalf("delete: %d", s)
	}
	if !evaluation().has("CERT.UNTRUSTED") {
		t.Error("removing the anchor did not re-evaluate the endpoint as untrusted")
	}
	if s, _ := e.do("DELETE", path+"/"+list.Anchors[0].SHA256, nil); s != 404 {
		t.Errorf("second delete: %d", s)
	}

	log, _ := e.st.Audit("system", asset.SystemID, 50)
	var actions []string
	for _, l := range log {
		actions = append(actions, l.Action)
	}
	if j := strings.Join(actions, ","); !strings.Contains(j, "anchor-add") || !strings.Contains(j, "anchor-remove") {
		t.Errorf("audit %v", actions)
	}

	// Explicit re-evaluation records an event and keeps the report.
	before, _ := e.st.Report(sc.ID)
	if s, _ := e.do("POST", "/api/v1/scans/"+itoa(sc.ID)+"/reevaluate", nil); s != 200 {
		t.Fatalf("reevaluate: %d", s)
	}
	after, _ := e.st.Report(sc.ID)
	if string(before) != string(after) {
		t.Error("re-evaluation rewrote the stored report")
	}
	events, _ := e.st.Events(sc.ID)
	found := false
	for _, ev := range events {
		found = found || strings.Contains(ev.Message, "re-evaluated (requested)")
	}
	if !found {
		t.Error("no re-evaluation event")
	}
	if s, _ := e.do("POST", "/api/v1/scans/999999/reevaluate", nil); s != 404 {
		t.Errorf("reevaluate unknown scan: %d", s)
	}
}

func TestReferenceDataAndServerBundle(t *testing.T) {
	e := newEnv(t)
	var ref struct {
		Lists []struct {
			Name, Retrieved, Licence string
			Count                    int
		} `json:"lists"`
		Attribution string `json:"attribution"`
	}
	if s := e.call("GET", "/api/v1/reference-data", nil, &ref); s != 200 || len(ref.Lists) != 6 || !strings.Contains(ref.Attribution, "CCADB") {
		t.Fatalf("reference data: %d %+v", s, ref)
	}
	for _, l := range ref.Lists {
		if l.Count == 0 || l.Licence == "" || l.Retrieved == "" {
			t.Errorf("list %+v", l)
		}
	}
	var b struct {
		Anchors []any `json:"anchors"`
	}
	if s := e.call("GET", "/api/v1/trust-anchors", nil, &b); s != 200 || b.Anchors == nil {
		t.Errorf("server bundle: %d %+v", s, b)
	}
}

// TestDROWNAcrossTheEstate is REQ-TVLN-2 end to end through the runner: a key served on
// an endpoint whose latest scan accepted SSLv2 is reported on another endpoint serving it.
func TestDROWNAcrossTheEstate(t *testing.T) {
	// A runner that is never started: nothing else may claim the queued scan.
	st, err := store.Open(filepath.Join(t.TempDir(), "drown.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	runner := server.NewRunner(st, server.Guard{}, server.RunnerOptions{})
	e := struct {
		st     *store.Store
		runner *server.Runner
	}{st, runner}
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	leaf := root.Leaf(t, pkitest.LeafOpts{})
	ci := tlsprobe.DescribeCertificate(leaf)
	legacy, err := st.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "legacy", Host: "legacy.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	old := tlsprobe.Report{SchemaVersion: tlsprobe.SchemaVersion, Target: tlsprobe.Target{Host: "legacy.test", Port: 443},
		Protocols:    []tlsprobe.ProtocolResult{{Version: "SSLv2", Supported: true, Evidence: tlsprobe.EvidenceServerHello}},
		Certificates: []tlsprobe.CertResult{{Source: "tls-default", Chain: []tlsprobe.CertInfo{ci}}}}
	raw, _ := json.Marshal(old)
	if _, _, err := e.st.EnqueueScan(legacy.ID, "manual", "test"); err != nil {
		t.Fatal(err)
	}
	sc, err := e.st.ClaimNext()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.FinishScan(sc.ID, store.Result{Report: raw, Evaluation: []byte(`{}`), Band: "Broken"}); err != nil {
		t.Fatal(err)
	}
	modern, err := e.st.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "modern", Host: "modern.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	rep := &tlsprobe.Report{SchemaVersion: tlsprobe.SchemaVersion, Target: tlsprobe.Target{Host: "modern.test", Port: 443},
		Protocols:    []tlsprobe.ProtocolResult{{Version: "TLSv1.3", Supported: true, Evidence: tlsprobe.EvidenceServerHello}},
		Certificates: []tlsprobe.CertResult{{Source: "tls-default", NameMatches: true, Chain: []tlsprobe.CertInfo{ci}}}}
	ev := e.runner.Evaluate(rep, modern.ID)
	found := false
	for _, f := range ev.Findings {
		found = found || f.ID == "VULN.DROWN-SHARED-KEY" && strings.Contains(f.Detail, "legacy.test:443")
	}
	if !found {
		t.Errorf("DROWN across the estate not reported: %+v", ev.Findings)
	}
	// The SSLv2 endpoint itself is not told about its own key.
	if ev := e.runner.Evaluate(&old, legacy.ID); func() bool {
		for _, f := range ev.Findings {
			if f.ID == "VULN.DROWN-SHARED-KEY" {
				return true
			}
		}
		return false
	}() {
		t.Error("an endpoint was reported for sharing a key with itself")
	}
}

func pemFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
