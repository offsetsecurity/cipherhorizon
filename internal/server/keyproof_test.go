package server_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pki/pkitest"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// An endpoint that only replays a copy of a certificate a host holds (it never completes a
// handshake, so it never proves it holds the key) gets a proposal for a person to decide, not an
// automatic join into the host's system.
func TestAReplayedCertificateProposesButNeverAutoJoins(t *testing.T) {
	e := newEnv(t)
	ec, _ := testserver.Certificates(t)
	leaf, err := x509.ParseCertificate(ec.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// RSA-only legacy suites crypto/tls will not offer: the certificate is seen only in raw flights.
	srv := testserver.StartScript(t, testserver.LegacyWithCertificate(0x0303, []uint16{0x000A}, [][]byte{leaf.Raw}))
	a := e.addAsset(srv.Addr)
	if sc := e.wait(e.startScan(a.ID).ID); sc.Status != "done" {
		t.Fatalf("scan %s", sc.Status)
	}
	c := &corr{e: e, endpoint: a, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})}
	before := c.endpointSystem()
	c.uploadHost("web-01", true)

	if got := links(e, "confirmed"); len(got) != 0 {
		t.Fatalf("a replayed certificate joined automatically: %+v", got)
	}
	proposed := links(e, "proposed")
	if len(proposed) != 1 || proposed[0].AssetID != a.ID || proposed[0].Strength != "strong" || proposed[0].Note == "" {
		t.Fatalf("proposed links = %+v", proposed)
	}
	if c.endpointSystem() != before || len(e.systems()) != 2 {
		t.Errorf("the endpoint moved from system %d to %d (%d systems)", before, c.endpointSystem(), len(e.systems()))
	}
}

// A key shown with SSLv2 on another endpoint only in an unproven certificate is reported at low
// severity; the same key from a completed handshake stays high.
func TestDROWNFromAnUnprovenCertificateIsLow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "drown.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	runner := server.NewRunner(st, server.Guard{}, server.RunnerOptions{})
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})

	sslv2 := func(host string, cr tlsprobe.CertResult) {
		t.Helper()
		a, err := st.CreateAsset(store.Asset{Kind: store.KindTLS, Name: host, Host: host, Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		rep := tlsprobe.Report{SchemaVersion: tlsprobe.SchemaVersion, Target: tlsprobe.Target{Host: host, Port: 443},
			Protocols:    []tlsprobe.ProtocolResult{{Version: "SSLv2", Supported: true, Evidence: tlsprobe.EvidenceServerHello}},
			Certificates: []tlsprobe.CertResult{cr}}
		raw, _ := json.Marshal(rep)
		if _, _, err := st.EnqueueScan(a.ID, "manual", "test"); err != nil {
			t.Fatal(err)
		}
		sc, err := st.ClaimNext()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.FinishScan(sc.ID, store.Result{Report: raw, Evaluation: []byte(`{}`), Band: "Broken"}); err != nil {
			t.Fatal(err)
		}
	}
	victim := func(ci tlsprobe.CertInfo) []eval.Finding {
		t.Helper()
		a, err := st.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "v" + ci.SHA256[:8], Host: "v" + ci.SHA256[:8] + ".test", Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		rep := &tlsprobe.Report{SchemaVersion: tlsprobe.SchemaVersion, Target: tlsprobe.Target{Host: a.Host, Port: 443},
			Protocols:    []tlsprobe.ProtocolResult{{Version: "TLSv1.3", Supported: true, Evidence: tlsprobe.EvidenceServerHello}},
			Certificates: []tlsprobe.CertResult{{Source: "tls-default", NameMatches: true, Chain: []tlsprobe.CertInfo{ci}}}}
		var out []eval.Finding
		for _, f := range runner.Evaluate(rep, a.ID).Findings {
			if f.ID == "VULN.DROWN-SHARED-KEY" {
				out = append(out, f)
			}
		}
		return out
	}

	replayed := tlsprobe.DescribeCertificate(root.Leaf(t, pkitest.LeafOpts{}))
	sslv2("replay.test", tlsprobe.CertResult{Source: "raw-tlsv1.2, TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyUnproven: true, Chain: []tlsprobe.CertInfo{replayed}})
	failed := tlsprobe.DescribeCertificate(root.Leaf(t, pkitest.LeafOpts{}))
	sslv2("failed.test", tlsprobe.CertResult{Source: "tls-default", KeyUnproven: true, Chain: []tlsprobe.CertInfo{failed}})
	proven := tlsprobe.DescribeCertificate(root.Leaf(t, pkitest.LeafOpts{}))
	sslv2("legacy.test", tlsprobe.CertResult{Source: "tls-default", Chain: []tlsprobe.CertInfo{proven}})

	for _, c := range []struct {
		name string
		ci   tlsprobe.CertInfo
		want eval.Severity
	}{{"raw flight", replayed, eval.Low}, {"failed handshake", failed, eval.Low}, {"completed handshake", proven, eval.High}} {
		fs := victim(c.ci)
		if len(fs) != 1 || fs[0].Severity != c.want {
			t.Errorf("%s: DROWN findings %+v, want one at %s", c.name, fs, c.want)
		}
	}
}
