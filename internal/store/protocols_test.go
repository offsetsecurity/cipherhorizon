package store_test

import (
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// runSSH stores one finished SSH scan: no band, score -1, and a baseline verdict.
func runSSH(t *testing.T, s *store.Store, host string, level int, meets *bool, changes int) store.Asset {
	t.Helper()
	a, err := s.CreateAsset(store.Asset{Kind: store.KindSSH, Name: host, Host: host, Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	sc, _, err := s.EnqueueScan(a.ID, "manual", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimNext(); err != nil {
		t.Fatal(err)
	}
	base := ""
	if meets != nil {
		base = "cipherhorizon-ssh-2026"
	}
	if err := s.FinishScan(sc.ID, store.Result{Report: []byte(`{"r":1}`), Evaluation: []byte(`{"e":1}`), Score: -1,
		ReadinessLevel: level, HNDLExposed: level < 3, Baseline: base, BaselineMeets: meets, BaselineChanges: changes}); err != nil {
		t.Fatal(err)
	}
	return a
}

func ptr(b bool) *bool { return &b }

// REQ-SHW-4: the fleet broken down by protocol, each with its own measure.
func TestFleetSummaryByProtocol(t *testing.T) {
	s, _ := open(t)
	runOne(t, s, asset(t, s, "web.example", 443), 3, "Strong", 0)
	runOne(t, s, asset(t, s, "old.example", 443), 1, "Fair", 0)
	asset(t, s, "new.example", 443)
	runSSH(t, s, "bastion.example", 3, ptr(true), 0)
	runSSH(t, s, "git.example", 1, ptr(false), 4)
	runSSH(t, s, "ancient.example", 0, ptr(false), 1)
	runSSH(t, s, "silent.example", -1, nil, 0)

	f, err := s.FleetSummary(3)
	if err != nil {
		t.Fatal(err)
	}
	tls, ssh := f.Protocols[store.ProtocolTLS], f.Protocols[store.ProtocolSSH]
	if tls == nil || ssh == nil {
		t.Fatalf("protocols %v", f.Protocols)
	}
	if tls.Assets != 3 || tls.Scanned != 2 || tls.HNDLExposed != 1 || tls.Bands["Strong"] != 1 || tls.Bands["Fair"] != 1 {
		t.Errorf("tls %+v", tls)
	}
	if ssh.Assets != 4 || ssh.Scanned != 4 || ssh.BaselineMeets != 1 || ssh.BaselineFails != 2 || ssh.SSH1 != 1 || ssh.Bands != nil {
		t.Errorf("ssh %+v", ssh)
	}
	if ssh.Readiness[3] != 1 || ssh.Readiness[1] != 1 || ssh.Readiness[0] != 1 {
		t.Errorf("ssh readiness %v", ssh.Readiness)
	}
	// The cross-protocol totals still count everything.
	if f.Assets != 7 || f.Scanned != 6 || f.Readiness[3] != 2 {
		t.Errorf("fleet assets %d scanned %d readiness %v", f.Assets, f.Scanned, f.Readiness)
	}
	for _, r := range f.NeedsAttention {
		if r.Protocol == "" || r.Protocol == store.ProtocolSSH && (r.Band != "" || r.Score != -1) {
			t.Errorf("attention row %+v", r)
		}
	}
}

// REQ-SHE-5: hygiene bands count TLS endpoints only; an SSH server never lands in a band.
func TestFleetBandsCountTLSOnly(t *testing.T) {
	s, _ := open(t)
	runOne(t, s, asset(t, s, "web.example", 443), 3, "Strong", 0)
	runSSH(t, s, "bastion.example", 3, ptr(true), 0)
	f, err := s.FleetSummary(3)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range f.Bands {
		total += n
	}
	if total != 1 || f.Bands["Strong"] != 1 {
		t.Errorf("bands %v: only the TLS endpoint has a band", f.Bands)
	}
}

// REQ-SHB-5: the verdict is stored with the scan and read back on the asset; re-evaluation
// replaces it.
func TestBaselineIsStoredWithTheScan(t *testing.T) {
	s, _ := open(t)
	a := runSSH(t, s, "git.example", 1, ptr(false), 4)
	got, err := s.GetAsset(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	d := got.LastDone
	if d == nil || d.Baseline != "cipherhorizon-ssh-2026" || d.BaselineMeets == nil || *d.BaselineMeets || d.BaselineChanges != 4 || d.Band != "" {
		t.Fatalf("last done %+v", d)
	}
	if err := s.ReplaceEvaluation(d.ID, store.Result{Evaluation: []byte(`{"e":2}`), Score: -1, ReadinessLevel: 3,
		Baseline: "cipherhorizon-ssh-2026", BaselineMeets: ptr(true)}, "re-evaluated"); err != nil {
		t.Fatal(err)
	}
	sc, _ := s.GetScan(d.ID)
	if sc.BaselineMeets == nil || !*sc.BaselineMeets || sc.BaselineChanges != 0 {
		t.Errorf("after re-evaluation %+v", sc)
	}
	// A TLS scan has no verdict.
	tls := runOne(t, s, asset(t, s, "web.example", 443), 3, "Strong", 0)
	if tls.Baseline != "" || tls.BaselineMeets != nil {
		t.Errorf("tls scan %+v", tls)
	}
}
