package eval_test

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

func sigResult(control string, accepted ...string) *tlsprobe.SignatureResult {
	r := &tlsprobe.SignatureResult{Version: "TLSv1.3", Control: control}
	for _, c := range tlsprobe.SigCandidates() {
		res := tlsprobe.SigRefused
		for _, a := range accepted {
			if a == c.Name {
				res = tlsprobe.SigAccepted
			}
		}
		r.Schemes = append(r.Schemes, tlsprobe.SigScheme{ID: c.ID, Name: c.Name, Algorithm: c.Algorithm, PQ: c.PQ, Result: res})
	}
	return r
}

// REQ-PQS-5: a dual-certificate server whose default certificate is classical reaches L4 on the
// signature stage's evidence, and the authentication dimension says which evidence.
func TestDualCertificateServerReachesL4(t *testing.T) {
	r := modern()
	r.Signatures = sigResult(tlsprobe.SigRefused, "ecdsa_secp256r1_sha256", "mldsa65")
	ev := eval.Evaluate(r, now)
	if ev.Readiness.Level != eval.LevelPQAuth {
		t.Fatalf("level %d, want L4", ev.Readiness.Level)
	}
	a := ev.Readiness.Authentication
	if a.Status != "post-quantum" || !strings.Contains(a.Detail, "ML-DSA-65") || !strings.Contains(a.Detail, "only signature scheme offered") {
		t.Errorf("authentication %+v", a)
	}
	if ids(ev)["PQC.CLASSICAL-AUTH"] {
		t.Error("PQC.CLASSICAL-AUTH raised although the server holds an ML-DSA key")
	}

	// The same answers with the control accepted prove nothing.
	r.Signatures = sigResult(tlsprobe.SigAccepted, "ecdsa_secp256r1_sha256", "mldsa65")
	if lvl := eval.Evaluate(r, now).Readiness.Level; lvl != eval.LevelHybridNeg {
		t.Errorf("control accepted: level %d, want L3", lvl)
	}
	// ML-DSA accepted but no hybrid key exchange: authentication alone never lifts the level.
	r = modern()
	r.Negotiated = negotiated(x25519)
	r.Groups = []tlsprobe.GroupResult{x25519}
	r.Signatures = sigResult(tlsprobe.SigRefused, "mldsa65")
	if lvl := eval.Evaluate(r, now).Readiness.Level; lvl != eval.LevelExposed {
		t.Errorf("classical key exchange with ML-DSA: level %d, want L1", lvl)
	}
}

// REQ-PQS-2/5 end to end: an ML-DSA-only server with a hybrid group is L4.
func TestAnMLDSAOnlyServerIsL4(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13, Cert: testserver.CertMLDSA,
		SelectCertFirst: true, Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}})
	rep, err := tlsprobe.Scan(t.Context(), tlsprobe.Target{Host: srv.Host, Port: srv.Port}, tlsprobe.Options{Concurrency: 8})
	if err != nil {
		t.Fatal(err)
	}
	ev := eval.Evaluate(rep, rep.Started)
	if ev.Readiness.Level != eval.LevelPQAuth {
		t.Fatalf("level %d (%s), want L4; authentication %+v", ev.Readiness.Level, ev.Readiness.Label, ev.Readiness.Authentication)
	}
	if !strings.Contains(ev.Readiness.Authentication.Detail, "ML-DSA-65") {
		t.Errorf("authentication %+v", ev.Readiness.Authentication)
	}
}

// REQ-PQS-7: a report without the stage (made before it existed) is judged as before.
func TestOldReportsEvaluateUnchanged(t *testing.T) {
	r := modern()
	before := eval.Evaluate(r, now)
	r.Signatures = nil
	after := eval.Evaluate(r, now)
	if before.Readiness.Level != after.Readiness.Level || len(before.Findings) != len(after.Findings) || before.Hygiene.Score != after.Hygiene.Score {
		t.Errorf("a report without signatures changed: %+v vs %+v", before.Readiness, after.Readiness)
	}
	if before.Readiness.Level != eval.LevelHybridNeg {
		t.Errorf("modern() is L%d, want L3", before.Readiness.Level)
	}
}
