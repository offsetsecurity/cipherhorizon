package tlsprobe_test

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

func accepted(rep *tlsprobe.Report) map[string]bool {
	out := map[string]bool{}
	for _, s := range rep.Signatures.Accepted() {
		out[s.Name] = true
	}
	return out
}

func leafAlgorithm(rep *tlsprobe.Report) string {
	for _, c := range rep.Certificates {
		if len(c.Chain) > 0 {
			return c.Chain[0].PublicKey.Algorithm
		}
	}
	return ""
}

// REQ-PQS-2: a server whose only certificate is ML-DSA, and which picks its certificate before
// answering (as OpenSSL does), is seen as the TLS 1.3 server it is.
func TestAnMLDSAOnlyServerIsSeen(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13, Cert: testserver.CertMLDSA,
		SelectCertFirst: true, Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}})
	rep := scan(t, srv, opts())
	if got := strings.Join(supported(rep), ","); got != "TLSv1.3" {
		t.Fatalf("supported versions %q, want TLSv1.3 (an ML-DSA-only server must not look like it lacks TLS 1.3)", got)
	}
	if len(rep.Groups) == 0 || len(rep.Suites) == 0 {
		t.Errorf("groups %v suites %v: enumeration must work against an ML-DSA-only server", rep.Groups, rep.Suites)
	}
	if got := leafAlgorithm(rep); got != "ML-DSA-65" {
		t.Errorf("leaf key algorithm %q, want ML-DSA-65", got)
	}
	if acc := accepted(rep); !acc["mldsa65"] || len(acc) != 1 {
		t.Errorf("accepted schemes %v, want only mldsa65", acc)
	}
}

// REQ-PQS-3: the stage lists every scheme the server holds a key for.
func TestSignatureStageListsAcceptedSchemes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  testserver.Config
		want []string
	}{
		{"ecdsa and ml-dsa", testserver.Config{MinVersion: tls.VersionTLS13, Cert: testserver.CertECDSAAndMLDSA},
			[]string{"ecdsa_secp256r1_sha256", "mldsa65"}},
		{"ecdsa and rsa", testserver.Config{MinVersion: tls.VersionTLS12, Cert: testserver.CertBoth},
			[]string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512"}},
		{"ecdsa, picks first", testserver.Config{MinVersion: tls.VersionTLS13, SelectCertFirst: true},
			[]string{"ecdsa_secp256r1_sha256"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := scan(t, testserver.Start(t, tc.cfg), opts())
			if rep.Signatures == nil || rep.Signatures.Control != tlsprobe.SigRefused {
				t.Fatalf("signatures %+v", rep.Signatures)
			}
			acc := accepted(rep)
			for _, w := range tc.want {
				if !acc[w] {
					t.Errorf("%s not accepted; accepted %v", w, acc)
				}
			}
			if len(acc) != len(tc.want) {
				t.Errorf("accepted %v, want exactly %v", acc, tc.want)
			}
			if st := stageMap(rep)["signatures"]; st.Outcome != tlsprobe.OutcomeDone || st.Connections != len(tlsprobe.SigCandidates())+1 {
				t.Errorf("stage %+v, want done with %d connections", st, len(tlsprobe.SigCandidates())+1)
			}
		})
	}
}

// REQ-PQS-4: a server that answers whatever is offered proves nothing, and the stage says so.
func TestSignatureStageControlCatchesServersThatIgnoreTheList(t *testing.T) {
	srv := testserver.StartScript(t, testserver.AnswerAnyTLS13())
	o := opts()
	o.SkipCertificates = true
	rep, _ := tlsprobe.Scan(t.Context(), target(t, srv), o)
	if rep == nil || rep.Signatures == nil {
		t.Fatalf("no signature result: %+v", rep)
	}
	if rep.Signatures.Control != tlsprobe.SigAccepted || rep.Signatures.Conclusive() || len(rep.Signatures.Accepted()) != 0 {
		t.Errorf("control %q, accepted %v: a server answering a private-use scheme must make the stage inconclusive",
			rep.Signatures.Control, rep.Signatures.Accepted())
	}
	if st := stageMap(rep)["signatures"]; st.Outcome != tlsprobe.OutcomeInconclusive || !strings.Contains(st.Reason, "does not choose its certificate") {
		t.Errorf("stage %+v", st)
	}
}

// TC-S5: no TLS 1.3, no stage.
func TestSignatureStageSkippedWithoutTLS13(t *testing.T) {
	rep := scan(t, testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}), opts())
	if rep.Signatures != nil {
		t.Errorf("signatures %+v on a TLS 1.2 server", rep.Signatures)
	}
	if st := stageMap(rep)["signatures"]; st.Outcome != tlsprobe.OutcomeSkipped || st.ReasonCode != tlsprobe.ReasonNotApplicable {
		t.Errorf("stage %+v", st)
	}
}
