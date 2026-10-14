package sshprobe_test

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"golang.org/x/crypto/ssh"
)

func opts() sshprobe.Options { return sshprobe.Options{Timeout: 3 * time.Second} }

// scriptOpts is for scripted servers, which never answer a key exchange: each probe waits out its timeout.
func scriptOpts() sshprobe.Options { return sshprobe.Options{Timeout: 400 * time.Millisecond} }

func scan(t *testing.T, s *testserver.Server, o sshprobe.Options) *sshprobe.Report {
	t.Helper()
	rep, err := sshprobe.Scan(context.Background(), sshprobe.Target{Host: s.Host, Port: s.Port}, o)
	if err != nil {
		t.Fatalf("Scan: %v\n%+v", err, rep)
	}
	return rep
}

func stage(rep *sshprobe.Report, name string) sshprobe.Stage {
	for _, s := range rep.Stages {
		if s.Name == name {
			return s
		}
	}
	return sshprobe.Stage{}
}

func fingerprints(rep *sshprobe.Report) []string {
	var out []string
	for _, k := range rep.HostKeys {
		out = append(out, k.Fingerprint)
	}
	slices.Sort(out)
	return out
}

// REQ-SHP-2: the lists are the server's, exactly; the signals are broken out.
func TestKEXINITListsMatchTheServer(t *testing.T) {
	kex := []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519, ssh.KeyExchangeECDHP256, ssh.InsecureKeyExchangeDH14SHA1}
	ciphers := []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128CTR, ssh.InsecureCipherAES128CBC}
	macs := []string{ssh.HMACSHA256ETM, ssh.HMACSHA256, ssh.HMACSHA1}
	srv := testserver.Start(t, testserver.Config{KeyExchanges: kex, Ciphers: ciphers, MACs: macs})
	rep := scan(t, srv, opts())
	a := rep.Algorithms
	if a == nil {
		t.Fatal("no algorithms")
	}
	// x/crypto adds the libssh alias of curve25519-sha256 after it, as OpenSSH does.
	wantKex := []string{kex[0], kex[1], "curve25519-sha256@libssh.org", kex[2], kex[3]}
	if !slices.Equal(a.Kex, wantKex) {
		t.Errorf("kex %v, want %v", a.Kex, wantKex)
	}
	if !slices.Equal(a.CipherC2S, ciphers) || !slices.Equal(a.CipherS2C, ciphers) {
		t.Errorf("ciphers %v / %v, want %v", a.CipherC2S, a.CipherS2C, ciphers)
	}
	if !slices.Equal(a.MACC2S, macs) {
		t.Errorf("macs %v, want %v", a.MACC2S, macs)
	}
	if !a.StrictKex {
		t.Error("x/crypto advertises kex-strict-s-v00@openssh.com; StrictKex is false")
	}
	for _, k := range a.Kex {
		if strings.HasPrefix(k, "kex-strict") || strings.HasPrefix(k, "ext-info") {
			t.Errorf("signal %s listed as a key exchange", k)
		}
	}
	if id := rep.Identification; id == nil || id.ProtoVersion != "2.0" || id.SSH1 {
		t.Errorf("identification %+v", id)
	}
}

// REQ-SHP-3: negotiating as OpenSSH 10.6 lands on the hybrid and completes it; the signature over
// the exchange hash verifies, which it can only do if both sides computed the same H.
func TestNegotiationCompletesTheHybridExchange(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{
		KeyExchanges: []string{ssh.KeyExchangeCurve25519, ssh.KeyExchangeMLKEM768X25519}, Keys: []string{testserver.KeyEd25519}})
	rep := scan(t, srv, opts())
	n := rep.Negotiated
	if n == nil || n.Kex != "mlkem768x25519-sha256" || !n.Completed || !n.Verified || n.Evidence != sshprobe.EvidenceObserved {
		t.Fatalf("negotiated %+v", n)
	}
	if n.HostKey != "ssh-ed25519" || n.Cipher != "chacha20-poly1305@openssh.com" || n.MAC != "" {
		t.Errorf("negotiated %+v: want ssh-ed25519, chacha20-poly1305 and no separate MAC", n)
	}
	if st := stage(rep, sshprobe.StageNegotiation); st.Outcome != tlsprobe.OutcomeDone || st.Connections != 1 {
		t.Errorf("stage %+v", st)
	}
}

// Every exchange the scanner implements reaches a verified signature against an independent server.
func TestEveryImplementedKeyExchangeVerifies(t *testing.T) {
	for _, k := range []string{ssh.KeyExchangeCurve25519, "curve25519-sha256@libssh.org", ssh.KeyExchangeECDHP256, ssh.KeyExchangeECDHP384,
		ssh.KeyExchangeECDHP521, ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeDH14SHA256, ssh.KeyExchangeDH16SHA512,
		ssh.InsecureKeyExchangeDH14SHA1, ssh.InsecureKeyExchangeDH1SHA1} {
		t.Run(k, func(t *testing.T) {
			srv := testserver.Start(t, testserver.Config{KeyExchanges: []string{k}})
			rep := scan(t, srv, opts())
			if len(rep.HostKeys) != 1 || !rep.HostKeys[0].Verified {
				t.Fatalf("host keys %+v, attempts %+v", rep.HostKeys, rep.HostKeyAttempts)
			}
			if got := rep.HostKeyAttempts[0].Kex; got != k && (k != "curve25519-sha256@libssh.org" || got != ssh.KeyExchangeCurve25519) {
				t.Errorf("fetched with %s, want %s", rep.HostKeyAttempts[0].Kex, k)
			}
		})
	}
}

// REQ-SHP-4: one exchange per advertised host key algorithm; keys grouped by fingerprint.
func TestHostKeysAreReadPerAlgorithm(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{Keys: []string{testserver.KeyEd25519, testserver.KeyECDSA, testserver.KeyRSA},
		RSAAlgorithms: []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}})
	rep := scan(t, srv, opts())
	want := append([]string(nil), srv.Fingerprints...)
	slices.Sort(want)
	if got := fingerprints(rep); !slices.Equal(got, want) {
		t.Fatalf("fingerprints %v, want %v", got, want)
	}
	for _, k := range rep.HostKeys {
		if !k.Verified {
			t.Errorf("%s not verified: %s", k.Type, k.VerifyNote)
		}
		switch k.Algorithm {
		case "RSA":
			slices.Sort(k.ServedBy)
			if !slices.Equal(k.ServedBy, []string{"rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"}) || k.Bits != 3072 {
				t.Errorf("RSA key %+v", k)
			}
		case "ECDSA":
			if k.Curve != "P-256" {
				t.Errorf("ECDSA key %+v", k)
			}
		}
	}
	if st := stage(rep, sshprobe.StageHostKeys); st.Outcome != tlsprobe.OutcomeDone || st.Connections != len(rep.Algorithms.HostKey) {
		t.Errorf("stage %+v (advertised %v)", st, rep.Algorithms.HostKey)
	}
	if rep.Connections > sshprobe.MaxScanConnections {
		t.Errorf("%d connections", rep.Connections)
	}
}

// ML-DSA host keys, from an independent implementation (draft-sfluhrer-ssh-mldsa in x/crypto).
func TestMLDSAHostKeyIsReadAndVerified(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{Keys: []string{testserver.KeyMLDSA65}})
	rep := scan(t, srv, opts())
	if len(rep.HostKeys) != 1 {
		t.Fatalf("host keys %+v; attempts %+v", rep.HostKeys, rep.HostKeyAttempts)
	}
	k := rep.HostKeys[0]
	if k.Type != "ssh-mldsa-65" || k.Algorithm != "ML-DSA-65" || !k.PQ || !k.Verified || k.Fingerprint != srv.Fingerprints[0] {
		t.Errorf("key %+v, want a verified ML-DSA-65 key %s", k, srv.Fingerprints[0])
	}
}

// The OpenSSH 10.6 composite host key, checked against the draft's construction (no library
// implements it yet: QA-PLAN-006 records the limit).
func TestCompositeHostKeyIsReadAndVerified(t *testing.T) {
	key, err := testserver.NewCompositeKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := testserver.ListenComposite("", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	rep := scan(t, srv, opts())
	if len(rep.HostKeys) != 1 {
		t.Fatalf("host keys %+v; attempts %+v", rep.HostKeys, rep.HostKeyAttempts)
	}
	k := rep.HostKeys[0]
	if k.Type != "ssh-mldsa44-ed25519" || !k.PQ || !k.Verified || k.Fingerprint != key.Fingerprint() {
		t.Errorf("key %+v (note %q), want a verified composite %s", k, k.VerifyNote, key.Fingerprint())
	}
}

// REQ-SHP-5: a host certificate's fields are read.
func TestHostCertificatesAreParsed(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{Keys: []string{testserver.KeyEd25519}, Certificate: true})
	rep := scan(t, srv, opts())
	var cert *sshprobe.HostKey
	for i := range rep.HostKeys {
		if rep.HostKeys[i].Certificate != nil {
			cert = &rep.HostKeys[i]
		}
	}
	if cert == nil {
		t.Fatalf("no certificate among %+v", rep.HostKeys)
	}
	c := cert.Certificate
	if c.KeyType != "ssh-ed25519" || c.Serial != 42 || c.CertType != 2 || !slices.Equal(c.Principals, []string{"localhost", "127.0.0.1"}) ||
		c.CAType != "ecdsa-sha2-nistp256" || !strings.HasPrefix(c.CAFingerprint, "SHA256:") || !c.ValidBefore.After(time.Now()) {
		t.Errorf("certificate %+v", c)
	}
}

// REQ-SHP-1: SSH-1, preambles and non-SSH services.
func TestIdentificationIsParsed(t *testing.T) {
	t.Run("ssh-1 only", func(t *testing.T) {
		rep := scan(t, testserver.StartScript(t, testserver.Script{Ident: "SSH-1.5-OldServer_1.2", NoKexInit: true}), opts())
		id := rep.Identification
		if id == nil || !id.SSH1Only || id.Software != "OldServer_1.2" || rep.Algorithms != nil {
			t.Fatalf("identification %+v algorithms %+v", id, rep.Algorithms)
		}
		if st := stage(rep, sshprobe.StageAlgorithms); st.Outcome != tlsprobe.OutcomeSkipped || st.ReasonCode != tlsprobe.ReasonNotApplicable {
			t.Errorf("algorithms stage %+v", st)
		}
	})
	t.Run("1.99 is both", func(t *testing.T) {
		rep := scan(t, testserver.StartScript(t, testserver.Script{Ident: "SSH-1.99-Both"}), scriptOpts())
		if id := rep.Identification; id == nil || !id.SSH1 || id.SSH1Only || rep.Algorithms == nil {
			t.Fatalf("identification %+v", id)
		}
	})
	t.Run("preamble", func(t *testing.T) {
		rep := scan(t, testserver.StartScript(t, testserver.Script{Preamble: []string{"Welcome", "Authorised use only"}}), scriptOpts())
		if id := rep.Identification; id == nil || len(id.Preamble) != 2 || id.Software != "OpenSSH_9.6" {
			t.Fatalf("identification %+v", id)
		}
	})
	t.Run("too long a preamble", func(t *testing.T) {
		lines := make([]string, 25)
		for i := range lines {
			lines[i] = "line"
		}
		srv := testserver.StartScript(t, testserver.Script{Preamble: lines})
		rep, err := sshprobe.Scan(context.Background(), sshprobe.Target{Host: srv.Host, Port: srv.Port}, opts())
		if err == nil || rep.Identification != nil || !strings.Contains(err.Error(), "did not send an SSH identification") {
			t.Fatalf("err %v identification %+v", err, rep.Identification)
		}
	})
	t.Run("not ssh", func(t *testing.T) {
		srv := testserver.StartScript(t, testserver.Script{RawReplace: []byte("HTTP/1.1 400 Bad Request\r\n\r\n<html>")})
		_, err := sshprobe.Scan(context.Background(), sshprobe.Target{Host: srv.Host, Port: srv.Port}, opts())
		if err == nil || !strings.Contains(err.Error(), "HTTP/1.1 400") {
			t.Fatalf("err %v: the reason must quote what the service sent", err)
		}
	})
}

// REQ-SHP-6: a server whose only key exchange this scanner cannot carry out leaves the host keys
// inconclusive, with the reason, and the negotiated choice computed, not observed.
func TestStagesSayWhatTheyCouldNotDo(t *testing.T) {
	rep := scan(t, testserver.StartScript(t, testserver.Script{Kex: []string{"sntrup761x25519-sha512", "kex-strict-s-v00@openssh.com"}}), opts())
	if n := rep.Negotiated; n == nil || n.Kex != "sntrup761x25519-sha512" || n.Evidence != sshprobe.EvidenceComputed || n.Completed {
		t.Errorf("negotiated %+v", n)
	}
	st := stage(rep, sshprobe.StageHostKeys)
	if st.Outcome != tlsprobe.OutcomeInconclusive || !strings.Contains(st.Reason, "sntrup761x25519-sha512") {
		t.Errorf("host keys stage %+v", st)
	}
	if len(rep.HostKeyAttempts) != 1 || rep.HostKeyAttempts[0].Outcome != sshprobe.AttemptNoCommonKex {
		t.Errorf("attempts %+v", rep.HostKeyAttempts)
	}
}

// REQ-SHP-7: every connection goes through the caller's dialer, and the budget holds.
func TestSSHScanRespectsTheGuardAndBudget(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{Keys: []string{testserver.KeyEd25519, testserver.KeyECDSA, testserver.KeyRSA}})
	o := opts()
	refused := errors.New("refused by the scan scope")
	o.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, refused }
	if _, err := sshprobe.Scan(context.Background(), sshprobe.Target{Host: srv.Host, Port: srv.Port}, o); err == nil || !strings.Contains(err.Error(), refused.Error()) {
		t.Fatalf("err %v: the dialer's refusal must stop the scan", err)
	}
	o = opts()
	o.MaxConnections = 3
	rep, _ := sshprobe.Scan(context.Background(), sshprobe.Target{Host: srv.Host, Port: srv.Port}, o)
	if rep.Connections > 3 {
		t.Errorf("%d connections with a budget of 3", rep.Connections)
	}
	inconclusive := 0
	for _, a := range rep.HostKeyAttempts {
		if a.Outcome == sshprobe.AttemptInconclusive {
			inconclusive++
		}
	}
	if inconclusive == 0 {
		t.Errorf("attempts %+v: the budget must show as inconclusive attempts", rep.HostKeyAttempts)
	}
}

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]sshprobe.Target{
		"host":              {Host: "host", Port: 22},
		"ssh://host":        {Host: "host", Port: 22},
		"ssh://host:2222/x": {Host: "host", Port: 2222},
		"[::1]:22":          {Host: "::1", Port: 22},
		"10.0.0.1":          {Host: "10.0.0.1", Port: 22},
	} {
		got, err := sshprobe.ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	if _, err := sshprobe.ParseTarget("host:99999"); err == nil {
		t.Error("port 99999 accepted")
	}
}
