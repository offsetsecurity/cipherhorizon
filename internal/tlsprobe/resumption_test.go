package tlsprobe_test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// A server that issues tickets resumes on the second connection, in TLS 1.3 and in TLS 1.2, and
// the scan reads what the tickets state. Go's server issues one-week tickets and never allows
// early data over TCP.
func TestResumptionIsProbed(t *testing.T) {
	rep := scan(t, testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12}), tlsprobe.Options{})
	r := rep.Resumption
	if r == nil || r.TLS13 == nil || r.TLS12 == nil {
		t.Fatalf("resumption was not probed for both versions: %+v", r)
	}
	for name, v := range map[string]*tlsprobe.ResumeResult{"TLS 1.3": r.TLS13, "TLS 1.2": r.TLS12} {
		if v.Tickets == 0 || v.Resumed == nil || !*v.Resumed {
			t.Errorf("%s: tickets %d, resumed %v, note %q", name, v.Tickets, v.Resumed, v.Note)
		}
		if v.LifetimeSeconds == nil {
			t.Errorf("%s: the ticket's stated lifetime was not read (%s)", name, v.Note)
		}
	}
	// Go's server states one week in TLS 1.3 and gives no hint (0, "unspecified") in TLS 1.2.
	if l := r.TLS13.LifetimeSeconds; l != nil && *l != 7*24*3600 {
		t.Errorf("TLS 1.3 ticket lifetime: %d", *l)
	}
	if l := r.TLS12.LifetimeSeconds; l != nil && *l != 0 {
		t.Errorf("TLS 1.2 lifetime hint: %d", *l)
	}
	if r.TLS13.MaxEarlyData == nil || *r.TLS13.MaxEarlyData != 0 {
		t.Errorf("TLS 1.3: a server that does not allow early data states 0: %v", r.TLS13.MaxEarlyData)
	}
	if r.TLS12.MaxEarlyData != nil {
		t.Error("TLS 1.2 has no early data")
	}
	found := false
	for _, st := range rep.Stages {
		for _, pr := range st.Probes {
			if st.Name == tlsprobe.StageCerts && len(pr) > 0 && pr[:11] == "per version" {
				found = true
			}
		}
	}
	if !found {
		t.Error("the stage does not say what the resumption probe sent")
	}
}

// A TLS 1.3-only server is probed for TLS 1.3 alone.
func TestResumptionTLS13Only(t *testing.T) {
	rep := scan(t, testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13}), tlsprobe.Options{})
	if r := rep.Resumption; r == nil || r.TLS13 == nil || r.TLS12 != nil || r.TLS13.Resumed == nil || !*r.TLS13.Resumed {
		t.Fatalf("resumption: %+v", r)
	}
}

// The early-data allowance is read from the ticket's early_data extension; a ticket without the
// extension allows none.
func TestTicketParsing(t *testing.T) {
	// lifetime 7200, age_add, nonce 01 00, ticket aa bb, extensions: early_data (42) = 16384.
	withEarly := []byte{0, 0, 0x1c, 0x20, 1, 2, 3, 4, 2, 1, 0, 0, 2, 0xaa, 0xbb, 0, 8, 0, 42, 0, 4, 0, 0, 0x40, 0}
	lt, early, ok := tlsprobe.ParseTicket13ForTest(withEarly)
	if !ok || lt != 7200 || early != 16384 {
		t.Errorf("ticket with early data: %d %d %v", lt, early, ok)
	}
	without := []byte{0, 0, 0x1c, 0x20, 1, 2, 3, 4, 0, 0, 1, 0xaa, 0, 0}
	if lt, early, ok := tlsprobe.ParseTicket13ForTest(without); !ok || lt != 7200 || early != 0 {
		t.Errorf("ticket without early data: %d %d %v", lt, early, ok)
	}
	for i := range withEarly {
		tlsprobe.ParseTicket13ForTest(withEarly[:i]) // a truncated ticket must not panic
	}
}

// The scan runs the weak-key tests on every served certificate and records which ran.
func TestServedKeysAreTested(t *testing.T) {
	rep := scan(t, testserver.Start(t, testserver.Config{Cert: testserver.CertBoth}), tlsprobe.Options{})
	saw := map[string]bool{}
	for _, cr := range rep.Certificates {
		for _, ci := range cr.Chain {
			if ci.KeyTests == nil {
				t.Fatalf("%s: the key was not tested", ci.Subject)
			}
			if len(ci.KeyTests.Weak) != 0 {
				t.Errorf("%s: a sound test key is reported weak: %+v", ci.Subject, ci.KeyTests.Weak)
			}
			saw[ci.PublicKey.Algorithm] = len(ci.KeyTests.Ran) > 0
		}
	}
	if !saw["RSA"] || !saw["ECDSA"] {
		t.Errorf("both key types run tests: %v", saw)
	}
	if kt := tlsprobe.TestKey(struct{}{}); kt == nil || kt.Ran == nil || len(kt.Ran) != 0 {
		t.Errorf("a key type with no test records an empty list, not a missing one: %+v", kt)
	}
}

// The package's own ChaCha20-Poly1305 reader agrees with the reference implementation on messages
// of every length around the block boundaries, and refuses a message with one bit changed.
func TestChachaReaderMatchesTheReference(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1000} {
		key, nonce, aad, msg := make([]byte, 32), make([]byte, 12), make([]byte, 5), make([]byte, n)
		for _, b := range [][]byte{key, nonce, aad, msg} {
			if _, err := rand.Read(b); err != nil {
				t.Fatal(err)
			}
		}
		ref, err := chacha20poly1305.New(key)
		if err != nil {
			t.Fatal(err)
		}
		sealed := ref.Seal(nil, nonce, msg, aad)
		got, err := tlsprobe.ChachaOpenForTest(key, nonce, sealed, aad)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("length %d: %v", n, err)
		}
		sealed[len(sealed)/2] ^= 1
		if _, err := tlsprobe.ChachaOpenForTest(key, nonce, sealed, aad); err == nil {
			t.Fatalf("length %d: a changed message was accepted", n)
		}
	}
}
