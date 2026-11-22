package tlsprobe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// distinctECChain is n self-issued dummy P-256 certificates, each with its own key.
func distinctECChain(t *testing.T, n int) [][]byte {
	t.Helper()
	out := make([][]byte, n)
	for i := range out {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: fmt.Sprintf("dummy %d", i)},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"127.0.0.1"}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = der
	}
	return out
}

// A server that sends a very long chain has only the first pki.MaxServedCerts certificates
// analysed, and the report says the chain was cut. A chain from a raw flight is not proven.
func TestLongRawChainIsCut(t *testing.T) {
	order := []uint16{0x000A} // TLS_RSA_WITH_3DES_EDE_CBC_SHA: crypto/tls will not offer it
	srv := testserver.StartScript(t, testserver.LegacyWithCertificate(0x0303, order, distinctECChain(t, 40)))
	rep := scan(t, srv, opts())
	if len(rep.Certificates) != 1 {
		t.Fatalf("%d certificate results, want 1", len(rep.Certificates))
	}
	c := rep.Certificates[0]
	if len(c.Chain) != pki.MaxServedCerts {
		t.Errorf("%d certificates analysed, want %d", len(c.Chain), pki.MaxServedCerts)
	}
	if c.KeyProven() || !c.KeyUnproven {
		t.Errorf("a chain read from a raw flight is recorded as proven: %+v", c.Source)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "40 certificates; the first 16 were analysed") {
		t.Errorf("no note that the chain was cut: %q", rep.Notes)
	}
}

// When the scan's context ends during the weak-key tests, the scan returns promptly, marks the
// report incomplete, and leaves the untested keys without results.
func TestWeakKeyTestsStopWhenTheScanIsCancelled(t *testing.T) {
	order := []uint16{0x000A}
	chain := distinctECChain(t, 40)
	// The search builds its table once per process; build it now so that it is not timed.
	warm, err := x509.ParseCertificate(distinctECChain(t, 1)[0])
	if err != nil {
		t.Fatal(err)
	}
	tlsprobe.TestKey(warm.PublicKey)
	srv := testserver.StartScript(t, testserver.LegacyWithCertificate(0x0303, order, chain))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	cancelled := make(chan time.Time, 1)
	o := opts()
	o.Progress = func(msg string) {
		if msg == "fetching certificates" {
			once.Do(func() {
				time.AfterFunc(300*time.Millisecond, func() { cancelled <- time.Now(); cancel() })
			})
		}
	}
	rep, _ := tlsprobe.Scan(ctx, target(t, srv), o)
	end := time.Now()
	var at time.Time
	select {
	case at = <-cancelled:
	default:
		t.Fatal("the scan finished before it was cancelled")
	}
	if late := end.Sub(at); late > 2*time.Second {
		t.Errorf("the scan ran on for %v after it was cancelled", late)
	}
	if rep == nil || !rep.Incomplete {
		t.Fatal("a cancelled scan is not marked incomplete")
	}
	untested := 0
	for _, c := range rep.Certificates {
		for _, ci := range c.Chain {
			if ci.KeyTests == nil {
				untested++
			}
		}
	}
	if len(rep.Certificates) == 0 {
		t.Fatal("the cancel came before the raw chain was read; the test did not reach the weak-key tests")
	}
	if untested == 0 {
		t.Error("every key carries weak-key results although the scan was cancelled during the tests")
	}
}

// A chain from a completed handshake is proven; the same report read back without the field
// still treats a raw-flight chain as unproven.
func TestHandshakeChainIsProven(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{})
	rep := scan(t, srv, opts())
	if len(rep.Certificates) == 0 {
		t.Fatal("no certificate")
	}
	for _, c := range rep.Certificates {
		if !c.KeyProven() || c.KeyUnproven {
			t.Errorf("%s: a chain from a completed handshake is unproven", c.Source)
		}
	}
	old := tlsprobe.CertResult{Source: "raw-tlsv1.2, TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
	if old.KeyProven() {
		t.Error("a raw-flight chain in a report without keyUnproven reads as proven")
	}
}
