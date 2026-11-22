package server_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sshtest "github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
	"golang.org/x/crypto/ssh"
)

// assign assigns a fix and returns its id (the id of the work behind it).
func assign(t *testing.T, e *env, subject map[string]any) int64 {
	t.Helper()
	var out struct{ Fix fixJSON }
	if s := e.call("POST", "/api/v1/fixes", map[string]any{"subject": subject, "owner": "dummy team"}, &out); s != 201 {
		t.Fatalf("assign %v: %d", subject, s)
	}
	return out.Fix.ID
}

// rawListener answers every connection on addr with reply, then closes it.
func rawListener(t *testing.T, addr string, reply []byte) {
	t.Helper()
	var l net.Listener
	var err error
	for range 50 { // the old server's port can take a moment to come free
		if l, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
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
				defer c.Close() //nolint:errcheck // test server
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if len(reply) > 0 {
					_, _ = c.Read(make([]byte, 4096))
					_, _ = c.Write(reply)
				}
			}()
		}
	}()
}

// A finding about the certificate is fixed only when a scan saw a certificate and found the problem
// gone: an endpoint that answers but shows no certificate (a fatal alert to every hello, or a closed
// connection) leaves the fix waiting.
func TestACertificateFindingIsNotFixedByAScanThatSawNoCertificate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply []byte
	}{
		{"fatal alert", []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}},
		{"closed connection", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			expired, _ := selfSignedFrom(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
			srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{expired}})
			a := e.addAsset(srv.Addr)
			e.scanAndWait(a.ID)
			id := assign(t, e, map[string]any{"kind": "finding", "assetId": a.ID, "findingKey": "CERT.EXPIRED"})

			srv.Close()
			rawListener(t, srv.Addr, tc.reply)
			if sc := e.scanAndWait(a.ID); sc.Status != "done" {
				t.Fatalf("the rescan did not finish: %+v", sc)
			}
			if v := verificationOf(t, e, id); v.Status != "waiting" || !strings.Contains(v.Detail, "could not check for CERT.EXPIRED") {
				t.Fatalf("a scan that saw no certificate: %+v", v)
			}
			if f := fixes(t, e); len(f.Fixed) != 0 || len(f.BeingFixed) != 1 {
				t.Fatalf("fixed %d, being fixed %d", len(f.Fixed), len(f.BeingFixed))
			}
		})
	}
}

// rsaCuttingFront relays connections to backend, but while cut is set it closes any connection whose
// client key exchange init asks for a single RSA host key algorithm: the server's RSA key is then never
// read, while everything else is.
func rsaCuttingFront(t *testing.T, backend string, cut *atomic.Bool) string {
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
			go relayUnlessRSA(c, backend, cut.Load())
		}
	}()
	return l.Addr().String()
}

func relayUnlessRSA(c net.Conn, backend string, cut bool) {
	defer c.Close() //nolint:errcheck // test relay
	b, err := net.Dial("tcp", backend)
	if err != nil {
		return
	}
	defer b.Close() //nolint:errcheck // test relay
	go func() { _, _ = io.Copy(c, b); _ = c.Close() }()
	r := bufio.NewReader(c)
	ident, err := r.ReadString('\n')
	if err != nil {
		return
	}
	if _, err := io.WriteString(b, ident); err != nil {
		return
	}
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return
	}
	pkt := make([]byte, binary.BigEndian.Uint32(head[:]))
	if len(pkt) > 64<<10 {
		return
	}
	if _, err := io.ReadFull(r, pkt); err != nil {
		return
	}
	if cut && asksOnlyRSA(pkt) {
		return
	}
	_, _ = b.Write(head[:])
	_, _ = b.Write(pkt)
	_, _ = io.Copy(b, r)
}

// asksOnlyRSA reads a KEXINIT packet (padding length, message, cookie, then name-lists) and says whether
// its host key list is one RSA algorithm.
func asksOnlyRSA(pkt []byte) bool {
	p := pkt
	if len(p) < 1+1+16 || p[1] != 20 {
		return false
	}
	p = p[1+1+16:]
	var lists []string
	for range 2 {
		if len(p) < 4 {
			return false
		}
		n := int(binary.BigEndian.Uint32(p))
		if len(p) < 4+n {
			return false
		}
		lists = append(lists, string(p[4:4+n]))
		p = p[4+n:]
	}
	hk := lists[1]
	return !strings.Contains(hk, ",") && (strings.HasPrefix(hk, "rsa-") || strings.HasPrefix(hk, "ssh-rsa"))
}

// A host-key finding is fixed only when the rescan read the key it is about: a scan whose RSA key
// requests were cut is incomplete and leaves the fix waiting, and the unchanged server still reads not fixed.
func TestAHostKeyFindingIsNotFixedByAScanThatDidNotReadTheKey(t *testing.T) {
	e := newEnv(t)
	backend := sshtest.Start(t, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
		Keys: []string{sshtest.KeyEd25519, sshtest.KeyRSA1024}})
	var cut atomic.Bool
	front := rsaCuttingFront(t, backend.Addr, &cut)
	var a sshAssetJSON
	if s := e.call("POST", "/api/v1/assets", map[string]any{"target": "ssh://" + front}, &a); s != 201 || a.Protocol != "ssh" {
		t.Fatalf("add: %d %+v", s, a)
	}
	e.scanAndWait(a.ID)
	id := assign(t, e, map[string]any{"kind": "finding", "assetId": a.ID, "findingKey": "SSH.HOSTKEY-RSA-SMALL"})

	cut.Store(true)
	sc := e.scanAndWait(a.ID)
	if sc.Status != "done" || !sc.Incomplete {
		t.Fatalf("a scan that did not read an advertised host key must be incomplete: %+v", sc)
	}
	if v := verificationOf(t, e, id); v.Status != "waiting" {
		t.Fatalf("the RSA key was not read: %+v", v)
	}
	if f := fixes(t, e); len(f.Fixed) != 0 {
		t.Fatalf("fixed %d", len(f.Fixed))
	}

	cut.Store(false)
	e.scanAndWait(a.ID)
	if v := verificationOf(t, e, id); v.Status != "not-verified" || !strings.Contains(v.Detail, "still finds SSH.HOSTKEY-RSA-SMALL") {
		t.Fatalf("the unchanged server read in full: %+v", v)
	}
}

// renewalFixture is two endpoints serving one old certificate, both scanned, with its renewal assigned,
// and the first endpoint renewed and rescanned.
type renewalFixture struct {
	e                *env
	a, b             assetJSON
	srvB             *testserver.Server
	id               int64
	oldCert, newCert tls.Certificate
	oldFP            string
}

func newRenewal(t *testing.T, scanBBefore bool) *renewalFixture {
	t.Helper()
	f := &renewalFixture{e: newEnv(t)}
	now := time.Now()
	f.oldCert, f.oldFP = selfSignedFrom(t, now.Add(-80*24*time.Hour), now.Add(5*24*time.Hour))
	f.newCert, _ = selfSignedFrom(t, now.Add(-10*time.Minute), now.Add(90*24*time.Hour))
	srvA := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{f.oldCert}})
	f.srvB = testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{f.oldCert}})
	f.a = f.e.addAsset(srvA.Addr)
	f.e.scanAndWait(f.a.ID)
	if scanBBefore {
		f.b = f.e.addAsset(f.srvB.Addr)
		f.e.scanAndWait(f.b.ID)
	}
	f.id = assign(t, f.e, map[string]any{"kind": "certificate", "certificate": f.oldFP})
	restart(t, srvA, f.newCert)
	f.e.scanAndWait(f.a.ID)
	return f
}

// A renewal stays not verifiable when an endpoint that served the old certificate is deleted before it
// showed the new one, and pruning that endpoint's older scans does not drop it from what is checked.
func TestARenewalCoversEndpointsDeletedOrPrunedSince(t *testing.T) {
	t.Run("deleted", func(t *testing.T) {
		f := newRenewal(t, true)
		if v := verificationOf(t, f.e, f.id); v.Status != "waiting" {
			t.Fatalf("before the second endpoint is rescanned: %+v", v)
		}
		if s, b := f.e.do("DELETE", "/api/v1/assets/"+itoa(f.b.ID), nil); s != 204 && s != 200 {
			t.Fatalf("delete: %d %s", s, b)
		}
		if v := verificationOf(t, f.e, f.id); v.Status != "not-verifiable" || !strings.Contains(v.Detail, "deleted") {
			t.Fatalf("an endpoint that served the old certificate was deleted: %+v", v)
		}
	})
	t.Run("pruned", func(t *testing.T) {
		defer func(n int) { store.Retention = n }(store.Retention)
		store.Retention = 2
		f := newRenewal(t, true)
		for range 3 { // the scan from before the assignment is pruned
			f.e.scanAndWait(f.b.ID)
		}
		if v := verificationOf(t, f.e, f.id); v.Status != "not-verified" || !strings.Contains(v.Detail, f.b.Name) {
			t.Fatalf("the second endpoint still serves the old certificate: %+v", v)
		}
	})
}

// Every endpoint a scan saw serving the old certificate must show the new one, including an endpoint
// first scanned after the renewal was assigned; and such an endpoint deleted later still counts.
func TestARenewalCoversEndpointsFirstScannedAfterTheAssignment(t *testing.T) {
	f := newRenewal(t, false)
	f.b = f.e.addAsset(f.srvB.Addr)
	f.e.scanAndWait(f.b.ID)
	if v := verificationOf(t, f.e, f.id); v.Status != "not-verified" || !strings.Contains(v.Detail, f.b.Name+" still presents it") {
		t.Fatalf("an endpoint first scanned after the assignment still serves the old certificate: %+v", v)
	}
	if fx := fixes(t, f.e); len(fx.Fixed) != 0 {
		t.Fatalf("fixed %d", len(fx.Fixed))
	}
	if s, b := f.e.do("DELETE", "/api/v1/assets/"+itoa(f.b.ID), nil); s != 204 && s != 200 {
		t.Fatalf("delete: %d %s", s, b)
	}
	if v := verificationOf(t, f.e, f.id); v.Status != "not-verifiable" {
		t.Fatalf("that endpoint deleted before it showed the new certificate: %+v", v)
	}

	// The control: both endpoints renewed verifies.
	g := newRenewal(t, true)
	restart(t, g.srvB, g.newCert)
	g.e.scanAndWait(g.b.ID)
	if v := verificationOf(t, g.e, g.id); v.Status != "verified" {
		t.Fatalf("both endpoints renewed: %+v", v)
	}
}
