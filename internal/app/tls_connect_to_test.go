package app_test

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// sniServer is a TLS server on loopback that records the server name of every ClientHello.
type sniServer struct {
	port  int
	mu    sync.Mutex
	names map[string]int
}

func startSNIServer(t *testing.T) *sniServer {
	t.Helper()
	ec, _, err := testserver.LoadCertificates()
	if err != nil {
		t.Fatal(err)
	}
	s := &sniServer{names: map[string]int{}}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{ec}}
	cfg.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		s.names[hi.ServerName]++
		s.mu.Unlock()
		return nil, nil
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s.port = l.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // test server
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	return s
}

func (s *sniServer) seen() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for k, v := range s.names {
		out[k] = v
	}
	return out
}

// The name cannot resolve, so a completed scan proves the address was used and no lookup made.
func TestTLSScanConnectTo(t *testing.T) {
	const name = "nosuchname.invalid"
	srv := startSNIServer(t)
	f := &fakeNet{names: map[string][]net.IP{}} // a lookup of any name fails, and is counted
	f.server = "127.0.0.1:" + strconv.Itoa(srv.port)
	target := name + ":" + strconv.Itoa(srv.port)

	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--http-checks=false", "--connect-to", "127.0.0.1", target)
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	if n := f.lookups.Load(); n != 0 {
		t.Errorf("the lookup hook was called %d times, want never", n)
	}

	var results []struct {
		Target string
		Report tlsprobe.Report
	}
	if err := json.Unmarshal([]byte(stdout), &results); err != nil || len(results) != 1 {
		t.Fatalf("stdout: %v\n%.300s", err, stdout)
	}
	rep, addr := results[0].Report, "127.0.0.1:"+strconv.Itoa(srv.port)
	if results[0].Target != target {
		t.Errorf("target = %q, want %q", results[0].Target, target)
	}
	if rep.Target.Host != name || rep.Target.SNI != name || rep.Target.Port != srv.port {
		t.Errorf("report.target = %+v, want host and sni %q", rep.Target, name)
	}
	if rep.Address != addr {
		t.Errorf("report.address = %q, want %q", rep.Address, addr)
	}
	if len(rep.Addresses) != 1 || rep.Addresses[0] != "127.0.0.1" {
		t.Errorf("report.addresses = %v, want the one address", rep.Addresses)
	}
	if rep.NoSNI == "" {
		t.Error("report.noSni is absent: the scan did not treat the target as a name")
	}
	if len(rep.Certificates) == 0 {
		t.Fatal("no certificate in the report")
	}
	// The test certificate is for "localhost": judged against the target's name, it does not
	// match, and the reason names the target.
	if c := rep.Certificates[0]; c.NameMatches || !strings.Contains(c.NameError, name) {
		t.Errorf("the certificate was not judged against %q: nameMatches=%t nameError=%q", name, c.NameMatches, c.NameError)
	}

	// The server saw the name, and no other name. A few hellos carry no server name at all, as in
	// any scan of a name: the one made without it on purpose (the noSni comparison) and the
	// SSLv3 hellos, which have no extensions.
	names := srv.seen()
	if names[name] == 0 || names[name] <= names[""] {
		t.Errorf("the server saw %q as server name %d times, no name %d times", name, names[name], names[""])
	}
	for other := range names {
		if other != name && other != "" {
			t.Errorf("the server saw another server name, %q: %v", other, names)
		}
	}
	if f.asked.Load() != addr {
		t.Errorf("connections were asked for %v, want %s", f.asked.Load(), addr)
	}
}

func TestTLSScanConnectToIPv6ReportAddress(t *testing.T) {
	f := &fakeNet{server: hybridServer(t)}
	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--no-certs", "--connect-to", "2606:4700:4700::1111", "v6.example:8443")
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	for _, want := range []string{`"address": "[2606:4700:4700::1111]:8443"`, `"target": "v6.example:8443"`, `"sni": "v6.example"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the result lacks %s", want)
		}
	}
	if f.lookups.Load() != 0 {
		t.Error("a lookup was made")
	}
}

func TestTLSScanConnectToUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"not an address":         {"--connect-to", "example.org", "a.example"},
		"address with a port":    {"--connect-to", "192.0.2.1:443", "a.example"},
		"address in brackets":    {"--connect-to", "[2001:db8::1]", "a.example"},
		"address with a zone":    {"--connect-to", "fe80::1%eth0", "a.example"},
		"two addresses":          {"--connect-to", "192.0.2.1,192.0.2.2", "a.example"},
		"empty after trimming":   {"--connect-to", " ", "a.example"},
		"more than one target":   {"--connect-to", "192.0.2.1", "a.example", "b.example"},
		"target is an address":   {"--connect-to", "192.0.2.1", "192.0.2.9:443"},
		"target is an IPv6 addr": {"--connect-to", "192.0.2.1", "[2001:db8::9]:443"},
		"no target":              {"--connect-to", "192.0.2.1"},
		"an empty address":       {"--connect-to", "", "a.example"},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeNet{}
			code, stdout, stderr := runNet(t, f, append([]string{"tls", "scan", "--json"}, args...)...)
			if code != app.ExitFatal || stdout != "" {
				t.Errorf("exit %d stdout %q\nstderr: %s", code, stdout, stderr)
			}
			if f.dials.Load() != 0 || f.lookups.Load() != 0 {
				t.Errorf("%d connections, %d lookups for a usage error", f.dials.Load(), f.lookups.Load())
			}
		})
	}
}

// With --public the --connect-to address is checked before any connection, as a target's own
// address is.
func TestTLSScanConnectToWithPublic(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "fd00::1", "169.254.169.254", "::ffff:192.168.0.1"} {
		f := &fakeNet{}
		code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--public", "--connect-to", addr, "www.example:443")
		wantRefused(t, f, code, stdout, stderr)
		if f.lookups.Load() != 0 {
			t.Errorf("%s: a lookup was made", addr)
		}
	}

	f := &fakeNet{server: hybridServer(t)}
	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--no-certs", "--public", "--connect-to", "8.8.8.8", "www.example:443")
	if code != app.ExitOK || !strings.Contains(stdout, `"address": "8.8.8.8:443"`) || f.lookups.Load() != 0 {
		t.Errorf("exit %d, %d lookups\nstdout: %.300s\nstderr: %s", code, f.lookups.Load(), stdout, stderr)
	}
}

func TestTLSScanHelpListsConnectTo(t *testing.T) {
	code, _, stderr := run(t, "tls", "scan", "-h")
	if code != app.ExitOK || !strings.Contains(stderr, "\n  -connect-to ADDRESS\n") {
		t.Errorf("exit %d; tls scan -h should list the flag on its own line:\n%s", code, stderr)
	}
}
