package app_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
)

// fakeNet replaces the network of "tls scan": every connection goes to one test server, whatever
// address was asked for, and names resolve from a table. It counts both.
type fakeNet struct {
	server  string              // where every connection really goes
	names   map[string][]net.IP // nil: no lookup hook is installed
	dials   atomic.Int64
	lookups atomic.Int64
	asked   atomic.Value // the last address a connection was asked for
}

func (f *fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.dials.Add(1)
	f.asked.Store(addr)
	if f.server == "" {
		return nil, errors.New("fakeNet: no server")
	}
	var d net.Dialer
	return d.DialContext(ctx, network, f.server)
}

func (f *fakeNet) lookup(_ context.Context, host string) ([]net.IP, error) {
	f.lookups.Add(1)
	ips, ok := f.names[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

// runNet is run with the network replaced by f.
func runNet(t *testing.T, f *fakeNet, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runEnv(t, func(e *app.Env) { e.Dial, e.LookupIP = f.dial, f.lookup }, args...)
}

// runEnv is run with the Env changed by set.
func runEnv(t *testing.T, set func(*app.Env), args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	env := app.Env{
		Stdout: &out, Stderr: &errOut, OS: "linux",
		Tier:      func() string { return "user" },
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
		Hostname:  func() (string, error) { return "fixture-host", nil },
	}
	set(&env)
	code = app.Main(context.Background(), args, env)
	return code, out.String(), errOut.String()
}

const refusalLine = "cipherhorizon: target address is not allowed"

// wantRefused asserts what a caller of --public relies on: exit 1, nothing on stdout (no JSON,
// not even "[]"), one stderr line that starts with the refusal text, and no connection.
func wantRefused(t *testing.T, f *fakeNet, code int, stdout, stderr string) {
	t.Helper()
	if code != app.ExitFatal {
		t.Errorf("exit %d, want %d", code, app.ExitFatal)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing", stdout)
	}
	if !strings.HasPrefix(stderr, refusalLine) || strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
		t.Errorf("stderr = %q, want one line starting %q", stderr, refusalLine)
	}
	if n := f.dials.Load(); n != 0 {
		t.Errorf("%d connections were made, want none", n)
	}
}

func TestTLSScanPublicRefusesEveryNonPublicRange(t *testing.T) {
	for kind, target := range map[string]string{
		"loopback":                "127.0.0.1:443",
		"loopback, IPv6":          "[::1]:443",
		"private 10/8":            "10.1.2.3:443",
		"private 172.16/12":       "172.31.255.254:443",
		"private 192.168/16":      "192.168.1.1",
		"carrier NAT":             "100.64.0.1:443",
		"link-local":              "169.254.169.254:443",
		"link-local, IPv6":        "[fe80::1]:443",
		"multicast":               "224.0.0.1:443",
		"multicast, IPv6":         "[ff02::1]:443",
		"broadcast":               "255.255.255.255:443",
		"unspecified":             "0.0.0.0:443",
		"unspecified, IPv6":       "[::]:443",
		"0/8":                     "0.1.2.3:443",
		"documentation 1":         "192.0.2.7:443",
		"documentation 2":         "198.51.100.7:443",
		"documentation 3":         "203.0.113.7:443",
		"documentation, IPv6":     "[2001:db8::1]:443",
		"benchmark":               "198.19.0.1:443",
		"192.0.0.0/24":            "192.0.0.8:443",
		"reserved 240/4":          "240.0.0.1:443",
		"unique-local":            "[fd12:3456::1]:443",
		"metadata, Alibaba":       "100.100.100.200:443",
		"metadata, Azure":         "168.63.129.16:443",
		"metadata, Oracle":        "192.0.0.192:443",
		"metadata, AWS IPv6":      "[fd00:ec2::254]:443",
		"IPv4-mapped private":     "[::ffff:10.0.0.1]:443",
		"NAT64 private":           "[64:ff9b::a00:1]:443",
		"6to4 private":            "[2002:a00:1::1]:443",
		"Teredo, private client":  "[2001:0:808:808::f5ff:fffe]:443",
		"Teredo, loopback server": "[2001:0:7f00:1::f7f7:f7f7]:443",
	} {
		t.Run(kind, func(t *testing.T) {
			f := &fakeNet{}
			code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--public", target)
			wantRefused(t, f, code, stdout, stderr)
		})
	}
}

func TestTLSScanPublicScansAPublicAddress(t *testing.T) {
	f := &fakeNet{server: hybridServer(t)}
	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--no-certs", "--public", "8.8.8.8:443")
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"address": "8.8.8.8:443"`) || !strings.Contains(stdout, "TLS_AES_128_GCM_SHA256") {
		t.Errorf("the scan did not run as it does without --public:\n%.600s", stdout)
	}
	if f.dials.Load() == 0 || f.asked.Load() != "8.8.8.8:443" {
		t.Errorf("connections: %d, last asked for %v", f.dials.Load(), f.asked.Load())
	}
}

func TestTLSScanPublicRefusesANameWithOnePrivateAddress(t *testing.T) {
	f := &fakeNet{names: map[string][]net.IP{
		"mixed.example": {net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.5")},
	}}
	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--public", "mixed.example:443")
	wantRefused(t, f, code, stdout, stderr)
	if !strings.Contains(stderr, "10.0.0.5") || !strings.Contains(stderr, "mixed.example") {
		t.Errorf("stderr should name the address and the target: %s", stderr)
	}
}

// Every target is checked before the first scan starts: a refused second target means the
// first is not scanned either.
func TestTLSScanPublicChecksEveryTargetFirst(t *testing.T) {
	f := &fakeNet{server: hybridServer(t)}
	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--public", "8.8.8.8:443", "192.168.0.1:443")
	wantRefused(t, f, code, stdout, stderr)
}

// The name is resolved once, by the check; the scan connects to an address that was judged.
func TestTLSScanPublicResolvesANameOnce(t *testing.T) {
	f := &fakeNet{server: hybridServer(t), names: map[string][]net.IP{"public.example": {net.ParseIP("8.8.4.4")}}}
	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--no-certs", "--public", "public.example:8443")
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	if n := f.lookups.Load(); n != 1 {
		t.Errorf("the name was resolved %d times, want once", n)
	}
	if !strings.Contains(stdout, `"address": "8.8.4.4:8443"`) {
		t.Errorf("report address:\n%.400s", stdout)
	}
}

// A name that does not resolve is not a refusal: the result is what it is without --public.
func TestTLSScanPublicLeavesAnUnresolvedNameAlone(t *testing.T) {
	f := &fakeNet{names: map[string][]net.IP{}}
	code, stdout, stderr := runNet(t, f, "tls", "scan", "--json", "--public", "nosuchname.invalid")
	if code != app.ExitIncomplete || !strings.HasPrefix(stdout, "[") || strings.Contains(stderr, refusalLine) {
		t.Errorf("exit %d\nstdout: %.200s\nstderr: %s", code, stdout, stderr)
	}
	if f.dials.Load() != 0 {
		t.Errorf("%d connections for a name with no address", f.dials.Load())
	}
}

func TestTLSScanWithoutPublicStillScansLoopback(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--json", "--no-certs", hybridServer(t))
	if code != app.ExitOK || !strings.Contains(stdout, `"address": "127.0.0.1:`) {
		t.Errorf("exit %d\nstdout: %.300s\nstderr: %s", code, stdout, stderr)
	}
}

// The second line: a connection to an address that is not public is refused when it is made,
// with the default dialer and with an injected one.
func TestPublicDialRefusesAtConnectTime(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // test listener
	g := server.Guard{Public: true}

	if c, err := app.GuardDial(g, nil)(context.Background(), "tcp", l.Addr().String()); !errors.Is(err, server.ErrBlocked) {
		if c != nil {
			_ = c.Close()
		}
		t.Errorf("default dialer: err = %v, want a refusal", err)
	}

	f := &fakeNet{server: l.Addr().String()}
	if _, err := app.GuardDial(g, f.dial)(context.Background(), "tcp", "10.0.0.1:443"); !errors.Is(err, server.ErrBlocked) {
		t.Errorf("injected dialer: err = %v, want a refusal", err)
	}
	if f.dials.Load() != 0 {
		t.Error("the injected dialer was called for a refused address")
	}
	c, err := app.GuardDial(g, f.dial)(context.Background(), "tcp", "8.8.8.8:443")
	if err != nil {
		t.Fatalf("a public address was refused: %v", err)
	}
	_ = c.Close()
}

func TestTLSScanHelpListsPublic(t *testing.T) {
	code, _, stderr := run(t, "tls", "scan", "-h")
	if code != app.ExitOK || !strings.Contains(stderr, "\n  -public\n") {
		t.Errorf("exit %d; tls scan -h should list the flag on its own line:\n%s", code, stderr)
	}
}

func TestTLSScanPublicRejectsPrivateRevocation(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--public", "--revocation", "--revocation-private", "a.example")
	if code != app.ExitFatal || stdout != "" || !strings.Contains(stderr, "--revocation-private") {
		t.Errorf("exit %d stdout %q stderr %s", code, stdout, stderr)
	}
}
