package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type findZone struct {
	a  map[string][]string
	mx []string
}

func (z findZone) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, a := range z.a[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	if out == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}
func (findZone) LookupCNAME(_ context.Context, host string) (string, error) { return host + ".", nil }
func (z findZone) LookupMX(context.Context, string) ([]*net.MX, error) {
	var out []*net.MX
	for _, h := range z.mx {
		out = append(out, &net.MX{Host: h + "."})
	}
	return out, nil
}
func (findZone) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, nil }
func (findZone) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (findZone) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, nil
}

type findLogs struct{ asked *int }

func (findLogs) Name() string { return "the test log search" }
func (f findLogs) Search(context.Context, string) ([]string, error) {
	*f.asked++
	return []string{"api.example.com", "*.example.com"}, nil
}

func runFind(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Main(context.Background(), append([]string{"find"}, args...), Env{Stdout: &out, Stderr: &errb})
	return code, out.String(), errb.String()
}

func TestFindCommand(t *testing.T) {
	asked := 0
	oldR, oldD, oldC := findResolver, findDial, findCT
	defer func() { findResolver, findDial, findCT = oldR, oldD, oldC }()
	findResolver = findZone{a: map[string][]string{"example.com": {"192.0.2.1"}, "mail.example.com": {"192.0.2.25"},
		"api.example.com": {"192.0.2.2"}, "git.example.com": {"192.0.2.7"}}, mx: []string{"mail.example.com"}}
	open := map[string]bool{"192.0.2.1:443": true, "192.0.2.25:25": true, "192.0.2.2:443": true, "192.0.2.7:22": true}
	findDial = func(_ context.Context, addr string, port int) (net.Conn, error) {
		if open[fmt.Sprintf("%s:%d", addr, port)] {
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		}
		return nil, errors.New("refused")
	}
	findCT = findLogs{asked: &asked}

	// By default: the domain's records only, names on standard output, the summary on standard error.
	code, stdout, stderr := runFind(t, "Example.com")
	if code != ExitOK || stdout != "example.com\nmail.example.com\n" {
		t.Errorf("default: exit %d, stdout %q", code, stdout)
	}
	if asked != 0 {
		t.Error("certificate logs were searched without --ct")
	}
	for _, want := range []string{"example.com: 2 names, 2 resolve, 2 answer on a port", "certificate logs           not used", "No source knows every name"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary lacks %q:\n%s", want, stderr)
		}
	}

	list := filepath.Join(t.TempDir(), "names.txt")
	if err := os.WriteFile(list, []byte("# ours\ngit.example.com\ngone.example.com\nother.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runFind(t, "--ct", "--list", list, "--targets", "example.com")
	if code != ExitOK || stdout != "api.example.com:443\nexample.com:443\ngit.example.com:22\nmail.example.com:25\n" {
		t.Errorf("--targets: exit %d, stdout %q", code, stdout)
	}
	if asked != 1 || !strings.Contains(stderr, "1 supplied names are not under example.com") || !strings.Contains(stderr, "*.example.com") {
		t.Errorf("asked=%d summary:\n%s", asked, stderr)
	}
	if _, stdout, _ = runFind(t, "--list", list, "--all", "--no-ports", "example.com"); !strings.Contains(stdout, "gone.example.com\n") {
		t.Errorf("--all lists names that do not resolve: %q", stdout)
	}
	if _, stdout, _ = runFind(t, "--json", "example.com"); !strings.Contains(stdout, `"domain": "example.com"`) || !strings.Contains(stdout, `"ports"`) {
		t.Errorf("--json: %q", stdout)
	}
	for name, args := range map[string][]string{
		"no domain": {}, "two domains": {"a.example", "b.example"}, "an address": {"192.0.2.1"},
		"targets without ports": {"--targets", "--no-ports", "example.com"}, "a missing list": {"--list", filepath.Join(t.TempDir(), "absent"), "example.com"},
	} {
		if code, stdout, _ := runFind(t, args...); code != ExitFatal || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want a fatal error and nothing printed", name, code, stdout)
		}
	}
}
