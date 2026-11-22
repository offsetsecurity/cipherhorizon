package mcpserver_test

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/mcpserver"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
)

// countingListener accepts TCP connections on loopback and counts them, closing each at once.
func countingListener(t *testing.T) (port string, accepted func() int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), n.Load
}

// The scan tools take an IP address or a host name: a host with line breaks or an address with a
// zone is refused as an invalid target, and no connection is opened.
func TestScanToolsRefuseHostsThatAreNotNames(t *testing.T) {
	cs := connect(t, mcpserver.Options{Scan: loopback()})
	for _, tool := range []string{"tls_scan", "ssh_scan"} {
		port, accepted := countingListener(t)
		for _, host := range []string{
			"::ffff:127.0.0.1%x\r\nX-Extra: 1\r\nContent-Length: 0\r\n\r\nPOST /x HTTP/1.1\r\nHost: dummy.invalid",
			"::ffff:127.0.0.1%x",
			"127.0.0.1\r\nX-Extra: 1",
		} {
			res := call(t, cs, tool, map[string]any{"target": "[" + host + "]:" + port})
			if !res.IsError || !strings.Contains(text(res), "invalid target") {
				t.Errorf("%s %q: want an invalid-target error, got %q", tool, host, text(res))
			}
		}
		if n := accepted(); n != 0 {
			t.Errorf("%s opened %d connections for targets it should refuse", tool, n)
		}
	}
}

// Under a scope of domains, an address is in scope only by its address: a zone that ends in a
// scope domain does not make it a name under that domain.
func TestScanToolsKeepZonedAddressesInsideTheScope(t *testing.T) {
	for _, entries := range [][]string{{"example.com"}, {"example.com", "10.0.0.0/8"}} {
		scope, err := server.ParseScope(entries)
		if err != nil {
			t.Fatal(err)
		}
		opts := loopback()
		opts.Guard.Scope = scope
		cs := connect(t, mcpserver.Options{Scan: opts})
		for _, tool := range []string{"tls_scan", "ssh_scan"} {
			port, accepted := countingListener(t)
			for _, target := range []string{"127.0.0.1:" + port, "[::ffff:127.0.0.1%x.example.com]:" + port} {
				args := map[string]any{"target": target}
				if tool == "tls_scan" {
					args["httpChecks"] = false
				}
				if res := call(t, cs, tool, args); !res.IsError {
					t.Errorf("%s %s under scope %v: scanned, want a refusal", tool, target, entries)
				}
			}
			if n := accepted(); n != 0 {
				t.Errorf("%s under scope %v opened %d connections outside the scope", tool, entries, n)
			}
		}
	}
}
