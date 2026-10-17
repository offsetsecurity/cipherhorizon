package app

import (
	"strings"
	"testing"
)

// PRD-009 REQ-PORT-1 and REQ-PORT-2: where serve listens, from --addr, --port and the
// environment.
func TestServePortFlag(t *testing.T) {
	noEnv := func(string) string { return "" }
	for _, c := range []struct {
		addr             string
		port             int
		addrSet, portSet bool
		want             string
	}{
		{"", -1, false, false, "127.0.0.1:8080"},
		{"", 9000, false, true, "127.0.0.1:9000"},
		{"0.0.0.0", 9000, true, true, "0.0.0.0:9000"},
		{"0.0.0.0", -1, true, false, "0.0.0.0:8080"},
		{"127.0.0.1:8443", -1, true, false, "127.0.0.1:8443"},
		{":8081", -1, true, false, ":8081"},
		{"::1", 9001, true, true, "[::1]:9001"},
		{"[::1]:9002", -1, true, false, "[::1]:9002"},
		{"localhost", 0, true, true, "localhost:0"},
	} {
		got, err := listenAddr(c.addr, c.port, c.addrSet, c.portSet, noEnv)
		if err != nil || got != c.want {
			t.Errorf("listenAddr(%q, %d) = %q, %v; want %q", c.addr, c.port, got, err, c.want)
		}
	}
}

func TestServeAddrAndPortConflict(t *testing.T) {
	noEnv := func(string) string { return "" }
	_, err := listenAddr("0.0.0.0:80", 81, true, true, noEnv)
	if err == nil || !strings.Contains(err.Error(), "--addr") || !strings.Contains(err.Error(), "--port") {
		t.Errorf("an --addr with a port and a --port: err = %v, want one naming both flags", err)
	}
	for _, p := range []int{-2, 65536, 100000} {
		if _, err := listenAddr("", p, false, true, noEnv); err == nil || !strings.Contains(err.Error(), "not a port number") {
			t.Errorf("--port %d: err = %v", p, err)
		}
	}
}

func TestServePortFromEnvironment(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		name             string
		env              map[string]string
		addr             string
		port             int
		addrSet, portSet bool
		want             string
	}{
		{"port only", map[string]string{portEnv: "9100"}, "", -1, false, false, "127.0.0.1:9100"},
		{"addr host and port", map[string]string{addrEnv: "0.0.0.0", portEnv: "9100"}, "", -1, false, false, "0.0.0.0:9100"},
		{"addr with a port", map[string]string{addrEnv: "0.0.0.0:9200"}, "", -1, false, false, "0.0.0.0:9200"},
		{"the --port flag wins", map[string]string{portEnv: "9100"}, "", 9300, false, true, "127.0.0.1:9300"},
		{"the --port flag beats the address's port", map[string]string{addrEnv: "0.0.0.0:9200"}, "", 9300, false, true, "0.0.0.0:9300"},
		{"the --addr flag wins", map[string]string{addrEnv: "10.0.0.1", portEnv: "9100"}, "127.0.0.1:9400", -1, true, false, "127.0.0.1:9400"},
		{"--addr host with the port from the environment", map[string]string{portEnv: "9100"}, "0.0.0.0", -1, true, false, "0.0.0.0:9100"},
	} {
		got, err := listenAddr(c.addr, c.port, c.addrSet, c.portSet, env(c.env))
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	_, err := listenAddr("", -1, false, false, env(map[string]string{portEnv: "eighty"}))
	if err == nil || !strings.Contains(err.Error(), portEnv) {
		t.Errorf("a bad %s: err = %v, want one naming the variable", portEnv, err)
	}
	_, err = listenAddr("", -1, false, false, env(map[string]string{addrEnv: "0.0.0.0:80", portEnv: "81"}))
	if err == nil {
		t.Errorf("%s with a port and %s: no error", addrEnv, portEnv)
	}
}

func TestBusyPortMessageSuggestsTheNextPort(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:8080": "port 8080 is already in use on 127.0.0.1",
		":65535":         "--port 65534",
	} {
		if got := busyPortMessage(addr); !strings.Contains(got, want) {
			t.Errorf("busyPortMessage(%q) = %q, want it to contain %q", addr, got, want)
		}
	}
	if got := busyPortMessage("127.0.0.1:8080"); !strings.Contains(got, "--port 8081") {
		t.Errorf("no next port suggested: %q", got)
	}
}
