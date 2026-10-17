package app

import "testing"

// PRD-009 REQ-PORT-4: the installed service's "open at" URL follows --port.
func TestServiceURLFollowsPort(t *testing.T) {
	for args, want := range map[string][]string{
		"http://127.0.0.1:8080":  nil,
		"http://127.0.0.1:9000":  {"--port", "9000"},
		"http://127.0.0.1:9001":  {"--addr", "0.0.0.0", "--port=9001"},
		"https://127.0.0.1:8443": {"--addr", "0.0.0.0:8443", "--tls-cert", "c.pem"},
	} {
		if got := serviceURL(want); got != args {
			t.Errorf("serviceURL(%v) = %q, want %q", want, got, args)
		}
	}
}
