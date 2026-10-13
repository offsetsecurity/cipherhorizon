package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

var labelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// targetSpec is what a person typed, parsed: the host and port, and what the scheme said.
type targetSpec struct {
	host string
	port int
	// portGiven is false when the port is the default for the scheme (443, or 22 for ssh://).
	portGiven bool
	// starttls is set by a STARTTLS scheme (smtp://) or "none" by https://; empty otherwise.
	starttls string
	// protocol is "ssh" for ssh://, "tls" for any TLS scheme, and empty without a scheme.
	protocol string
}

// normalizeTarget turns what a person types into a host and port (AC-01.4).
// A URL is accepted and reduced to its host and port; credentials, spaces and
// malformed names or ports are refused with a reason. ssh:// names an SSH server (PRD-008).
func normalizeTarget(input string) (targetSpec, error) {
	var t targetSpec
	s := strings.TrimSpace(input)
	if s == "" {
		return t, fmt.Errorf("empty")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return t, fmt.Errorf("contains whitespace")
	}
	schemePort := 0
	if i := strings.Index(s, "://"); i >= 0 {
		switch sc := strings.ToLower(s[:i]); sc {
		case "ssh":
			t.protocol, schemePort = "ssh", 22
			s = s[i+3:]
		case "https", "http", "tls", "ssl":
			t.starttls, t.protocol = "none", "tls"
			s = s[i+3:]
		default:
			// A STARTTLS service named by its scheme: smtp://, imap://, ldaps:// ... (REQ-SX-2).
			rest, proto, defPort, _, serr := tlsprobe.SplitScheme(s)
			if serr != nil {
				return t, fmt.Errorf("unsupported scheme %q", s[:i])
			}
			t.starttls, t.protocol, schemePort, s = proto, "tls", defPort, rest
			if t.starttls == "" {
				t.starttls = "none"
			}
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if strings.ContainsAny(s, "@\\") {
		return t, fmt.Errorf("credentials and backslashes are not allowed")
	}
	pt, err := tlsprobe.ParseTarget(s)
	if err != nil {
		return t, err
	}
	_, _, perr := net.SplitHostPort(s)
	t.portGiven = perr == nil
	if !t.portGiven && schemePort != 0 {
		pt.Port = schemePort
	}
	t.host, t.port = strings.TrimSuffix(strings.ToLower(pt.Host), "."), pt.Port
	if t.host == "" {
		return t, fmt.Errorf("empty host")
	}
	if net.ParseIP(t.host) == nil {
		if len(t.host) > 253 {
			return t, fmt.Errorf("host name is too long")
		}
		for _, label := range strings.Split(t.host, ".") {
			if !labelRE.MatchString(label) {
				return t, fmt.Errorf("%q is not a valid host name", t.host)
			}
		}
	}
	return t, nil
}

// assetKindFor decides TLS or SSH (PRD-008 REQ-SHW-1): a scheme decides; otherwise the requested
// protocol ("tls", "ssh", or "auto"/"" meaning port 22 is SSH and anything else TLS). It returns
// the kind and, for SSH chosen without a port, the port to use.
func assetKindFor(t targetSpec, requested string) (kind string, port int, msg string) {
	port = t.port
	req := strings.ToLower(strings.TrimSpace(requested))
	if t.protocol != "" && req != "" && req != "auto" && req != t.protocol {
		return "", 0, "the scheme says " + t.protocol + " but protocol " + req + " was chosen"
	}
	p := t.protocol
	if p == "" {
		switch req {
		case "", "auto":
			p = "tls"
			if t.portGiven && t.port == 22 {
				p = "ssh"
			}
		case "tls", "ssh":
			p = req
		default:
			return "", 0, "protocol must be auto, tls or ssh"
		}
	}
	if p == "ssh" {
		if !t.portGiven {
			port = 22
		}
		if t.starttls != "" && t.starttls != "none" {
			return "", 0, "STARTTLS applies to TLS endpoints, not SSH"
		}
		return store.KindSSH, port, ""
	}
	return store.KindTLS, port, ""
}

// normalizeTags trims, de-duplicates and bounds tags.
func normalizeTags(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		if len(t) > 30 {
			return nil, fmt.Errorf("tag %q is longer than 30 characters", t)
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	if len(out) > 10 {
		return nil, fmt.Errorf("at most 10 tags")
	}
	return out, nil
}

// allowedIntervals are the rescan schedules the product offers (seconds; 0 = off).
var allowedIntervals = map[int]bool{0: true, 3600: true, 21600: true, 86400: true, 604800: true}
