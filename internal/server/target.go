package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

var labelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// normalizeTarget turns what a person types into a host and port (AC-01.4).
// A URL is accepted and reduced to its host and port; credentials, spaces and
// malformed names or ports are refused with a reason.
func normalizeTarget(input string) (host string, port int, starttls string, err error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", 0, "", fmt.Errorf("empty")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return "", 0, "", fmt.Errorf("contains whitespace")
	}
	schemePort := 0
	if i := strings.Index(s, "://"); i >= 0 {
		switch sc := strings.ToLower(s[:i]); sc {
		case "https", "http", "tls", "ssl":
			starttls = "none"
			s = s[i+3:]
		default:
			// A STARTTLS service named by its scheme: smtp://, imap://, ldaps:// ... (REQ-SX-2).
			rest, proto, defPort, _, serr := tlsprobe.SplitScheme(s)
			if serr != nil {
				return "", 0, "", fmt.Errorf("unsupported scheme %q", s[:i])
			}
			starttls, schemePort, s = proto, defPort, rest
			if starttls == "" {
				starttls = "none"
			}
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if strings.ContainsAny(s, "@\\") {
		return "", 0, "", fmt.Errorf("credentials and backslashes are not allowed")
	}
	t, err := tlsprobe.ParseTarget(s)
	if err != nil {
		return "", 0, "", err
	}
	if _, _, perr := net.SplitHostPort(s); perr != nil && schemePort != 0 {
		t.Port = schemePort
	}
	host = strings.TrimSuffix(strings.ToLower(t.Host), ".")
	if host == "" {
		return "", 0, "", fmt.Errorf("empty host")
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return "", 0, "", fmt.Errorf("host name is too long")
		}
		for _, label := range strings.Split(host, ".") {
			if !labelRE.MatchString(label) {
				return "", 0, "", fmt.Errorf("%q is not a valid host name", host)
			}
		}
	}
	return host, t.Port, starttls, nil
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
