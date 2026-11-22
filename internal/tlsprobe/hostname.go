package tlsprobe

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// IsHostName reports whether s is a valid host name: at most 253 characters of dot-separated
// labels, each 1 to 63 ASCII letters, digits, hyphens or underscores, not starting or ending
// with a hyphen. Case does not matter; a trailing dot is not part of the name and is refused
// here, so callers strip it first. An IP address with a zone, a URL, or a string with spaces,
// control characters or other non-host text is not a host name.
//
// This is the one rule for what a scan target's host may be when it is not an IP literal, and
// for what counts as a name under a scan-scope domain.
func IsHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			c := s[i] | 0x20 // ASCII lower case; leaves digits, '-' and '_' unchanged
			if (c < 'a' || c > 'z') && (s[i] < '0' || s[i] > '9') && s[i] != '-' && s[i] != '_' {
				return false
			}
			continue
		}
		label := s[start:i]
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		start = i + 1
	}
	return true
}

// CheckHost accepts a scan target's host when it is an IP address without a zone, or a host
// name (IsHostName) with or without one trailing dot, and says why otherwise.
func CheckHost(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	name := strings.TrimSuffix(host, ".")
	if len(name) > 253 {
		return errors.New("host name is too long")
	}
	if !IsHostName(name) {
		return fmt.Errorf("%q is not an IP address or a valid host name", host)
	}
	return nil
}
