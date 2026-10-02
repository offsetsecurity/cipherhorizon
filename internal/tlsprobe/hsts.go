package tlsprobe

import (
	"math"
	"strconv"
	"strings"
)

// Bounds on what is kept of the Strict-Transport-Security header.
const (
	maxHSTSValues   = 4
	maxHSTSValueLen = 512
)

// cleanHeaderValue strips control characters and bounds the length; header
// values are attacker-controlled and travel to the UI.
func cleanHeaderValue(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxHSTSValueLen {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// ParseHSTS parses the Strict-Transport-Security header values of one response
// by RFC 6797 §6.1:
//
//   - directives are separated by ";", names are case-insensitive, values are a
//     token or a quoted-string;
//   - max-age is required, once, and is 1*DIGIT;
//   - a directive appearing twice makes the whole header invalid (§6.1 rule 2);
//   - includeSubDomains takes no value; unknown directives are ignored.
//
// More than one header is a problem in itself: a user agent processes only the
// first (§8.1). The first value is the one parsed.
func ParseHSTS(values []string) *HSTSResult {
	h := &HSTSResult{}
	for _, v := range values {
		if len(h.Values) == maxHSTSValues {
			h.Problems = append(h.Problems, "more headers than were kept")
			break
		}
		h.Values = append(h.Values, cleanHeaderValue(v))
	}
	if len(h.Values) == 0 {
		return h
	}
	if len(values) > 1 {
		h.Problems = append(h.Problems, "the header is sent more than once; browsers use only the first")
	}
	seen := map[string]bool{}
	for _, d := range splitDirectives(h.Values[0]) {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		name, value, hasValue := strings.Cut(d, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if !isToken(name) {
			h.Problems = append(h.Problems, "unreadable directive "+strconv.Quote(d))
			continue
		}
		if seen[name] {
			h.Problems = append(h.Problems, "directive "+name+" appears more than once")
			continue
		}
		seen[name] = true
		if hasValue && strings.HasPrefix(value, `"`) {
			if len(value) < 2 || !strings.HasSuffix(value, `"`) {
				h.Problems = append(h.Problems, "unterminated quoted value in "+name)
				continue
			}
			value = value[1 : len(value)-1]
		}
		switch name {
		case "max-age":
			if !hasValue || value == "" || strings.Trim(value, "0123456789") != "" {
				h.Problems = append(h.Problems, "max-age is not a number of seconds")
				continue
			}
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				n = math.MaxInt64 // a valid but enormous value
			}
			h.MaxAge = &n
		case "includesubdomains":
			if hasValue {
				h.Problems = append(h.Problems, "includeSubDomains takes no value")
				continue
			}
			h.IncludeSubDomains = true
		case "preload":
			h.Preload = true
		}
	}
	if h.MaxAge == nil && !seen["max-age"] {
		h.Problems = append(h.Problems, "max-age is missing")
	}
	return h
}

// splitDirectives splits on ";" outside quoted strings.
func splitDirectives(v string) []string {
	var out []string
	var cur strings.Builder
	quoted, escaped := false, false
	for _, r := range v {
		switch {
		case escaped:
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case r == ';' && !quoted:
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	return append(out, cur.String())
}

// isToken reports whether s is an RFC 7230 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > 0x7e || r <= 0x20 || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, r) {
			return false
		}
	}
	return true
}
