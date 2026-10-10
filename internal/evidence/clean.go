package evidence

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// SafeText reports whether s is fit to carry as host-supplied data: valid UTF-8, no
// control characters, and at most max bytes. Host strings (file names, versions) are
// attacker-controlled; a sensor that meets one that fails this must skip it and say so
// in its coverage, never pass it on, because Validate would reject it and a single
// hostile name must not be able to abort an inventory.
func SafeText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Clean makes a host-supplied string safe to carry: invalid UTF-8 and control
// characters become '?', and the result is truncated to max bytes. Use it for values
// that are expected to be tidy (a version, an architecture) where dropping the whole
// observation would lose a real finding.
func Clean(s string, max int) string {
	var sb strings.Builder
	for _, r := range strings.ToValidUTF8(s, "?") {
		if sb.Len()+utf8.RuneLen(r) > max {
			break
		}
		if unicode.IsControl(r) {
			r = '?'
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
