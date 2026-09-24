package knowledge

import (
	"regexp"
	"strconv"
	"strings"
)

// Version is a numeric major.minor.patch triple. Suffixes ("1.1.1w", "3.5.0~rc1")
// are ignored on purpose: capability gates only ever ask "is the upstream release
// at least X.Y.Z".
type Version [3]int

var leadingNumbersRE = regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// ParseDebian extracts the upstream release from a Debian package version
// "[epoch:]upstream[-revision]" and parses its numeric prefix. ok is false when no
// numeric prefix can be read; callers must then treat gated capabilities as
// unknown (and omit them), never as present.
func ParseDebian(debVersion string) (v Version, ok bool) {
	s := debVersion
	if epoch, rest, found := strings.Cut(s, ":"); found && allDigits(epoch) {
		s = rest
	}
	if i := strings.LastIndex(s, "-"); i >= 0 {
		s = s[:i]
	}
	return parseNumeric(s)
}

// ParseFile parses a file-version string such as "3.5.7" or "3.5.7.0" (a PE
// version resource). Only the first three numbers are used.
func ParseFile(fileVersion string) (Version, bool) {
	return parseNumeric(strings.TrimSpace(fileVersion))
}

func parseNumeric(s string) (v Version, ok bool) {
	m := leadingNumbersRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.Atoi(m[i+1]) // digits by construction; overflow saturates harmlessly to 0
		}
	}
	return v, true
}

// AtLeast reports whether v >= min.
func (v Version) AtLeast(min Version) bool {
	for i := range v {
		if v[i] != min[i] {
			return v[i] > min[i]
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
