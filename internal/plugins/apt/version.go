package apt

import (
	"regexp"
	"strconv"
	"strings"
)

// version is a numeric major.minor.patch triple. Suffixes ("1.1.1w", "3.5.0~rc1")
// are ignored on purpose: capability gates in this package only ever ask
// "is the upstream release at least X.Y.Z".
type version [3]int

var leadingNumbersRE = regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// upstream extracts the upstream release from a Debian package version
// "[epoch:]upstream[-revision]" and parses its numeric prefix. ok is false when
// no numeric prefix can be read; callers must then treat gated capabilities as
// unknown (and omit them), never as present.
func upstream(debVersion string) (v version, ok bool) {
	s := debVersion
	if epoch, rest, found := strings.Cut(s, ":"); found && allDigits(epoch) {
		s = rest
	}
	if i := strings.LastIndex(s, "-"); i >= 0 {
		s = s[:i]
	}
	m := leadingNumbersRE.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.Atoi(m[i+1]) // digits by construction; overflow saturates harmlessly to 0
		}
	}
	return v, true
}

// atLeast reports whether v >= min.
func (v version) atLeast(min version) bool {
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
