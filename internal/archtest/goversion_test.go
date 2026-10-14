package archtest

import (
	"regexp"
	"strings"
	"testing"
)

// REQ-PQS-9 (PRD-008): the Go version go.mod requires is the one the README and CONTRIBUTING name.
// crypto/mldsa arrived in Go 1.27, so an older toolchain cannot build the scanner's ML-DSA checks.
func TestDocsNameTheGoVersion(t *testing.T) {
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+)`).FindStringSubmatch(readFile(t, repoRoot+"/go.mod"))
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}
	v := m[1]
	if v < "1.27" {
		t.Errorf("go.mod requires Go %s; crypto/mldsa needs 1.27", v)
	}
	for file, want := range map[string]string{
		"README.md":       "Go " + v + " or newer",
		"CONTRIBUTING.md": "Go " + v + "+",
	} {
		if !strings.Contains(readFile(t, repoRoot+"/"+file), want) {
			t.Errorf("%s does not say %q", file, want)
		}
	}
	if !strings.Contains(readFile(t, repoRoot+"/README.md"), "go-"+v+"%2B") {
		t.Errorf("README badge does not say go-%s+", v)
	}
}
