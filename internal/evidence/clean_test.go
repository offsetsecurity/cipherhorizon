package evidence

import (
	"strings"
	"testing"
)

func TestSafeText(t *testing.T) {
	for s, want := range map[string]bool{
		"Program Files/App/libcrypto-3-x64.dll": true,
		"caf\u00e9/\u5de5\u5177.dll":            true, // non-ASCII is fine
		"a\nb":                                  false,
		"a\x1b[31mb":                            false,
		"a\x00b":                                false,
		"a\x7fb":                                false,
		"bad\xffutf8":                           false,
		strings.Repeat("a", 1025):               false,
	} {
		if got := SafeText(s, 1024); got != want {
			t.Errorf("SafeText(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestClean(t *testing.T) {
	if got := Clean("3.5\x1b[31m.7\xff", 64); got != "3.5?[31m.7?" {
		t.Errorf("Clean = %q", got)
	}
	if got := Clean(strings.Repeat("\u00e9", 100), 10); len(got) > 10 {
		t.Errorf("not truncated: %d bytes", len(got))
	}
	if got := Clean("plain", 64); got != "plain" {
		t.Errorf("Clean altered clean text: %q", got)
	}
	// Whatever Clean returns must pass SafeText.
	if s := Clean("x\ny\x00\xfe\xfdz", 64); !SafeText(s, 64) {
		t.Errorf("Clean output %q is not safe text", s)
	}
}
