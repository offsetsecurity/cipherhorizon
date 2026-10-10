package web

import (
	"regexp"
	"strings"
	"testing"
)

// PRD-007 REQ-ST-5 (DESIGN.md §3, §14): what the interface says has no em-dash or en-dash, none
// of the hype words, and no letter grades (the product rates with its own TLS hygiene score).
func TestUICopyRules(t *testing.T) {
	blockComment := regexp.MustCompile(`(?s)/\*.*?\*/|<!--.*?-->`)
	lineComment := regexp.MustCompile(`(?m)(^|\s)//.*$`)
	banned := regexp.MustCompile(`(?i)military[- ]grade|ai[- ]powered|quantum[- ]proof|revolutionary|unbreakable|bullet ?proof|cutting[- ]edge|next[- ]gen\b|best[- ]in[- ]class|world[- ]class|\bgrade [A-F][+-]?\b|\b[A-F][+-]? grade\b`)
	checked := 0
	for name, body := range embedded(t) {
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".html") {
			continue
		}
		checked++
		code := lineComment.ReplaceAllString(blockComment.ReplaceAllString(body, ""), "$1")
		for n, line := range strings.Split(code, "\n") {
			if strings.ContainsAny(line, "—–") {
				t.Errorf("%s:%d: an em-dash or en-dash in copy: %s", name, n+1, strings.TrimSpace(line))
			}
			if m := banned.FindString(line); m != "" {
				t.Errorf("%s:%d: %q is not how this product talks: %s", name, n+1, m, strings.TrimSpace(line))
			}
		}
	}
	if checked < 10 {
		t.Fatalf("only %d files checked", checked)
	}
}

// REQ-ST-1/2/3: the story is told where people see it first: sign-in, the Overview, About.
func TestTheProductTellsItsStory(t *testing.T) {
	f := embedded(t)
	for file, wants := range map[string][]string{
		"static/js/auth.js":           {"Quantum-safe before it", "Post-quantum readiness", "A TLS scanner that shows its work", "An inventory you can hand over", "TLS and post-quantum scanner", "post-quantum-cryptography-readiness.html"},
		"static/js/views/overview.js": {"class: 'eyebrow'", "Post-quantum readiness · TLS scanner · CBOM", "Scan an endpoint for post‑quantum readiness"},
		// UX-REVIEW-008 S4: About says what the product is; Help how to use it; Settings who may.
		"static/js/views/about.js":    {"NIST IR 8547", "FIPS 203, 204, 205", "Developed by", "post-quantum-cryptography-readiness", "Open-source components", "Reference data"},
		"static/js/views/help.js":     {"Scan an endpoint", "Inventory a machine", "Post-quantum readiness levels", "The TLS hygiene score", "What is and is not checked", "Command line and CI"},
		"static/js/views/settings.js": {"Turn on sign-in", "Turn off sign-in", "This server", "--open-network"},
	} {
		for _, w := range wants {
			if !strings.Contains(f[file], w) {
				t.Errorf("%s lacks %q", file, w)
			}
		}
	}
}
