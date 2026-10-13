package web

import (
	"os"
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
		"static/js/auth.js":           {"Quantum-safe before it", "Post-quantum readiness, protocol by protocol", "Scanners that show their work", "An inventory you can hand over", "TLS · SSH · post-quantum readiness", "TLS, SSH and, next, VPN", "post-quantum-cryptography-readiness.html"},
		"static/js/views/overview.js": {"class: 'eyebrow'", "Post-quantum readiness · TLS · SSH · CBOM", "Scan an endpoint for post‑quantum readiness", "For TLS", "For SSH"},
		// UX-REVIEW-008 S4: About says what the product is; Help how to use it; Settings who may.
		"static/js/views/about.js":    {"NIST IR 8547", "FIPS 203, 204, 205", "Developed by", "post-quantum-cryptography-readiness", "Open-source components", "Reference data"},
		"static/js/views/help.js":     {"Protocols, and how each is judged", "Scan a TLS endpoint", "Scan an SSH server", "Inventory a machine", "Post-quantum readiness levels", "The TLS hygiene score", "The SSH baseline", "What is and is not checked", "Command line and CI"},
		"static/js/views/settings.js": {"Turn on sign-in", "Turn off sign-in", "This server", "--open-network"},
	} {
		for _, w := range wants {
			if !strings.Contains(f[file], w) {
				t.Errorf("%s lacks %q", file, w)
			}
		}
	}
}

// PRD-008 REQ-SHW-3: an SSH report speaks SSH, not TLS.
func TestSSHReportCopyHasNoTLSWords(t *testing.T) {
	body := embedded(t)["static/js/views/report-ssh.js"]
	if body == "" {
		t.Fatal("report-ssh.js is not embedded")
	}
	blockComment := regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment := regexp.MustCompile(`(?m)(^|\s)//.*$`)
	tlsWords := regexp.MustCompile(`(?i)cipher suites?|certificate chain|TLS hygiene|handshake|\bTLS\b`)
	code := lineComment.ReplaceAllString(blockComment.ReplaceAllString(body, ""), "$1")
	for n, line := range strings.Split(code, "\n") {
		if m := tlsWords.FindString(line); m != "" {
			t.Errorf("report-ssh.js:%d says %q: %s", n+1, m, strings.TrimSpace(line))
		}
	}
}

// PRD-008 REQ-SHE-5, REQ-SHW-2 (UX-DESIGN-007 §1): the interface calls an SSH server an SSH server,
// and never gives it a score.
func TestSSHServersAreNamedAndNotScored(t *testing.T) {
	blockComment := regexp.MustCompile(`(?s)/\*.*?\*/|<!--.*?-->`)
	lineComment := regexp.MustCompile(`(?m)(^|\s)//.*$`)
	wrong := regexp.MustCompile(`(?i)SSH endpoints?\b|SSH hygiene|SSH score`)
	for name, body := range embedded(t) {
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".html") {
			continue
		}
		code := lineComment.ReplaceAllString(blockComment.ReplaceAllString(body, ""), "$1")
		for n, line := range strings.Split(code, "\n") {
			if m := wrong.FindString(line); m != "" {
				t.Errorf("%s:%d says %q: %s", name, n+1, m, strings.TrimSpace(line))
			}
		}
	}
}

// PRD-008 REQ-SHW-8: no surface still introduces the product as a TLS scanner alone.
func TestNoSurfaceSaysTLSScannerAlone(t *testing.T) {
	old := regexp.MustCompile(`for every TLS endpoint you run|TLS and post-quantum scanner|TLS scanner · CBOM|A TLS scanner that shows its work|readiness and TLS scanner`)
	for name, body := range embedded(t) {
		if m := old.FindString(body); m != "" {
			t.Errorf("%s still says %q", name, m)
		}
	}
	// And the files outside the interface that introduce it.
	for _, f := range []string{"../README.md", "../Dockerfile", "../.goreleaser.yaml", "../internal/app/app.go", "../internal/reportpdf/frame.go",
		"../site/index.html", "../site/start.html", "../site/faq.html"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := old.FindString(string(b)); m != "" {
			t.Errorf("%s still says %q", f, m)
		}
	}
}
