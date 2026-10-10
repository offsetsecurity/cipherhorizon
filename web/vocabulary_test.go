package web

import (
	"regexp"
	"strings"
	"testing"
)

// PRD-005 REQ-LANG-1/2: the primary surfaces speak the user's words. A person who came to scan
// an endpoint or to collect a CBOM never has to learn the product's internal model on these
// pages: no "estate", "asset", "service", "host" (a machine is a machine), "evidence class",
// "observation", "rung", "stream", "possible matches" or "based on evidence only".

var primarySurfaces = []string{
	"static/index.html",
	"static/js/views/scan.js",
	"static/js/views/reports.js",
	"static/js/views/inventory.js",
	"static/js/views/systems.js",
}

var forbiddenWords = regexp.MustCompile(`(?i)\bestate\b|\bassets?\b|\bservices?\b|\bhosts?\b|evidence class|\bobservations?\b|\brungs?\b|\bstreams?\b|possible match|based on evidence only`)

// literals returns the text a page shows: string literals of a script, or the text between
// tags of an HTML file. Comments, identifiers and attribute values are not shown to people.
func literals(name, body string) []string {
	if strings.HasSuffix(name, ".html") {
		noScript := regexp.MustCompile(`(?s)<script.*?</script>|<svg.*?</svg>|<[^>]+>`).ReplaceAllString(body, "\n")
		return strings.Split(noScript, "\n")
	}
	body = regexp.MustCompile(`(?m)^\s*//.*$|/\*(?s:.*?)\*/`).ReplaceAllString(body, "")
	return regexp.MustCompile("'(?:[^'\\\\\n]|\\\\.)*'|`(?:[^`\\\\]|\\\\.)*`").FindAllString(body, -1)
}

// shown removes the parts of a literal that are code or terms of art, not the internal words:
// "host:port" is notation, "stream cipher" is a cipher, and a route or API path is an address.
func shown(lit string) string {
	lit = strings.ReplaceAll(lit, "host:port", "")
	lit = regexp.MustCompile(`(?i)stream[ -]cipher`).ReplaceAllString(lit, "") // a kind of cipher, not the internal "stream"
	return regexp.MustCompile(`#/[\w/?=&.-]*|/api/v1/[\w/?=&.${}-]*|\./[\w.-]+\.js`).ReplaceAllString(lit, "")
}

func vocabularyViolations(name, body string) []string {
	var out []string
	for _, lit := range literals(name, body) {
		if m := forbiddenWords.FindString(shown(lit)); m != "" {
			out = append(out, m+" in "+strings.TrimSpace(lit))
		}
	}
	return out
}

func TestPrimarySurfacesSpeakTheUsersWords(t *testing.T) {
	files := embedded(t)
	for _, name := range primarySurfaces {
		body, ok := files[name]
		if !ok {
			t.Fatalf("%s is not embedded", name)
		}
		for _, v := range vocabularyViolations(name, body) {
			t.Errorf("%s: %s", name, v)
		}
	}
	// Negative control: the guard does see a forbidden word in a literal and in HTML text.
	if len(vocabularyViolations("x.js", "const t = 'Your estate';")) == 0 ||
		len(vocabularyViolations("x.html", "<p>Hosts</p>")) == 0 ||
		len(vocabularyViolations("x.js", "// the estate, in a comment\nconst t = 'Scan host:port';")) != 0 {
		t.Error("the vocabulary guard does not work")
	}
}
