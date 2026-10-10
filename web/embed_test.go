package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// The UI must work air-gapped and must never turn scanned data into markup
// (PRD-001 AC-11.5, AC-11.6). These tests read the embedded files themselves.

func embedded(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := fs.WalkDir(content, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := content.ReadFile(path)
		if err != nil {
			return err
		}
		files[path] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
		t.Fatalf("only %d embedded files: %v", len(files), files)
	}
	return files
}

func TestNoExternalRequests(t *testing.T) {
	url := regexp.MustCompile(`(?i)(https?:)?//[a-z0-9.-]+\.[a-z]{2,}`)
	allowed := []string{
		"http://www.w3.org/2000/svg", // an XML namespace name, not a request
	}
	for name, body := range embedded(t) {
		if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css") || strings.HasSuffix(name, ".html") {
			for _, m := range url.FindAllString(body, -1) {
				ok := false
				for _, a := range allowed {
					if strings.Contains(a, m) {
						ok = true
					}
				}
				// example.com is reserved for documentation (RFC 2606): placeholder text, never fetched.
				if strings.Contains(m, "example.com") {
					ok = true
				}
				// Links to standards shown to the reader (Help's sources) are plain text hrefs the user
				// clicks; they are never fetched by the page itself.
				if !ok && (strings.HasSuffix(name, "about.js") || strings.HasSuffix(name, "help.js")) {
					ok = true
				}
				// The footer's credit link to the project's origin (Offset Security) is the same
				// kind of thing: a plain href the user may click, never fetched by the page.
				if !ok && strings.Contains(m, "offsetsecurity.net") {
					ok = true
				}
				if !ok {
					t.Errorf("%s references %q; the UI must make no external requests", name, m)
				}
			}
		}
	}
}

func TestNoInnerHTMLOrEval(t *testing.T) {
	banned := regexp.MustCompile(`\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function\(|dangerouslySet`)
	for name, body := range embedded(t) {
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".html") {
			continue
		}
		if loc := banned.FindStringIndex(body); loc != nil {
			t.Errorf("%s uses %q: data must reach the page only through textContent and properties", name, body[loc[0]:loc[1]])
		}
	}
}

func TestPageHasNoInlineScriptOrStyle(t *testing.T) {
	// The CSP is script-src 'self'; style-src 'self', so inline code would not run,
	// and its presence would mean the page depends on a policy it does not have.
	html := embedded(t)["static/index.html"]
	for _, m := range regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`).FindAllStringSubmatch(html, -1) {
		if !strings.Contains(m[1], "src=") || strings.TrimSpace(m[2]) != "" {
			t.Errorf("index.html has an inline <script>: %q", m[0])
		}
	}
	if regexp.MustCompile(`(?is)<style\b|\sstyle=`).MatchString(html) {
		t.Error("index.html has inline style")
	}
	if regexp.MustCompile(`(?i)\son[a-z]+=`).MatchString(html) {
		t.Error("index.html has an inline event handler")
	}
}

// The TLS hygiene rating is this product's own. Nothing the user sees may borrow another
// scanner's name or its vocabulary (letter grades, "grade").
func TestUIDoesNotBorrowAnotherScannersRatingVocabulary(t *testing.T) {
	banned := regexp.MustCompile(`(?i)ssl\s*labs|ssllabs|qualys|\bgrades?\b|\bgraded\b`)
	for name, body := range embedded(t) {
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".html") && !strings.HasSuffix(name, ".css") {
			continue
		}
		if m := banned.FindString(body); m != "" {
			t.Errorf("%s contains %q", name, m)
		}
	}
}
