package archtest

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// PRD-007 REQ-LM-1, REQ-LM-2: every relative link in the README and the launch documentation
// points at a file that exists, and every #anchor at a heading that exists.
func TestReadmeLinksResolve(t *testing.T) {
	docs := []string{"README.md", "SECURITY.md", "docs/deploy.md", "docs/CI.md", "docs/engineering/RELEASE-CHECKLIST-1.0.md"}
	site, _ := filepath.Glob("../../site/*.html")
	for _, s := range site {
		rel, _ := filepath.Rel("../..", s)
		docs = append(docs, filepath.ToSlash(rel))
	}
	mdLink := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	htmlLink := regexp.MustCompile(`(?:href|src)="([^"]+)"`)
	for _, doc := range docs {
		b, err := os.ReadFile(filepath.Join("../..", doc))
		if err != nil {
			t.Errorf("%s: %v", doc, err)
			continue
		}
		re := mdLink
		if strings.HasSuffix(doc, ".html") {
			re = htmlLink
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			target := m[1]
			switch {
			case strings.HasPrefix(target, "http://"), strings.HasPrefix(target, "https://"), strings.HasPrefix(target, "mailto:"),
				strings.HasPrefix(target, "../../"), // GitHub's own pages (releases, the security tab)
				strings.HasPrefix(target, "<"):
				continue
			}
			file, anchor, _ := strings.Cut(target, "#")
			path := filepath.Join("../..", filepath.Dir(doc), file)
			if file == "" {
				path = filepath.Join("../..", doc)
			}
			body, err := os.ReadFile(path)
			if err != nil && strings.HasPrefix(doc, "site/") {
				// The Pages workflow copies the fonts and images in from where they live.
				for _, alt := range siteAssets(file) {
					if b, aerr := os.ReadFile(alt); aerr == nil {
						body, err = b, nil
						break
					}
				}
			}
			if err != nil {
				if fi, serr := os.Stat(path); serr == nil && fi.IsDir() {
					continue
				}
				t.Errorf("%s links to %s, which does not exist", doc, target)
				continue
			}
			if anchor != "" && strings.HasSuffix(path, ".md") && !hasHeading(string(body), anchor) {
				t.Errorf("%s links to %s, but there is no such heading", doc, target)
			}
			if anchor != "" && strings.HasSuffix(path, ".html") && !strings.Contains(string(body), `id="`+anchor+`"`) {
				t.Errorf("%s links to %s, but there is no such id", doc, target)
			}
		}
	}
}

// hasHeading reports whether a Markdown document has a heading whose GitHub slug is anchor.
func hasHeading(md, anchor string) bool {
	strip := regexp.MustCompile("[^a-z0-9 _-]")
	for _, line := range strings.Split(md, "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "#")))
		h = strings.ReplaceAll(strip.ReplaceAllString(h, ""), " ", "-")
		if h == anchor {
			return true
		}
	}
	return false
}

// siteAssets maps a site path to the repository files .github/workflows/pages.yml copies there.
func siteAssets(file string) []string {
	switch {
	case strings.HasPrefix(file, "fonts/"):
		return []string{"../../web/static/" + file}
	case strings.HasPrefix(file, "img/"):
		return []string{"../../web/static/" + file, "../../docs/" + file}
	}
	return nil
}

// REQ-LM-2: the docs site makes no external request (its fonts, images and styles are its own);
// links to other sites are fine, loading from them is not.
func TestSiteMakesNoExternalRequests(t *testing.T) {
	files, _ := filepath.Glob("../../site/*")
	if len(files) < 8 {
		t.Fatalf("the site has %d files, want the seven pages and a stylesheet", len(files))
	}
	load := regexp.MustCompile(`(?i)(?:src=|<link[^>]+href=|url\()["']?(?:https?:)?//`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := load.FindString(string(b)); m != "" {
			t.Errorf("%s loads something from another site: %s", f, m)
		}
		if strings.ContainsAny(string(b), "—–") {
			t.Errorf("%s has an em-dash or en-dash", f)
		}
	}
}
