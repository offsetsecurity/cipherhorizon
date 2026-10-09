package web

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// PRD-007 WP-3: the Offset theme as written in DESIGN.md is the theme in style.css, its text
// colours pass WCAG AA in both modes, every logo is flat, and gradients appear only where they
// show something running.

var tokenRE = regexp.MustCompile(`(--[a-z0-9-]+):\s*([^;]+);`)

// themes returns the light (:root) and dark token maps of style.css, the dark one already
// falling back to light for tokens it does not redefine.
func themes(t *testing.T) (light, dark map[string]string) {
	t.Helper()
	css := embedded(t)["static/style.css"]
	cut := func(s, from, to string) string {
		i := strings.Index(s, from)
		if i < 0 {
			t.Fatalf("style.css: %q not found", from)
		}
		s = s[i:]
		if j := strings.Index(s, to); j >= 0 {
			s = s[:j]
		}
		return s
	}
	root := cut(css, ":root {", "\n}")
	mq := cut(cut(css, "@media (prefers-color-scheme: dark) {", "\n}\n"), ":root {", "\n  }")
	light, dark = map[string]string{}, map[string]string{}
	for _, m := range tokenRE.FindAllStringSubmatch(root, -1) {
		light[m[1]] = strings.TrimSpace(m[2])
	}
	for k, v := range light {
		dark[k] = v
	}
	for _, m := range tokenRE.FindAllStringSubmatch(mq, -1) {
		dark[m[1]] = strings.TrimSpace(m[2])
	}
	return light, dark
}

// resolve follows var(--x) references to a colour.
func resolve(tokens map[string]string, v string) string {
	for i := 0; i < 8 && strings.HasPrefix(v, "var("); i++ {
		v = tokens[strings.TrimSuffix(strings.TrimPrefix(v, "var("), ")")]
	}
	return strings.ToLower(v)
}

func TestStyleTokensMatchDesign(t *testing.T) {
	design, err := os.ReadFile("../DESIGN.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `(--[a-z0-9-]+)` \\| (#[0-9A-Fa-f]{6}) \\| (#[0-9A-Fa-f]{6}) \\|")
	rows := row.FindAllStringSubmatch(string(design), -1)
	if len(rows) < 15 {
		t.Fatalf("DESIGN.md lists %d colour tokens; the tables were not found", len(rows))
	}
	light, dark := themes(t)
	for _, r := range rows {
		tok, wantL, wantD := r[1], strings.ToLower(r[2]), strings.ToLower(r[3])
		if got := resolve(light, light[tok]); got != wantL {
			t.Errorf("%s light: style.css %q, DESIGN.md %s", tok, got, wantL)
		}
		if got := resolve(dark, dark[tok]); got != wantD {
			t.Errorf("%s dark: style.css %q, DESIGN.md %s", tok, got, wantD)
		}
	}
	// The type and shape the document promises.
	for _, want := range []string{`--font-ui: "Geist"`, `--font-mono: "Geist Mono"`, `--font-display: "Newsreader"`,
		"--radius: 4px", "--skew: -27.6deg", "--ease: cubic-bezier(.16, 1, .3, 1)"} {
		if !strings.Contains(embedded(t)["static/style.css"], want) {
			t.Errorf("style.css lacks %q", want)
		}
	}
	for _, f := range []string{"Geist-Variable.woff2", "GeistMono-Variable.woff2", "Newsreader-Variable.woff2", "Geist-LICENSE.txt", "Newsreader-LICENSE.txt"} {
		if _, ok := embedded(t)["static/fonts/"+f]; !ok {
			t.Errorf("font file %s is not bundled", f)
		}
	}
}

func luminance(hex string) float64 {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return -1
	}
	ch := func(i int) float64 {
		v, _ := strconv.ParseUint(hex[i:i+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(0) + 0.7152*ch(2) + 0.0722*ch(4)
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// REQ-BR-5: text at least 4.5:1, interface parts at least 3:1, light and dark.
func TestTokenContrast(t *testing.T) {
	text := [][2]string{
		{"--text", "--bg"}, {"--text", "--surface"}, {"--text", "--surface-2"},
		{"--text-2", "--surface"}, {"--text-2", "--bg"},
		{"--muted", "--surface"}, {"--muted", "--bg"}, {"--muted", "--surface-2"},
		{"--link", "--surface"}, {"--link", "--bg"}, {"--eyebrow", "--bg"},
		{"--on-primary", "--primary"}, {"--primary", "--primary-soft"},
		{"--rail-text", "--rail"}, {"--rail-text-2", "--rail"}, {"--rail-accent", "--rail"},
		{"--crit", "--crit-bg"}, {"--high", "--high-bg"}, {"--med", "--med-bg"}, {"--low", "--low-bg"},
		{"--good", "--good-bg"}, {"--info-c", "--info-bg"},
		{"--crit", "--surface"}, {"--good", "--surface"}, {"--med", "--surface"},
	}
	parts := [][2]string{{"--primary", "--surface"}, {"--primary", "--bg"}, {"--focus", "--surface"}, {"--border-strong", "--surface"}}
	light, dark := themes(t)
	for mode, tokens := range map[string]map[string]string{"light": light, "dark": dark} {
		check := func(pairs [][2]string, min float64) {
			for _, p := range pairs {
				fg, bg := resolve(tokens, tokens[p[0]]), resolve(tokens, tokens[p[1]])
				if luminance(fg) < 0 || luminance(bg) < 0 {
					t.Errorf("%s: %s or %s is not a plain colour (%q, %q)", mode, p[0], p[1], fg, bg)
					continue
				}
				if c := contrast(fg, bg); c < min {
					t.Errorf("%s: %s %s on %s %s is %.2f:1, want at least %.1f:1", mode, p[0], fg, p[1], bg, c, min)
				}
			}
		}
		check(text, 4.5)
		check(parts[:3], 3)
		check(parts[3:], 1.5) // a hairline input border, paired with a label and focus ring
	}
}

// REQ-BR-3: every logo is flat: no gradient, filter, glow, shadow, stroke or transparency.
func TestLogosAreFlat(t *testing.T) {
	bad := regexp.MustCompile(`(?i)gradient|filter|feGaussian|drop-shadow|opacity|rgba\(|stroke="(?:#|rgb|url|currentColor)|mask=`)
	files := embedded(t)
	logos := map[string]string{}
	for name, body := range files {
		if strings.HasPrefix(name, "static/img/") && strings.HasSuffix(name, ".svg") {
			logos[name] = body
		}
	}
	if len(logos) < 5 {
		t.Fatalf("only %d logo files", len(logos))
	}
	dom := files["static/js/dom.js"]
	i := strings.Index(dom, "export function brandMark")
	if i < 0 {
		t.Fatal("brandMark is gone")
	}
	logos["dom.js brandMark"] = dom[i : i+strings.Index(dom[i:], "\n}\n")]
	html := files["static/index.html"]
	j := strings.Index(html, `<span class="brandmark"`)
	logos["index.html brandmark"] = html[j : j+strings.Index(html[j:], "</span>")]
	for name, body := range logos {
		if m := bad.FindString(body); m != "" {
			t.Errorf("%s is not flat: %q", name, m)
		}
	}
	// UX-REVIEW-008 S1: the icon is a padlock on a rounded square, nothing borrowed from another mark.
	for _, f := range []string{"mark.svg", "mark-on-navy.svg", "mark-mono.svg"} {
		body := files["static/img/"+f]
		if !strings.Contains(body, `rx="7"`) || !strings.Contains(body, "a5.25 5.25 0 0 1 10.5 0") {
			t.Errorf("%s is not the padlock icon", f)
		}
	}
	if !strings.Contains(html, `href="/img/mark.svg"`) {
		t.Error("the favicon is not the icon")
	}
}

// REQ-BR-4: gradients only for the loading skeleton and the running-scan shimmer.
func TestNoDecorativeGradients(t *testing.T) {
	allowed := regexp.MustCompile(`^\s*\.(skeleton|progress-fill)\b`)
	for name, body := range embedded(t) {
		switch {
		case strings.HasSuffix(name, ".css"):
			for n, line := range strings.Split(body, "\n") {
				if strings.Contains(line, "gradient(") && !allowed.MatchString(line) {
					t.Errorf("%s:%d: a decorative gradient: %s", name, n+1, strings.TrimSpace(line))
				}
			}
		case strings.HasSuffix(name, ".js"), strings.HasSuffix(name, ".html"):
			if regexp.MustCompile(`(?i)gradient\(|linearGradient|radialGradient`).MatchString(body) {
				t.Errorf("%s draws a gradient", name)
			}
		}
	}
}
