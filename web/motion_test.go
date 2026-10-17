package web

import (
	"regexp"
	"strings"
	"testing"
)

// PRD-009 REQ-MOT-5 and DESIGN.md §9: motion animates only what is cheap and does not move the
// layout, and reduced motion switches every animation and transition off.

var keyframesRE = regexp.MustCompile(`@keyframes\s+([a-z0-9-]+)\s*\{((?:[^{}]*\{[^{}]*\})*[^{}]*)\}`)

// animatable are the properties a keyframe may set. background-position is the running-scan
// shimmer and the loading skeleton; stroke-dasharray/-dashoffset draw SVG lines and rings.
var animatable = map[string]bool{"opacity": true, "transform": true, "stroke-dashoffset": true, "stroke-dasharray": true, "background-position": true}

// layoutProps must never be transitioned: animating them reflows the page on every frame.
var layoutProps = []string{"width", "height", "top", "left", "right", "bottom", "margin", "padding", "font-size"}

// layoutExceptions are the transitions of a layout property that are the thing being shown.
var layoutExceptions = map[string]string{
	".progress-fill": "a scan's progress is a width by nature, and it changes only while a scan runs",
}

func TestMotionRulesAreRespected(t *testing.T) {
	css := embedded(t)["static/style.css"]
	frames := keyframesRE.FindAllStringSubmatch(css, -1)
	if len(frames) < 10 {
		t.Fatalf("found only %d @keyframes: has the pattern stopped matching?", len(frames))
	}
	propRE := regexp.MustCompile(`([a-z-]+)\s*:`)
	for _, f := range frames {
		for _, p := range propRE.FindAllStringSubmatch(f[2], -1) {
			if !animatable[p[1]] {
				t.Errorf("@keyframes %s animates %s; only opacity, transform and SVG strokes may move", f[1], p[1])
			}
		}
	}
	ruleRE := regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)
	for _, r := range ruleRE.FindAllStringSubmatch(css, -1) {
		sel := strings.TrimSpace(r[1])
		for _, decl := range strings.Split(r[2], ";") {
			name, value, ok := strings.Cut(decl, ":")
			if !ok || strings.TrimSpace(name) != "transition" {
				continue
			}
			for _, part := range strings.Split(value, ",") {
				fields := strings.Fields(part)
				if len(fields) == 0 {
					continue
				}
				for _, lp := range layoutProps {
					if fields[0] == lp && layoutExceptions[sel] == "" {
						t.Errorf("%s transitions %s, a layout property", sel, lp)
					}
				}
			}
		}
	}
	// The reduced-motion reset is the last motion rule in the file and covers everything.
	i := strings.LastIndex(css, "@media (prefers-reduced-motion: reduce)")
	if i < 0 {
		t.Fatal("no prefers-reduced-motion block")
	}
	tail := css[i:]
	if !strings.Contains(tail, "animation: none !important") || !strings.Contains(tail, "transition: none !important") ||
		!strings.Contains(tail, "*, *::before, *::after") {
		t.Error("the last reduced-motion block does not switch off every animation and transition")
	}
	if j := strings.Index(tail, "\n}\n"); j >= 0 && (strings.Contains(tail[j:], "animation:") || strings.Contains(tail[j:], "transition:")) {
		t.Error("motion is declared after the reduced-motion reset, so the reset might not win")
	}
}

// PRD-009 REQ-CHT-6: every chart mark is a keyboard-reachable link with a name, and one listener
// set gives every mark the same behaviour.
func TestChartsAreKeyboardReachable(t *testing.T) {
	files := embedded(t)
	charts := files["static/js/charts.js"]
	for _, want := range []string{"role: 'link'", "tabindex: '0'", "'aria-label': label", "'data-href': href", "e.key === 'Enter'", "e.key === ' '", "focusin"} {
		if !strings.Contains(charts, want) {
			t.Errorf("charts.js: a mark lacks %s", want)
		}
	}
	if !strings.Contains(files["static/js/app.js"], "wireMarks(main)") {
		t.Error("app.js does not install the mark behaviour on the page")
	}
	// A view that makes marks gets them from mark(), never by hand-writing data-href.
	for name, src := range files {
		if !strings.HasPrefix(name, "static/js/views/") {
			continue
		}
		if strings.Contains(src, "'data-href'") {
			t.Errorf("%s writes data-href itself; use mark() so the mark has its role, name and focus", name)
		}
	}
	css := files["static/style.css"]
	if !strings.Contains(css, ".mark:focus-visible") || !strings.Contains(css, ".chart-hot .mark:not(.is-hot)") {
		t.Error("style.css lacks the mark's focus ring or the sibling dimming")
	}
}

// PRD-009 REQ-MOT-2: figures count to their value; nothing else is made to count.
func TestCountUpIsUsedOnlyForFigures(t *testing.T) {
	files := embedded(t)
	allowed := regexp.MustCompile(`countUp\((fig|big),`)
	n := 0
	for name, src := range files {
		if !strings.HasPrefix(name, "static/js/views/") {
			continue
		}
		for _, m := range regexp.MustCompile(`countUp\([a-zA-Z]+,`).FindAllString(src, -1) {
			n++
			if !allowed.MatchString(m) {
				t.Errorf("%s counts %s, which is not a figure", name, m)
			}
		}
	}
	if n < 3 {
		t.Errorf("countUp is used %d times; the status band, the level counts and the inventory tiles should count", n)
	}
}
