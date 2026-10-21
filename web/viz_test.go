package web

import (
	"regexp"
	"strings"
	"testing"
)

// PRD-013 REQ-VIS-1 (UX-DESIGN-011 §2): every quantity is drawn by one shared instrument, so one
// instrument means one thing on every page, and each instrument says in words what it shows.
func TestInstrumentsAreSharedAndLabelled(t *testing.T) {
	f := embedded(t)
	viz := f["static/js/viz.js"]
	if viz == "" {
		t.Fatal("viz.js is not embedded")
	}

	// Each instrument is exported from viz.js, and its body carries its meaning in words: an
	// aria-label on a role="img", a screen-reader word, or visible text (a chip is its word).
	body := func(name string) string {
		i := strings.Index(viz, "export function "+name+"(")
		if i < 0 {
			return ""
		}
		rest := viz[i+1:]
		if j := strings.Index(rest, "\nexport "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	labelled := regexp.MustCompile(`'aria-label'|sr-only|svg\('title'`)
	for _, name := range []string{"bitsBar", "partCell", "pqGlyph", "statusTile", "lifetimeBar", "gauge", "levelStepper", "stackBar"} {
		b := body(name)
		if b == "" {
			t.Errorf("viz.js does not export %s", name)
			continue
		}
		if !labelled.MatchString(b) {
			t.Errorf("viz.js %s has no text alternative (aria-label, sr-only word or SVG title)", name)
		}
	}
	for _, name := range []string{"bitsAxis", "strengthChip", "jumpNav", "strengthWords", "bandOf"} {
		if body(name) == "" {
			t.Errorf("viz.js does not export %s", name)
		}
	}
	// The bands are defined once: the scale's edges appear in viz.js and nowhere else.
	if !strings.Contains(viz, "[[0, 80, 'broken'], [80, 112, 'weak'], [112, 128, 'acceptable'], [128, 256, 'strong']]") {
		t.Error("viz.js lost the strength bands of PRD-010 §2")
	}

	// Every rebuilt screen draws with viz.js and keeps none of the retired, screen-local drawings.
	retired := regexp.MustCompile(`function (strengthBar|validityBar|strengthCellText|protocolMatrix|servedDiagram|chainPanel|coverageLine|algorithmsCard|suiteTable|signatureTable)\(`)
	for _, file := range []string{"static/js/views/report.js", "static/js/views/tls-config.js", "static/js/views/certificate.js", "static/js/views/inventory.js", "static/js/views/report-ssh.js"} {
		src := f[file]
		if src == "" {
			t.Errorf("%s is not embedded", file)
			continue
		}
		if !strings.Contains(src, "from '../viz.js'") {
			t.Errorf("%s does not draw with the shared instruments (no import from viz.js)", file)
		}
		if m := retired.FindString(src); m != "" {
			t.Errorf("%s still defines a screen-local drawing: %s", file, m)
		}
		// A bits bar is never redrawn locally: no screen builds its own band track.
		if strings.Contains(src, "bb-track") || strings.Contains(src, "bb-band") {
			t.Errorf("%s draws its own bits bar; use viz.js bitsBar", file)
		}
	}
}
