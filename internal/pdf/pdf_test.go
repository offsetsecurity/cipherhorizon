package pdf_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/example/cipherhorizon/internal/pdf"
	"github.com/example/cipherhorizon/internal/pdf/pdfcheck"
)

func TestDocumentIsWellFormedAndReadsBack(t *testing.T) {
	d := pdf.New()
	d.Title = "A (test) report \\ with ünïcode"
	f := &pdf.Flow{Doc: d, Left: 48, Right: pdf.PageWidth - 48, Top: 60, Bottom: pdf.PageHeight - 60}
	f.NewPage()
	d.Bookmark("Start", f.Page, f.Y)
	f.Add(pdf.Para{Spans: []pdf.Span{
		{Text: "Hostile (text) with a back\\slash, <script> and ", Size: 10},
		{Text: "a link", Size: 10, URL: "https://example.org/a?b=(c)"},
		{Text: " and a javascript: link", Size: 10, URL: "javascript:alert(1)"},
	}})
	var rows [][]pdf.Cell
	for i := 0; i < 120; i++ {
		rows = append(rows, []pdf.Cell{{Spans: []pdf.Span{{Text: fmt.Sprintf("row %d", i), Size: 9}}},
			{Chip: &pdf.Chip{Text: "A CHIP FAR TOO WIDE FOR ITS NARROW COLUMN", Size: 7}}})
	}
	f.Table([]pdf.Col{{Title: "Name", W: 3}, {Title: "State", W: 1}}, rows, pdf.TableStyle{Size: 9, Pad: 4})
	var b bytes.Buffer
	if err := d.Write(&b); err != nil {
		t.Fatal(err)
	}
	info, err := pdfcheck.Check(b.Bytes())
	if err != nil {
		t.Fatalf("not a well-formed PDF: %v", err)
	}
	if info.Pages < 3 {
		t.Errorf("a 120-row table spans pages; got %d pages", info.Pages)
	}
	for _, want := range []string{"Hostile (text) with a back\\slash, <script> and", "row 0", "row 119", "NAME"} {
		if !strings.Contains(info.Text, want) {
			t.Errorf("text %q not found", want)
		}
	}
	// The header row repeats on every page the table spans.
	if n := strings.Count(info.Text, "NAME"); n != info.Pages {
		t.Errorf("table header drawn %d times on %d pages", n, info.Pages)
	}
	if len(info.Links) != 1 || info.Links[0] != "https://example.org/a?b=(c)" {
		t.Errorf("only the https link becomes a link annotation: %q", info.Links)
	}
	if len(info.Outline) != 1 || info.Outline[0] != "Start" {
		t.Errorf("outline: %q", info.Outline)
	}
}

func TestWrapKeepsLinesWithinTheWidth(t *testing.T) {
	spans := []pdf.Span{{Text: "The quick brown fox jumps over the lazy dog; a_token_without_any_space_that_is_longer_than_the_whole_line_by_far_and_more", Size: 10}}
	lines := pdf.Wrap(spans, 120)
	if len(lines) < 4 {
		t.Fatalf("expected several lines, got %d", len(lines))
	}
	for i, l := range lines {
		if l.Width > 120.01 {
			t.Errorf("line %d is %.1f wide, more than 120", i, l.Width)
		}
	}
	if pdf.Wrap(nil, 100) != nil {
		t.Error("no spans, no lines")
	}
}

func TestEncodeShowsWhatTheStandardFontsHave(t *testing.T) {
	cases := map[string]string{
		"a → b":     "a -> b",
		"✔ ok":      " ok",
		"café · 5€": "caf\xe9 \xb7 5\x80",
		"日本":        "??",
		"tab\there": "tab here",
	}
	for in, want := range cases {
		if got := string(pdf.Encode(in)); got != want {
			t.Errorf("Encode(%q) = %q, want %q", in, got, want)
		}
	}
	if w := pdf.Width(pdf.Regular, 10, "Wi"); w != (944+222)*10/1000.0 {
		t.Errorf("Helvetica widths: got %.2f", w)
	}
	if w := pdf.Width(pdf.Mono, 10, "abc"); w != 18 {
		t.Errorf("Courier is 600 per glyph: got %.2f", w)
	}
}
