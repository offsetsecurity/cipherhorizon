// Package reportpdf lays out CipherHorizon's downloadable PDF reports: the
// endpoint report (full, TLS-only and certificate-only) and the inventory
// report. It reads the same stored scan, evaluation and inventory the web pages
// show, so a PDF never says something the page does not.
package reportpdf

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/example/cipherhorizon/internal/pdf"
)

// The palette follows the web UI (web/static/style.css).
var (
	ink      = pdf.Hex("#16192b")
	text2    = pdf.Hex("#4b5168")
	muted    = pdf.Hex("#6b7186")
	rule     = pdf.Hex("#e3e5ec")
	stripe   = pdf.Hex("#f7f8fb")
	headBG   = pdf.Hex("#eef0f5")
	violet   = pdf.Hex("#5b3fe0")
	night    = pdf.Hex("#1a1433")
	lavender = pdf.Hex("#c9c0ff")
	amber    = pdf.Hex("#d9702f")
	amber2   = pdf.Hex("#f2a33f")
	amberBG  = pdf.Hex("#fdf4e8")
	linkC    = pdf.Hex("#2a4fd6")
	white    = pdf.Color{R: 1, G: 1, B: 1}
)

// tone is a foreground and background pair for a status.
type tone struct{ fg, bg pdf.Color }

var (
	toneBad  = tone{pdf.Hex("#c4271b"), pdf.Hex("#fdecea")}
	toneHigh = tone{pdf.Hex("#c24a12"), pdf.Hex("#fdeee3")}
	toneWarn = tone{pdf.Hex("#a14b06"), pdf.Hex("#fdf3e1")}
	toneGood = tone{pdf.Hex("#067a4a"), pdf.Hex("#e6f8ee")}
	toneOK   = tone{pdf.Hex("#0b6e8f"), pdf.Hex("#e6f5fa")}
	toneLow  = tone{pdf.Hex("#1d5fd6"), pdf.Hex("#e9f0ff")}
	toneInfo = tone{pdf.Hex("#4c546a"), pdf.Hex("#eceef3")}
	toneL4   = tone{pdf.Hex("#6b3fd6"), pdf.Hex("#f1ebfd")}
)

const (
	marginX   = 48.0
	bodySize  = 9.5
	smallSize = 8.2
	coverH    = 172.0
)

var right = pdf.PageWidth - marginX

// doc wraps a pdf.Flow with the report's page frame and text helpers.
type doc struct {
	d       *pdf.Doc
	f       *pdf.Flow
	running string // the running header on pages after the first
	footer  string
}

type cover struct {
	kicker string   // e.g. "TLS SECURITY REPORT"
	title  string   // the endpoint or "Cryptographic inventory"
	lines  []string // under the title
}

func newDoc(title, subject string, created time.Time, c cover, running, footer string) *doc {
	d := pdf.New()
	d.Title, d.Subject, d.Creator, d.Created = title, subject, "CipherHorizon", created
	x := &doc{d: d, running: running, footer: footer}
	x.f = &pdf.Flow{Doc: d, Left: marginX, Right: right, Top: 64, Bottom: pdf.PageHeight - 60}
	x.f.Header = func(f *pdf.Flow) {
		p := f.Page
		if p.Index() == 0 {
			drawCover(p, c)
			f.Y = coverH + 24
			return
		}
		p.Text(marginX, 34, pdf.Bold, 7.5, violet, "CIPHERHORIZON")
		p.Text(marginX+pdf.Width(pdf.Bold, 7.5, "CIPHERHORIZON")+8, 34, pdf.Regular, 7.5, muted, running)
		p.Line(marginX, 42, right, 42, 0.5, rule)
		f.Y = 60
	}
	x.f.NewPage()
	return x
}

func drawCover(p *pdf.Page, c cover) {
	p.Rect(0, 0, pdf.PageWidth, coverH, night)
	p.Rect(pdf.PageWidth-150, 0, 150, coverH, pdf.Hex("#211a42"))
	p.Rect(pdf.PageWidth-60, 0, 60, coverH, pdf.Hex("#2a2152"))
	p.Rect(0, coverH-4, pdf.PageWidth, 4, amber2)
	// The mark: a violet tile with an amber horizon line.
	p.RoundRect(marginX, 30, 20, 20, 5, violet, 0, pdf.Color{})
	p.Rect(marginX+4, 42, 12, 2.2, amber2)
	p.Text(marginX+28, 44.5, pdf.Bold, 11.5, white, "CipherHorizon")
	p.TextRight(right, 44, pdf.Bold, 8, lavender, c.kicker)
	size := 24.0
	for size > 15 && pdf.Width(pdf.Bold, size, c.title) > right-marginX {
		size -= 1.5
	}
	lines := pdf.Wrap([]pdf.Span{{Text: c.title, Font: pdf.Bold, Size: size, Color: white}}, right-marginX)
	if len(lines) > 2 {
		lines = lines[:2]
	}
	y := 92.0
	if len(lines) == 2 {
		y = 84
	}
	for _, l := range lines {
		pdf.DrawLine(p, []pdf.Span{{Text: c.title, Font: pdf.Bold, Size: size, Color: white}}, l, marginX, y, 0)
		y += size * 1.15
	}
	y += 4
	for _, s := range c.lines {
		p.Text(marginX, y, pdf.Regular, 9.5, lavender, s)
		y += 14
	}
}

// finish draws the footers and returns the document's bytes.
func (x *doc) finish() ([]byte, error) {
	pages := x.d.Pages()
	for i, p := range pages {
		y := pdf.PageHeight - 40
		p.Line(marginX, y-10, right, y-10, 0.5, rule)
		p.Text(marginX, y, pdf.Regular, 7.2, muted, x.footer)
		p.TextRight(right, y, pdf.Regular, 7.2, muted, fmt.Sprintf("Page %d of %d", i+1, len(pages)))
	}
	var b bytes.Buffer
	err := x.d.Write(&b)
	return b.Bytes(), err
}

// ---- text helpers ------------------------------------------------------------------------------

func span(text string, f pdf.Font, size float64, c pdf.Color) pdf.Span {
	return pdf.Span{Text: text, Font: f, Size: size, Color: c}
}

func body(text string) pdf.Span  { return span(text, pdf.Regular, bodySize, ink) }
func bold(text string) pdf.Span  { return span(text, pdf.Bold, bodySize, ink) }
func soft(text string) pdf.Span  { return span(text, pdf.Regular, bodySize, text2) }
func small(text string) pdf.Span { return span(text, pdf.Regular, smallSize, muted) }
func mono(text string) pdf.Span  { return span(text, pdf.Mono, smallSize, ink) }
func linkTo(title, url string) pdf.Span {
	return pdf.Span{Text: title, Font: pdf.Regular, Size: smallSize, Color: linkC, URL: url}
}

func para(after float64, spans ...pdf.Span) pdf.Para { return pdf.Para{Spans: spans, After: after} }

// h1 starts a major part of the report and adds it to the outline.
func (x *doc) h1(title string) {
	x.f.Need(70)
	if x.f.Y > x.f.Top+10 {
		x.f.Y += 10
	}
	p := x.f.Page
	x.d.Bookmark(title, p, x.f.Y)
	p.Text(marginX, x.f.Y+15, pdf.Bold, 15, ink, title)
	p.Rect(marginX, x.f.Y+22, 26, 2.5, amber2)
	x.f.Y += 34
}

// h2 is a heading inside a part.
func (x *doc) h2(title string) {
	x.f.Need(96) // keep the heading with at least the first rows of what follows
	x.f.Y += 4
	x.f.Page.Text(marginX, x.f.Y+10, pdf.Bold, 10.5, ink, title)
	x.f.Y += 18
}

func (x *doc) p(spans ...pdf.Span) { x.f.Add(para(5, spans...)) }

func (x *doc) bullets(items []string) {
	for _, it := range items {
		if it == "" {
			continue
		}
		x.f.Add(pdf.Para{Spans: []pdf.Span{body(it)}, Indent: 12, Bullet: "•", After: 2.5})
	}
	x.f.Y += 3
}

func (x *doc) gap(h float64) { x.f.Y += h }

var tableStyle = pdf.TableStyle{Size: smallSize, HeaderFG: text2, HeaderBG: headBG, Stripe: stripe, Rule: rule, Pad: 4.5, After: 8}

func (x *doc) table(cols []pdf.Col, rows [][]pdf.Cell) {
	if len(rows) == 0 {
		return
	}
	x.f.Table(cols, rows, tableStyle)
}

// kv is a two-column table of labels and values.
func (x *doc) kv(pairs [][2]string) {
	var rows [][]pdf.Cell
	for _, kv := range pairs {
		if strings.TrimSpace(kv[1]) == "" {
			continue
		}
		rows = append(rows, []pdf.Cell{txt(kv[0], pdf.Bold, text2), txt(kv[1], pdf.Regular, ink)})
	}
	st := tableStyle
	st.NoHeader = true
	st.Stripe = pdf.Color{}
	x.f.Table([]pdf.Col{{W: 1}, {W: 3}}, rows, st)
}

func txt(s string, f pdf.Font, c pdf.Color) pdf.Cell {
	return pdf.Cell{Spans: []pdf.Span{span(s, f, smallSize, c)}}
}

func monoCell(s string) pdf.Cell { return pdf.Cell{Spans: []pdf.Span{span(s, pdf.Mono, 7.4, ink)}} }

func chipCell(text string, t tone) pdf.Cell {
	return pdf.Cell{Chip: &pdf.Chip{Text: text, FG: t.fg, BG: t.bg, Size: 7}}
}

func dotCell(text string, t tone) pdf.Cell {
	c := t.fg
	return pdf.Cell{Dot: &c, Spans: []pdf.Span{span(text, pdf.Bold, smallSize, t.fg)}}
}

// callout is a tinted note with a coloured edge.
func (x *doc) callout(t tone, spans ...pdf.Span) {
	x.f.Box(pdf.BoxStyle{Fill: t.bg, HasFill: true, Accent: t.fg, AccentWidth: 3, Pad: 8, Radius: 3, After: 8},
		pdf.Para{Spans: spans})
}

// chipLine is a block that draws a chip, then a paragraph beside it.
type chipLine struct {
	chip pdf.Chip
	para pdf.Para
}

// Height implements pdf.Block.
func (c chipLine) Height(w float64) float64 {
	cw := pdf.ChipWidth(c.chip) + 7
	return max(pdf.ChipHeight(c.chip)+2, c.para.Height(w-cw))
}

// Draw implements pdf.Block.
func (c chipLine) Draw(p *pdf.Page, x, y, w float64) {
	cw := pdf.DrawChip(p, x, y, c.chip) + 7
	c.para.Draw(p, x+cw, y-1, w-cw)
}

// tile is one of the summary figures at the top of a report.
type tile struct {
	big, label, sub string
	t               tone
}

// tiles draws up to four summary tiles in a row.
func (x *doc) tiles(ts []tile) {
	const h, gapW = 80.0, 10.0
	x.f.Add(pdf.Custom{H: h + 12, F: func(p *pdf.Page, x0, y, w float64) {
		tw := (w - gapW*float64(len(ts)-1)) / float64(len(ts))
		for i, t := range ts {
			tx := x0 + float64(i)*(tw+gapW)
			p.RoundRect(tx, y, tw, h, 6, t.t.bg, 0, pdf.Color{})
			p.Rect(tx, y+10, 3, h-20, t.t.fg)
			size := 22.0
			for size > 12 && pdf.Width(pdf.Bold, size, t.big) > tw-24 {
				size -= 1
			}
			p.Text(tx+14, y+30, pdf.Bold, size, t.t.fg, t.big)
			p.Text(tx+14, y+46, pdf.Bold, 6.8, text2, strings.ToUpper(t.label))
			sub := pdf.Para{Spans: []pdf.Span{span(t.sub, pdf.Regular, 7.8, text2)}, Leading: 1.25}
			sub.Draw(p, tx+14, y+51, tw-22)
		}
	}})
}

// ---- formatting --------------------------------------------------------------------------------

func day(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2 Jan 2006")
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2 Jan 2006, 15:04 UTC")
}

func plural(n int, one string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
