package pdf

import (
	"strings"
	"unicode/utf8"
)

// Span is a run of text in one style. A span with a URL is drawn as a link.
type Span struct {
	Text  string
	Font  Font
	Size  float64
	Color Color
	URL   string
}

// piece is a word (or part of one) placed on a line.
type piece struct {
	span  int // index into the spans of the paragraph
	text  string
	x, w  float64
	space bool // a space precedes it on the line
}

// Line is one wrapped line of a paragraph.
type Line struct {
	pieces []piece
	Width  float64
	Size   float64 // the largest font size on the line
}

type token struct {
	span  int
	text  string
	space bool
}

// Wrap breaks spans into lines no wider than maxW. A word longer than a line
// is broken where it must be.
func Wrap(spans []Span, maxW float64) []Line {
	var toks []token
	pendingSpace := false
	for i, s := range spans {
		text := strings.ReplaceAll(s.Text, "\n", " ")
		if text == "" {
			continue
		}
		if text[0] == ' ' {
			pendingSpace = true
		}
		for _, w := range strings.Fields(text) {
			toks = append(toks, token{span: i, text: w, space: pendingSpace})
			pendingSpace = true
		}
		pendingSpace = strings.HasSuffix(text, " ")
	}
	var lines []Line
	cur := Line{}
	flush := func() {
		if len(cur.pieces) > 0 {
			lines = append(lines, cur)
		}
		cur = Line{}
	}
	for _, t := range toks {
		s := spans[t.span]
		w := Width(s.Font, s.Size, t.text)
		sp := 0.0
		if t.space && len(cur.pieces) > 0 {
			sp = Width(s.Font, s.Size, " ")
		}
		if len(cur.pieces) > 0 && cur.Width+sp+w > maxW {
			flush()
			sp = 0
		}
		// A word wider than the whole line is cut into pieces that fit.
		for w > maxW && utf8.RuneCountInString(t.text) > 1 {
			cut := fitPrefix(s, t.text, maxW-cur.Width)
			if cut == "" {
				flush()
				cut = fitPrefix(s, t.text, maxW)
			}
			cw := Width(s.Font, s.Size, cut)
			cur.pieces = append(cur.pieces, piece{span: t.span, text: cut, x: cur.Width, w: cw})
			cur.Width += cw
			cur.Size = max(cur.Size, s.Size)
			flush()
			t.text = t.text[len(cut):]
			w = Width(s.Font, s.Size, t.text)
		}
		cur.pieces = append(cur.pieces, piece{span: t.span, text: t.text, x: cur.Width + sp, w: w, space: sp > 0})
		cur.Width += sp + w
		cur.Size = max(cur.Size, s.Size)
	}
	flush()
	return lines
}

// fitPrefix is the longest prefix of s (at least one rune) no wider than w.
func fitPrefix(sp Span, s string, w float64) string {
	end := 0
	for i, r := range s {
		next := i + utf8.RuneLen(r)
		if Width(sp.Font, sp.Size, s[:next]) > w {
			break
		}
		end = next
	}
	if end == 0 && w > 0 {
		_, n := utf8.DecodeRuneInString(s)
		if Width(sp.Font, sp.Size, s[:n]) <= w {
			return s[:n]
		}
	}
	return s[:end]
}

// DrawLine draws a wrapped line with its left edge at x and its baseline at y.
// align: 0 left, 1 right (x is then the right edge), 2 centre (x is the centre).
func DrawLine(p *Page, spans []Span, l Line, x, y float64, align int) {
	switch align {
	case 1:
		x -= l.Width
	case 2:
		x -= l.Width / 2
	}
	// Consecutive pieces of the same span are drawn as one run.
	for i := 0; i < len(l.pieces); {
		j := i
		var sb strings.Builder
		sb.WriteString(l.pieces[i].text)
		for j+1 < len(l.pieces) && l.pieces[j+1].span == l.pieces[i].span {
			j++
			if l.pieces[j].space {
				sb.WriteByte(' ')
			}
			sb.WriteString(l.pieces[j].text)
		}
		s := spans[l.pieces[i].span]
		start := l.pieces[i].x
		end := l.pieces[j].x + l.pieces[j].w
		p.Text(x+start, y, s.Font, s.Size, s.Color, sb.String())
		if s.URL != "" {
			p.Line(x+start, y+1.2, x+end, y+1.2, 0.4, s.Color)
			p.Link(x+start, y-s.Size, end-start, s.Size*1.3, s.URL)
		}
		i = j + 1
	}
}

// Block is something a Flow places: it knows its height at a width and how to
// draw itself with its top-left corner at x, y.
type Block interface {
	Height(w float64) float64
	Draw(p *Page, x, y, w float64)
}

// Para is a paragraph block.
type Para struct {
	Spans   []Span
	Leading float64 // line height as a multiple of the font size; 1.35 when zero
	Indent  float64 // left indent
	After   float64 // space after the paragraph
	Bullet  string  // drawn in the indent, e.g. "•" or "1."
	Align   int
}

func (b Para) leading() float64 {
	if b.Leading == 0 {
		return 1.35
	}
	return b.Leading
}

func (b Para) lines(w float64) []Line { return Wrap(b.Spans, w-b.Indent) }

func lineHeight(l Line, leading float64) float64 { return l.Size * leading }

// Height implements Block.
func (b Para) Height(w float64) float64 {
	h := 0.0
	for _, l := range b.lines(w) {
		h += lineHeight(l, b.leading())
	}
	return h + b.After
}

// Draw implements Block.
func (b Para) Draw(p *Page, x, y, w float64) {
	lines := b.lines(w)
	for i, l := range lines {
		lh := lineHeight(l, b.leading())
		base := y + lh - (lh-l.Size)/2 - l.Size*0.22
		if i == 0 && b.Bullet != "" && len(b.Spans) > 0 {
			s := b.Spans[0]
			p.TextRight(x+b.Indent-4, base, s.Font, s.Size, s.Color, b.Bullet)
		}
		ax := x + b.Indent
		switch b.Align {
		case 1:
			ax = x + w
		case 2:
			ax = x + b.Indent + (w-b.Indent)/2
		}
		DrawLine(p, b.Spans, l, ax, base, b.Align)
		y += lh
	}
}

// Gap is vertical space.
type Gap float64

// Height implements Block.
func (g Gap) Height(float64) float64 { return float64(g) }

// Draw implements Block.
func (Gap) Draw(*Page, float64, float64, float64) {}

// Custom is a block drawn by a function.
type Custom struct {
	H float64
	F func(p *Page, x, y, w float64)
}

// Height implements Block.
func (c Custom) Height(float64) float64 { return c.H }

// Draw implements Block.
func (c Custom) Draw(p *Page, x, y, w float64) { c.F(p, x, y, w) }

// Flow places blocks down the page and starts new pages as needed.
type Flow struct {
	Doc                      *Doc
	Page                     *Page
	Left, Right, Top, Bottom float64
	Y                        float64
	// Header, when set, runs on every page the flow starts and may move Y.
	Header func(f *Flow)
}

// Width is the width of the text column.
func (f *Flow) Width() float64 { return f.Right - f.Left }

// NewPage starts a page.
func (f *Flow) NewPage() {
	f.Page = f.Doc.AddPage()
	f.Y = f.Top
	if f.Header != nil {
		f.Header(f)
	}
}

// Need starts a new page unless h more points fit on this one.
func (f *Flow) Need(h float64) {
	if f.Page == nil || f.Y+h > f.Bottom {
		f.NewPage()
	}
}

// Add places blocks in order. A paragraph that does not fit continues on the
// next page line by line; other blocks move whole.
func (f *Flow) Add(blocks ...Block) {
	for _, b := range blocks {
		if p, ok := b.(Para); ok && p.Height(f.Width()) > f.Bottom-f.Y {
			f.splitPara(p)
			continue
		}
		h := b.Height(f.Width())
		f.Need(h)
		b.Draw(f.Page, f.Left, f.Y, f.Width())
		f.Y += h
	}
}

func (f *Flow) splitPara(b Para) {
	lines := b.lines(f.Width())
	for i, l := range lines {
		one := b
		one.After = 0
		if i > 0 {
			one.Bullet = ""
		}
		lh := lineHeight(l, b.leading())
		f.Need(lh)
		// Draw just this line, using the paragraph's own geometry.
		base := f.Y + lh - (lh-l.Size)/2 - l.Size*0.22
		if i == 0 && b.Bullet != "" {
			s := b.Spans[0]
			f.Page.TextRight(f.Left+b.Indent-4, base, s.Font, s.Size, s.Color, b.Bullet)
		}
		DrawLine(f.Page, b.Spans, l, f.Left+b.Indent, base, 0)
		f.Y += lh
	}
	f.Y += b.After
}

// BoxStyle styles a boxed group of blocks.
type BoxStyle struct {
	Fill, Border, Accent Color
	HasFill, HasBorder   bool
	AccentWidth          float64 // a coloured bar down the left edge
	Pad                  float64
	Radius               float64
	After                float64
}

// Box draws blocks inside a box. A box taller than a page is drawn without its
// frame so that it can break.
func (f *Flow) Box(st BoxStyle, blocks ...Block) {
	inner := f.Width() - 2*st.Pad - st.AccentWidth
	h := 2 * st.Pad
	for _, b := range blocks {
		h += b.Height(inner)
	}
	if h > f.Bottom-f.Top {
		f.Add(blocks...)
		f.Y += st.After
		return
	}
	f.Need(h)
	p := f.Page
	if st.HasFill || st.HasBorder {
		lw := 0.0
		if st.HasBorder {
			lw = 0.6
		}
		fill := st.Fill
		if !st.HasFill {
			fill = Color{1, 1, 1}
		}
		p.RoundRect(f.Left, f.Y, f.Width(), h, st.Radius, fill, lw, st.Border)
	}
	if st.AccentWidth > 0 {
		p.Rect(f.Left, f.Y, st.AccentWidth, h, st.Accent)
	}
	y := f.Y + st.Pad
	for _, b := range blocks {
		b.Draw(p, f.Left+st.AccentWidth+st.Pad, y, inner)
		y += b.Height(inner)
	}
	f.Y += h + st.After
}

// Chip is a small rounded label.
type Chip struct {
	Text   string
	FG, BG Color
	Size   float64
}

// ChipWidth is the drawn width of a chip.
func ChipWidth(c Chip) float64 { return Width(Bold, c.Size, c.Text) + c.Size*1.3 }

// ChipHeight is the drawn height of a chip.
func ChipHeight(c Chip) float64 { return c.Size * 1.75 }

// DrawChip draws a chip with its top-left corner at x, y and returns its width.
func DrawChip(p *Page, x, y float64, c Chip) float64 {
	w, h := ChipWidth(c), ChipHeight(c)
	p.RoundRect(x, y, w, h, h/2, c.BG, 0, Color{})
	p.Text(x+c.Size*0.65, y+h/2+c.Size*0.35, Bold, c.Size, c.FG, c.Text)
	return w
}

// Col is a table column.
type Col struct {
	Title string
	W     float64 // a share of the table width
	Align int     // 0 left, 1 right, 2 centre
}

// Cell is a table cell: text, or a chip, or a coloured dot before text.
type Cell struct {
	Spans []Span
	Chip  *Chip
	Dot   *Color
}

// TableStyle styles a table.
type TableStyle struct {
	Size                       float64
	HeaderFG, HeaderBG, Stripe Color
	Rule                       Color
	Pad                        float64
	After                      float64
	NoHeader                   bool // a key-value table has no header row
}

func (f *Flow) colWidths(cols []Col) []float64 {
	total := 0.0
	for _, c := range cols {
		total += c.W
	}
	ws := make([]float64, len(cols))
	for i, c := range cols {
		ws[i] = f.Width() * c.W / total
	}
	return ws
}

// fitChip shrinks a chip until it fits the column.
func fitChip(c Chip, w float64) Chip {
	for ChipWidth(c) > w && c.Size > 5 {
		c.Size -= 0.4
	}
	return c
}

func cellHeight(c Cell, w float64, st TableStyle) float64 {
	if c.Chip != nil {
		return ChipHeight(fitChip(*c.Chip, w))
	}
	if c.Dot != nil {
		w -= st.Size
	}
	h := 0.0
	for _, l := range Wrap(c.Spans, w) {
		h += l.Size * 1.3
	}
	if h == 0 {
		h = st.Size * 1.3
	}
	return h
}

func drawCell(p *Page, c Cell, x, y, w float64, align int, st TableStyle) {
	if c.Chip != nil {
		chip := fitChip(*c.Chip, w)
		cx := x
		switch align {
		case 1:
			cx = x + w - ChipWidth(chip)
		case 2:
			cx = x + (w-ChipWidth(chip))/2
		}
		DrawChip(p, cx, y, chip)
		return
	}
	if c.Dot != nil {
		p.Circle(x+st.Size*0.3, y+st.Size*0.62, st.Size*0.3, *c.Dot)
		x += st.Size
		w -= st.Size
	}
	for _, l := range Wrap(c.Spans, w) {
		lh := l.Size * 1.3
		ax := x
		switch align {
		case 1:
			ax = x + w
		case 2:
			ax = x + w/2
		}
		DrawLine(p, c.Spans, l, ax, y+l.Size*0.95, align)
		y += lh
	}
}

// Table draws a table; a header row is repeated on every page it spans.
func (f *Flow) Table(cols []Col, rows [][]Cell, st TableStyle) {
	ws := f.colWidths(cols)
	pad := st.Pad
	header := func() {
		if st.NoHeader {
			return
		}
		hh := st.Size*1.3 + 2*pad
		f.Need(hh + st.Size*3)
		f.Page.Rect(f.Left, f.Y, f.Width(), hh, st.HeaderBG)
		x := f.Left
		for i, c := range cols {
			hc := Cell{Spans: []Span{{Text: strings.ToUpper(c.Title), Font: Bold, Size: st.Size * 0.82, Color: st.HeaderFG}}}
			drawCell(f.Page, hc, x+pad, f.Y+pad+st.Size*0.1, ws[i]-2*pad, c.Align, st)
			x += ws[i]
		}
		f.Y += hh
	}
	header()
	for ri, r := range rows {
		rh := 0.0
		for i := range cols {
			if i < len(r) {
				rh = max(rh, cellHeight(r[i], ws[i]-2*pad, st))
			}
		}
		rh += 2 * pad
		if f.Y+rh > f.Bottom {
			f.NewPage()
			header()
		}
		if ri%2 == 1 && st.Stripe != (Color{}) {
			f.Page.Rect(f.Left, f.Y, f.Width(), rh, st.Stripe)
		}
		x := f.Left
		for i, c := range cols {
			if i < len(r) {
				drawCell(f.Page, r[i], x+pad, f.Y+pad, ws[i]-2*pad, c.Align, st)
			}
			x += ws[i]
		}
		f.Y += rh
		f.Page.Line(f.Left, f.Y, f.Right, f.Y, 0.4, st.Rule)
	}
	f.Y += st.After
}
