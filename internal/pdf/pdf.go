// Package pdf writes small, self-contained PDF documents for CipherHorizon's
// reports: A4 pages, the four standard fonts (no font files to embed), filled
// and stroked shapes, links and a flat outline. It needs nothing beyond the
// standard library and x/text, which the module already uses.
//
// The API places things from the top-left corner of the page, in points
// (1/72 inch), the way a layout is designed; the writer converts to PDF's
// bottom-left coordinates.
package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// A4 in points.
const (
	PageWidth  = 595.28
	PageHeight = 841.89
)

// Font is one of the four standard fonts the document uses.
type Font int

// The fonts. Regular, Bold and Italic are Helvetica; Mono is Courier.
const (
	Regular Font = iota
	Bold
	Italic
	Mono
)

var fontNames = [...]string{"Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Courier"}

// Color is an RGB colour with components from 0 to 1.
type Color struct{ R, G, B float64 }

// Hex parses "#rrggbb". An unreadable value is black.
func Hex(s string) Color {
	s = strings.TrimPrefix(s, "#")
	if len(s) != 6 {
		return Color{}
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return Color{}
	}
	return Color{float64(v>>16&0xff) / 255, float64(v>>8&0xff) / 255, float64(v&0xff) / 255}
}

func (c Color) op(fill bool) string {
	if fill {
		return fmt.Sprintf("%s %s %s rg", num(c.R), num(c.G), num(c.B))
	}
	return fmt.Sprintf("%s %s %s RG", num(c.R), num(c.G), num(c.B))
}

// num formats a number compactly, as PDF wants it (no exponent).
func num(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "0"
	}
	return strconv.FormatFloat(math.Round(f*100)/100, 'f', -1, 64)
}

// Doc is a document being written.
type Doc struct {
	Title    string
	Subject  string
	Creator  string
	Created  time.Time
	pages    []*Page
	outline  []outlineItem
	compress bool
}

type outlineItem struct {
	title string
	page  int
	y     float64
}

// New starts a document. Content streams are compressed.
func New() *Doc { return &Doc{compress: true, Created: time.Now().UTC()} }

// Page is one page; draw on it with its methods.
type Page struct {
	buf   bytes.Buffer
	links []link
	n     int
}

type link struct {
	x, y, w, h float64
	url        string
}

// AddPage appends a blank A4 page and returns it.
func (d *Doc) AddPage() *Page {
	p := &Page{n: len(d.pages)}
	d.pages = append(d.pages, p)
	return p
}

// Pages returns the pages in order.
func (d *Doc) Pages() []*Page { return d.pages }

// Index is the zero-based position of the page in its document.
func (p *Page) Index() int { return p.n }

// Bookmark adds an outline entry pointing at y on the page.
func (d *Doc) Bookmark(title string, p *Page, y float64) {
	d.outline = append(d.outline, outlineItem{title: title, page: p.n, y: y})
}

func (p *Page) printf(format string, a ...any) { fmt.Fprintf(&p.buf, format, a...) }

// Rect fills (and optionally strokes) a rectangle whose top-left corner is x, y.
func (p *Page) Rect(x, y, w, h float64, fill Color) {
	p.printf("%s %s %s %s %s re f\n", fill.op(true), num(x), num(PageHeight-y-h), num(w), num(h))
}

// StrokeRect outlines a rectangle.
func (p *Page) StrokeRect(x, y, w, h, lw float64, c Color) {
	p.printf("%s %s w %s %s %s %s re S\n", c.op(false), num(lw), num(x), num(PageHeight-y-h), num(w), num(h))
}

// RoundRect fills a rectangle with rounded corners of radius r; with lw > 0 it
// also strokes it in stroke.
func (p *Page) RoundRect(x, y, w, h, r float64, fill Color, lw float64, stroke Color) {
	r = math.Min(r, math.Min(w, h)/2)
	const k = 0.5523
	y0 := PageHeight - y - h // bottom
	x1, y1 := x+w, y0+h
	path := fmt.Sprintf("%s %s m %s %s l %s %s %s %s %s %s c %s %s l %s %s %s %s %s %s c %s %s l %s %s %s %s %s %s c %s %s l %s %s %s %s %s %s c h",
		num(x+r), num(y0),
		num(x1-r), num(y0), num(x1-r+r*k), num(y0), num(x1), num(y0+r-r*k), num(x1), num(y0+r),
		num(x1), num(y1-r), num(x1), num(y1-r+r*k), num(x1-r+r*k), num(y1), num(x1-r), num(y1),
		num(x+r), num(y1), num(x+r-r*k), num(y1), num(x), num(y1-r+r*k), num(x), num(y1-r),
		num(x), num(y0+r), num(x), num(y0+r-r*k), num(x+r-r*k), num(y0), num(x+r), num(y0))
	if lw > 0 {
		p.printf("%s %s %s w %s B\n", fill.op(true), stroke.op(false), num(lw), path)
		return
	}
	p.printf("%s %s f\n", fill.op(true), path)
}

// Circle fills a circle centred on cx, cy.
func (p *Page) Circle(cx, cy, r float64, fill Color) {
	p.RoundRect(cx-r, cy-r, 2*r, 2*r, r, fill, 0, Color{})
}

// Line draws a straight line.
func (p *Page) Line(x1, y1, x2, y2, lw float64, c Color) {
	p.printf("%s %s w %s %s m %s %s l S\n", c.op(false), num(lw), num(x1), num(PageHeight-y1), num(x2), num(PageHeight-y2))
}

// Text draws s with its baseline at y.
func (p *Page) Text(x, y float64, f Font, size float64, c Color, s string) {
	if s == "" {
		return
	}
	p.printf("BT /F%d %s Tf %s %s %s Td %s Tj ET\n", int(f)+1, num(size), c.op(true), num(x), num(PageHeight-y), pdfString(Encode(s)))
}

// TextRight draws s so that it ends at x.
func (p *Page) TextRight(x, y float64, f Font, size float64, c Color, s string) {
	p.Text(x-Width(f, size, s), y, f, size, c, s)
}

// Link makes a rectangle (top-left x, y) open url when clicked. Only http and
// https addresses are linked.
func (p *Page) Link(x, y, w, h float64, url string) {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return
	}
	p.links = append(p.links, link{x, y, w, h, url})
}

// pdfString writes bytes as a PDF literal string, escaping what must be.
func pdfString(b []byte) string {
	var sb strings.Builder
	sb.WriteByte('(')
	for _, c := range b {
		switch {
		case c == '(' || c == ')' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 32 || c > 126:
			fmt.Fprintf(&sb, "\\%03o", c)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte(')')
	return sb.String()
}

// Write serialises the document.
func (d *Doc) Write(w io.Writer) error {
	if len(d.pages) == 0 {
		d.AddPage()
	}
	var objs [][]byte // objs[i] is object number i+1
	add := func(body string) int { objs = append(objs, []byte(body)); return len(objs) }
	reserve := func() int { objs = append(objs, nil); return len(objs) }
	set := func(n int, body string) { objs[n-1] = []byte(body) }

	catalog := reserve()
	pagesObj := reserve()
	var fontRefs []string
	for i, name := range fontNames {
		n := add(fmt.Sprintf("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>", name))
		fontRefs = append(fontRefs, fmt.Sprintf("/F%d %d 0 R", i+1, n))
	}
	resources := fmt.Sprintf("<< /Font << %s >> >>", strings.Join(fontRefs, " "))

	pageNums := make([]int, len(d.pages))
	for i := range d.pages {
		pageNums[i] = reserve()
	}
	for i, p := range d.pages {
		content := p.buf.Bytes()
		var stream string
		if d.compress {
			var z bytes.Buffer
			zw := zlib.NewWriter(&z)
			if _, err := zw.Write(content); err != nil {
				return err
			}
			if err := zw.Close(); err != nil {
				return err
			}
			stream = fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream", z.Len(), z.Bytes())
		} else {
			stream = fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content)
		}
		contentObj := add(stream)
		var annots []string
		for _, l := range p.links {
			n := add(fmt.Sprintf("<< /Type /Annot /Subtype /Link /Rect [%s %s %s %s] /Border [0 0 0] /A << /S /URI /URI %s >> >>",
				num(l.x), num(PageHeight-l.y-l.h), num(l.x+l.w), num(PageHeight-l.y), pdfString([]byte(l.url))))
			annots = append(annots, fmt.Sprintf("%d 0 R", n))
		}
		a := ""
		if len(annots) > 0 {
			a = " /Annots [" + strings.Join(annots, " ") + "]"
		}
		set(pageNums[i], fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %s %s] /Resources %s /Contents %d 0 R%s >>",
			pagesObj, num(PageWidth), num(PageHeight), resources, contentObj, a))
	}
	kids := make([]string, len(pageNums))
	for i, n := range pageNums {
		kids[i] = fmt.Sprintf("%d 0 R", n)
	}
	set(pagesObj, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pageNums)))

	outlines := ""
	if len(d.outline) > 0 {
		root := reserve()
		items := make([]int, len(d.outline))
		for i := range d.outline {
			items[i] = reserve()
		}
		for i, it := range d.outline {
			body := fmt.Sprintf("<< /Title %s /Parent %d 0 R /Dest [%d 0 R /XYZ 0 %s 0]", pdfString(Encode(it.title)), root, pageNums[it.page], num(PageHeight-it.y))
			if i > 0 {
				body += fmt.Sprintf(" /Prev %d 0 R", items[i-1])
			}
			if i < len(items)-1 {
				body += fmt.Sprintf(" /Next %d 0 R", items[i+1])
			}
			set(items[i], body+" >>")
		}
		set(root, fmt.Sprintf("<< /Type /Outlines /First %d 0 R /Last %d 0 R /Count %d >>", items[0], items[len(items)-1], len(items)))
		outlines = fmt.Sprintf(" /Outlines %d 0 R /PageMode /UseOutlines", root)
	}
	set(catalog, fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R%s >>", pagesObj, outlines))
	info := add(fmt.Sprintf("<< /Title %s /Subject %s /Creator %s /Producer (CipherHorizon) /CreationDate (D:%s) >>",
		pdfString(Encode(d.Title)), pdfString(Encode(d.Subject)), pdfString(Encode(d.Creator)), d.Created.UTC().Format("20060102150405")+"Z"))

	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, len(objs))
	for i, body := range objs {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, catalog, info, xref)
	_, err := w.Write(out.Bytes())
	return err
}
