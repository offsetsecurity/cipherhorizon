package pdf

import (
	"strings"
	"unicode"

	"golang.org/x/text/encoding/charmap"
)

// Glyph widths of the standard fonts in thousandths of the font size, for the
// printable ASCII range 32..126 (from the Adobe Core 14 AFM files).
var helvetica = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // space .. /
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // 0..9
	278, 278, 584, 584, 584, 556, 1015, // : ; < = > ? @
	667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, // A..Z
	278, 278, 278, 469, 556, 333, // [ \ ] ^ _ `
	556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, // a..z
	334, 260, 334, 584, // { | } ~
}

var helveticaBold = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
	333, 333, 584, 584, 584, 611, 975,
	722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
	333, 278, 333, 584, 556, 333,
	556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500,
	389, 280, 389, 584,
}

// Widths of the WinAnsi characters above 126 that reports use; others take 556.
var highRegular = map[byte]int{0x80: 556, 0x85: 1000, 0x91: 222, 0x92: 222, 0x93: 333, 0x94: 333, 0x95: 350, 0x96: 556, 0x97: 1000,
	0xa0: 278, 0xa9: 737, 0xb0: 400, 0xb7: 278, 0xd7: 584}
var highBold = map[byte]int{0x80: 556, 0x85: 1000, 0x91: 278, 0x92: 278, 0x93: 500, 0x94: 500, 0x95: 350, 0x96: 556, 0x97: 1000,
	0xa0: 278, 0xa9: 737, 0xb0: 400, 0xb7: 278, 0xd7: 584}

// Characters outside WinAnsi that reports are likely to contain, written in
// characters the standard fonts have.
var substitutes = map[rune]string{
	'→': "->", '←': "<-", '⇒': "=>", '≤': "<=", '≥': ">=", '≠': "!=", '≈': "~",
	'✔': "", '✓': "", '✖': "x", '✗': "x", '▲': "!", '⚠': "!", '○': "o", '●': "•", '◆': "•",
	' ': " ", ' ': " ", ' ': " ", '​': "", '‑': "-", '−': "-", '⌄': "v", '›': ">",
}

// Encode converts text to the WinAnsi bytes the fonts are declared with.
// Control characters become spaces; anything the fonts cannot show becomes "?".
func Encode(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if sub, ok := substitutes[r]; ok {
			out = append(out, Encode(sub)...)
			continue
		}
		if unicode.IsControl(r) {
			out = append(out, ' ')
			continue
		}
		if r < 128 {
			out = append(out, byte(r)) //nolint:gosec // r < 128 fits a byte
			continue
		}
		if b, ok := charmap.Windows1252.EncodeRune(r); ok {
			out = append(out, b)
			continue
		}
		out = append(out, '?')
	}
	return out
}

// Width is the advance width of s in points.
func Width(f Font, size float64, s string) float64 {
	total := 0
	for _, b := range Encode(s) {
		total += glyphWidth(f, b)
	}
	return float64(total) * size / 1000
}

func glyphWidth(f Font, b byte) int {
	if f == Mono {
		return 600
	}
	table, high := &helvetica, highRegular
	if f == Bold {
		table, high = &helveticaBold, highBold
	}
	if b >= 32 && b <= 126 {
		return table[b-32]
	}
	if w, ok := high[b]; ok {
		return w
	}
	return 556
}

// Clean collapses runs of white space, as a paragraph shows them.
func Clean(s string) string { return strings.Join(strings.Fields(s), " ") }
