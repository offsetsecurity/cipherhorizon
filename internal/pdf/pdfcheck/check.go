// Package pdfcheck reads back the PDFs package pdf writes, for tests: it
// checks the cross-reference table points at every object, then returns the
// page count, the text shown, the links and the outline titles.
package pdfcheck

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Info is what a document contains.
type Info struct {
	Pages   int
	Text    string // every string shown, joined by spaces, decoded from WinAnsi
	Links   []string
	Outline []string
}

var (
	reStartXref = regexp.MustCompile(`startxref\s+(\d+)\s+%%EOF\s*$`)
	reSize      = regexp.MustCompile(`/Size (\d+)`)
	reStream    = regexp.MustCompile(`(?s)<< /Length (\d+)( /Filter /FlateDecode)? >>\nstream\n`)
	reTj        = regexp.MustCompile(`\((?:[^()\\]|\\.)*\) Tj`)
	reURI       = regexp.MustCompile(`/URI (\((?:[^()\\]|\\.)*\))`)
	reTitle     = regexp.MustCompile(`/Title (\((?:[^()\\]|\\.)*\)) /Parent`)
)

// Check validates the structure of b and reads its content.
func Check(b []byte) (Info, error) {
	var info Info
	if !bytes.HasPrefix(b, []byte("%PDF-1.")) {
		return info, fmt.Errorf("no PDF header")
	}
	m := reStartXref.FindSubmatch(b)
	if m == nil {
		return info, fmt.Errorf("no startxref/%%%%EOF trailer")
	}
	xref, _ := strconv.Atoi(string(m[1]))
	if xref <= 0 || xref >= len(b) || !bytes.HasPrefix(b[xref:], []byte("xref\n")) {
		return info, fmt.Errorf("startxref %d does not point at the xref table", xref)
	}
	sm := reSize.FindSubmatch(b[xref:])
	if sm == nil {
		return info, fmt.Errorf("trailer has no /Size")
	}
	size, _ := strconv.Atoi(string(sm[1]))
	lines := strings.Split(string(b[xref:]), "\n")
	if len(lines) < size+2 {
		return info, fmt.Errorf("xref table is short")
	}
	for n := 1; n < size; n++ {
		entry := lines[2+n]
		if len(entry) < 18 || entry[17] != 'n' {
			return info, fmt.Errorf("xref entry %d is not in use: %q", n, entry)
		}
		off, err := strconv.Atoi(entry[:10])
		if err != nil || off >= len(b) || !bytes.HasPrefix(b[off:], []byte(fmt.Sprintf("%d 0 obj\n", n))) {
			return info, fmt.Errorf("xref entry %d (offset %d) does not point at its object", n, off)
		}
	}
	info.Pages = bytes.Count(b, []byte("/Type /Page /Parent"))

	var text []string
	for _, loc := range reStream.FindAllSubmatchIndex(b, -1) {
		length, _ := strconv.Atoi(string(b[loc[2]:loc[3]]))
		start := loc[1]
		if start+length > len(b) {
			return info, fmt.Errorf("stream overruns the file")
		}
		data := b[start : start+length]
		if loc[4] >= 0 {
			zr, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				return info, fmt.Errorf("stream: %w", err)
			}
			data, err = io.ReadAll(zr)
			if err != nil {
				return info, fmt.Errorf("stream: %w", err)
			}
		}
		for _, tj := range reTj.FindAll(data, -1) {
			text = append(text, Unescape(string(tj[:len(tj)-3])))
		}
	}
	info.Text = strings.Join(text, " ")
	for _, u := range reURI.FindAllSubmatch(b, -1) {
		info.Links = append(info.Links, Unescape(string(u[1])))
	}
	for _, t := range reTitle.FindAllSubmatch(b, -1) {
		info.Outline = append(info.Outline, Unescape(string(t[1])))
	}
	return info, nil
}

// Unescape decodes a PDF literal string "(…)" written in WinAnsi.
func Unescape(lit string) string {
	s := strings.TrimSuffix(strings.TrimPrefix(lit, "("), ")")
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			out = append(out, c)
			continue
		}
		i++
		switch {
		case s[i] >= '0' && s[i] <= '7' && i+2 < len(s):
			v, err := strconv.ParseUint(s[i:i+3], 8, 8)
			if err == nil {
				out = append(out, byte(v))
				i += 2
				continue
			}
			out = append(out, s[i])
		default:
			out = append(out, s[i])
		}
	}
	// WinAnsi to UTF-8 for the characters reports use.
	var sb strings.Builder
	for _, c := range out {
		switch c {
		case 0x95:
			sb.WriteRune('•')
		case 0x96:
			sb.WriteRune('–')
		case 0x97:
			sb.WriteRune('—')
		case 0xb7:
			sb.WriteRune('·')
		default:
			if c < 0x80 {
				sb.WriteByte(c)
			} else {
				sb.WriteRune(rune(c))
			}
		}
	}
	return sb.String()
}
