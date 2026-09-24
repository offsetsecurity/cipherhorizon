package pefiles

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// A hand-written, bounds-checked reader for the one thing this sensor needs from
// a Windows executable: the version resource (VS_VERSIONINFO). It does not use
// debug/pe because that package parses the whole COFF symbol and string tables and
// sizes allocations from header fields a hostile file controls; here every read
// is small, explicit and capped, and no allocation is sized by the file.
//
// The file is only read, never loaded or executed.

// ErrNotPE means the file is not a PE image (a decoy, a text file, a truncated download).
var ErrNotPE = errors.New("pefiles: not a PE image")

// VersionInfo is what a PE's version resource says. Both strings are chosen by whoever
// built the file (or tampered with it): they are evidence of what the file claims,
// not proof of what it is.
type VersionInfo struct {
	// File is the file version, dotted ("3.5.7.0") from the fixed-size structure
	// when present, else the FileVersion string. Empty when the resource has none.
	File    string
	Product string // ProductName string
	Arch    string // "amd64", "x86", "arm64" or ""
}

const (
	maxReadRVA     = 64 << 10 // the largest resource read
	maxHeaderBytes = 4096     // the largest optional header accepted
	maxSections    = 96       // the PE format's own limit
	maxDirEntries  = 256      // entries examined per resource directory
	maxString      = 128      // characters copied out of a version string
	rtVersion      = 16       // RT_VERSION resource type
)

type section struct {
	va, virtualSize, rawSize, rawPtr uint32
}

type image struct {
	r       io.ReaderAt
	size    int64
	arch    string
	secs    []section
	resRVA  uint32
	resSize uint32
}

func (im *image) readAt(off int64, n int) ([]byte, error) {
	if n < 0 || off < 0 || off+int64(n) > im.size {
		return nil, ErrNotPE
	}
	b := make([]byte, n) // n is bounded by every caller
	if _, err := im.r.ReadAt(b, off); err != nil && (!errors.Is(err, io.EOF) || len(b) != n) {
		return nil, ErrNotPE
	}
	return b, nil
}

// readRVA reads n bytes at a relative virtual address, through the section table.
func (im *image) readRVA(rva uint32, n int) ([]byte, error) {
	if n < 0 || n > maxReadRVA {
		return nil, ErrNotPE
	}
	for _, s := range im.secs {
		span := s.virtualSize
		if s.rawSize > span {
			span = s.rawSize
		}
		if rva < s.va || rva-s.va >= span {
			continue
		}
		rel := rva - s.va
		if uint64(rel)+uint64(n) > uint64(s.rawSize) {
			return nil, ErrNotPE
		}
		return im.readAt(int64(s.rawPtr)+int64(rel), n)
	}
	return nil, ErrNotPE
}

func machineArch(m uint16) string {
	switch m {
	case 0x8664:
		return "amd64"
	case 0x14c:
		return "x86"
	case 0xaa64:
		return "arm64"
	}
	return ""
}

// parseImage reads just enough of the headers to find the section table and the
// resource directory.
func parseImage(r io.ReaderAt, size int64) (*image, error) {
	im := &image{r: r, size: size}
	dos, err := im.readAt(0, 64)
	if err != nil || dos[0] != 'M' || dos[1] != 'Z' {
		return nil, ErrNotPE
	}
	lfanew := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	if lfanew < 64 || lfanew > 1<<20 {
		return nil, ErrNotPE
	}
	hdr, err := im.readAt(lfanew, 24)
	if err != nil || string(hdr[:4]) != "PE\x00\x00" {
		return nil, ErrNotPE
	}
	nsec := int(binary.LittleEndian.Uint16(hdr[6:]))
	optSize := int(binary.LittleEndian.Uint16(hdr[20:]))
	im.arch = machineArch(binary.LittleEndian.Uint16(hdr[4:]))
	if nsec < 1 || nsec > maxSections || optSize < 96 || optSize > maxHeaderBytes {
		return nil, ErrNotPE
	}

	opt, err := im.readAt(lfanew+24, optSize)
	if err != nil {
		return nil, err
	}
	var dirOff int
	switch binary.LittleEndian.Uint16(opt) {
	case 0x10b: // PE32
		dirOff = 96
	case 0x20b: // PE32+
		dirOff = 112
	default:
		return nil, ErrNotPE
	}
	// Data directory entry 2 is the resource table; the header must be long enough to hold it.
	if dirOff+3*8 > len(opt) || int(binary.LittleEndian.Uint32(opt[dirOff-4:])) < 3 {
		return im, nil // a valid image with no resource directory: no version info
	}
	im.resRVA = binary.LittleEndian.Uint32(opt[dirOff+2*8:])
	im.resSize = binary.LittleEndian.Uint32(opt[dirOff+2*8+4:])

	table, err := im.readAt(lfanew+24+int64(optSize), nsec*40)
	if err != nil {
		return nil, err
	}
	for i := 0; i < nsec; i++ {
		e := table[i*40:]
		im.secs = append(im.secs, section{
			virtualSize: binary.LittleEndian.Uint32(e[8:]), va: binary.LittleEndian.Uint32(e[12:]),
			rawSize: binary.LittleEndian.Uint32(e[16:]), rawPtr: binary.LittleEndian.Uint32(e[20:]),
		})
	}
	return im, nil
}

// ReadVersion reads the version resource of the PE image in r (of the given
// size). It returns ErrNotPE for anything that is not a well-formed PE image. A
// valid image with no version resource returns a Version with only Arch set.
func ReadVersion(r io.ReaderAt, size int64) (VersionInfo, error) {
	im, err := parseImage(r, size)
	if err != nil {
		return VersionInfo{}, err
	}
	v := VersionInfo{Arch: im.arch}
	if im.resRVA == 0 || im.resSize == 0 {
		return v, nil
	}
	data, ok := im.findVersionData()
	if !ok {
		return v, nil
	}
	parseVersionBlock(data, &v)
	return v, nil
}

// findVersionData walks type -> name -> language and returns the bytes of the first
// RT_VERSION resource. Three levels, each capped, no recursion.
func (im *image) findVersionData() ([]byte, bool) {
	dir := im.resRVA
	// Level 1: the type directory; pick the RT_VERSION id entry.
	next, isDir, ok := im.dirEntry(dir, func(id uint32, named bool) bool { return !named && id == rtVersion })
	if !ok || !isDir {
		return nil, false
	}
	// Level 2: names; take the first.
	next, isDir, ok = im.dirEntry(im.resRVA+next, func(uint32, bool) bool { return true })
	if !ok || !isDir {
		return nil, false
	}
	// Level 3: languages; take the first, which must be a data entry.
	next, isDir, ok = im.dirEntry(im.resRVA+next, func(uint32, bool) bool { return true })
	if !ok || isDir {
		return nil, false
	}
	entry, err := im.readRVA(im.resRVA+next, 16)
	if err != nil {
		return nil, false
	}
	dataRVA := binary.LittleEndian.Uint32(entry[0:])
	dataSize := binary.LittleEndian.Uint32(entry[4:])
	if dataSize == 0 || dataSize > maxReadRVA {
		return nil, false
	}
	b, err := im.readRVA(dataRVA, int(dataSize))
	if err != nil {
		return nil, false
	}
	return b, true
}

// dirEntry reads the resource directory at rva and returns the offset (relative to
// the resource root) of the first entry accepted by want, and whether it is a
// subdirectory.
func (im *image) dirEntry(rva uint32, want func(id uint32, named bool) bool) (offset uint32, isDir, ok bool) {
	head, err := im.readRVA(rva, 16)
	if err != nil {
		return 0, false, false
	}
	named := int(binary.LittleEndian.Uint16(head[12:]))
	ids := int(binary.LittleEndian.Uint16(head[14:]))
	total := named + ids
	if total > maxDirEntries {
		total = maxDirEntries
	}
	for i := 0; i < total; i++ {
		e, err := im.readRVA(rva+16+uint32(i)*8, 8)
		if err != nil {
			return 0, false, false
		}
		nameOrID := binary.LittleEndian.Uint32(e[0:])
		target := binary.LittleEndian.Uint32(e[4:])
		isNamed := i < named
		if !want(nameOrID, isNamed) {
			continue
		}
		return target &^ 0x80000000, target&0x80000000 != 0, true
	}
	return 0, false, false
}

// parseVersionBlock reads a VS_VERSIONINFO block: the fixed file version, then the
// StringFileInfo strings FileVersion and ProductName. Every offset is checked; a
// malformed block yields whatever was read before the fault.
func parseVersionBlock(b []byte, v *VersionInfo) {
	// VS_VERSIONINFO: wLength, wValueLength, wType, szKey (UTF-16), pad, Value (VS_FIXEDFILEINFO), pad, Children.
	if len(b) < 6 {
		return
	}
	total := int(binary.LittleEndian.Uint16(b[0:]))
	if total > len(b) || total < 6 {
		total = len(b)
	}
	b = b[:total]
	valueLen := int(binary.LittleEndian.Uint16(b[2:]))
	key, pos := utf16Key(b)
	if key != "VS_VERSION_INFO" {
		return
	}
	pos = align4(pos)
	if valueLen >= 52 && pos+52 <= len(b) && binary.LittleEndian.Uint32(b[pos:]) == 0xFEEF04BD {
		ms := binary.LittleEndian.Uint32(b[pos+8:])
		ls := binary.LittleEndian.Uint32(b[pos+12:])
		if ms != 0 || ls != 0 {
			v.File = fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xffff, ls>>16, ls&0xffff)
		}
	}
	if valueLen > 0 {
		pos = align4(pos + valueLen)
	}

	var fileStr, productStr string
	for pos+6 <= len(b) {
		childLen := int(binary.LittleEndian.Uint16(b[pos:]))
		if childLen < 6 || pos+childLen > len(b) {
			break
		}
		child := b[pos : pos+childLen]
		if k, kend := utf16Key(child); k == "StringFileInfo" {
			fileStr, productStr = parseStringTables(child, align4(kend))
		}
		pos = align4(pos + childLen)
	}
	if v.File == "" {
		v.File = clean(fileStr)
	}
	v.Product = clean(productStr)
}

// parseStringTables reads the StringTable blocks inside a StringFileInfo block.
func parseStringTables(b []byte, pos int) (fileVersion, productName string) {
	for pos+6 <= len(b) {
		tlen := int(binary.LittleEndian.Uint16(b[pos:]))
		if tlen < 6 || pos+tlen > len(b) {
			return
		}
		tbl := b[pos : pos+tlen]
		_, kend := utf16Key(tbl) // the language/codepage key, e.g. "040904b0"
		spos := align4(kend)
		for spos+6 <= len(tbl) {
			slen := int(binary.LittleEndian.Uint16(tbl[spos:]))
			vlen := int(binary.LittleEndian.Uint16(tbl[spos+2:])) // in UTF-16 units
			if slen < 6 || spos+slen > len(tbl) {
				break
			}
			ent := tbl[spos : spos+slen]
			name, nend := utf16Key(ent)
			vstart := align4(nend)
			if vlen > 0 && vstart < len(ent) {
				val := utf16String(ent[vstart:], vlen)
				switch name {
				case "FileVersion":
					if fileVersion == "" {
						fileVersion = val
					}
				case "ProductName":
					if productName == "" {
						productName = val
					}
				}
			}
			spos = align4(spos + slen)
		}
		if fileVersion != "" || productName != "" {
			return // the first table that names either is enough
		}
		pos = align4(pos + tlen)
	}
	return
}

func align4(n int) int { return (n + 3) &^ 3 }

// utf16Key reads the NUL-terminated UTF-16 key that follows a block's three-word
// header, returning it and the offset just past its terminator. It is bounded by the block and by maxString.
func utf16Key(b []byte) (string, int) {
	pos := 6 // every key in a version block starts after wLength, wValueLength, wType
	var u []uint16
	for pos+2 <= len(b) {
		c := binary.LittleEndian.Uint16(b[pos:])
		pos += 2
		if c == 0 {
			return string(utf16.Decode(u)), pos
		}
		if len(u) < 64 {
			u = append(u, c)
		}
	}
	return string(utf16.Decode(u)), pos
}

// utf16String reads up to n UTF-16 units from b, stopping at NUL, at most maxString.
func utf16String(b []byte, n int) string {
	if n > maxString {
		n = maxString
	}
	var u []uint16
	for i := 0; i < n && 2*i+2 <= len(b); i++ {
		c := binary.LittleEndian.Uint16(b[2*i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// clean makes a host-supplied string safe to carry: printable ASCII and space only,
// bounded. It is data, never interpreted; anything odd is dropped, not escaped.
func clean(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if sb.Len() >= maxString {
			break
		}
		if r >= 0x20 && r < 0x7f {
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}
