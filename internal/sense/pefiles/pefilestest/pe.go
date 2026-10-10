// Package pefilestest builds small, valid PE images with a version resource, so the
// PE parser, the sensor and the pipeline are tested on any OS without shipping real
// binaries. Test support only.
package pefilestest

import (
	"encoding/binary"
	"unicode/utf16"
)

// u16 and u32 convert a length to the field width, failing loudly on a value the test
// helper never intends to build.
func u16(n int) uint16 {
	if n < 0 || n > 0xffff {
		panic("pefilestest: value out of range for a 16-bit field")
	}
	return uint16(n)
}

func u32(n int) uint32 {
	if n < 0 || int64(n) > 0xffffffff {
		panic("pefilestest: value out of range for a 32-bit field")
	}
	return uint32(n)
}

func u16s(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// vsBlock encodes one VS_VERSIONINFO-style block.
func vsBlock(key string, valueLen int, typ uint16, value []byte, children ...[]byte) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint16(b, 0) // wLength, patched below
	b = binary.LittleEndian.AppendUint16(b, u16(valueLen))
	b = binary.LittleEndian.AppendUint16(b, typ)
	b = append(b, u16s(key)...)
	b = append(b, 0, 0)
	b = pad4(b)
	b = append(b, value...)
	b = pad4(b)
	for _, c := range children {
		b = append(b, pad4(c)...)
	}
	binary.LittleEndian.PutUint16(b[0:], u16(len(b)))
	return b
}

func strEntry(name, value string) []byte {
	v := append(u16s(value), 0, 0)
	return vsBlock(name, len(v)/2, 1, v)
}

func fixedInfo(ms, ls uint32) []byte {
	var b []byte
	for _, w := range []uint32{0xFEEF04BD, 0x10000, ms, ls, ms, ls, 0x3f, 0, 4, 2, 0, 0, 0} {
		b = binary.LittleEndian.AppendUint32(b, w)
	}
	return b
}

// versionBlock builds a complete VS_VERSIONINFO for the given fixed version and strings.
func versionBlock(fixedMS, fixedLS uint32, fileVersion, product string) []byte {
	var entries [][]byte
	if fileVersion != "" {
		entries = append(entries, strEntry("FileVersion", fileVersion))
	}
	if product != "" {
		entries = append(entries, strEntry("ProductName", product))
	}
	table := vsBlock("040904b0", 0, 1, nil, entries...)
	sfi := vsBlock("StringFileInfo", 0, 1, nil, table)
	return vsBlock("VS_VERSION_INFO", 52, 0, fixedInfo(fixedMS, fixedLS), sfi)
}

// Opts tunes the image Build makes.
type Opts struct {
	Machine   uint16
	NoResDir  bool   // NumberOfRvaAndSizes = 0: a valid image with no resources
	DataSize  uint32 // override the resource data-entry size (0 = real size)
	PE32      bool
	BlockOnly []byte // override the version block bytes
	// Imports are library names for a static import table in an .idata section.
	Imports []string
	// RawImportBytes replaces the whole import section content (hostile-table tests).
	RawImportBytes []byte
}

// Build returns a minimal PE image whose .rsrc section holds a version resource.
func Build(o Opts, fixedMS, fixedLS uint32, fileVersion, product string) []byte {
	if o.Machine == 0 {
		o.Machine = 0x8664
	}
	block := o.BlockOnly
	if block == nil {
		block = versionBlock(fixedMS, fixedLS, fileVersion, product)
	}

	// Resource tree, RVA 0x1000: root(type) -> name -> language -> data entry -> block.
	var rsrc []byte
	dir := func(entryID, target uint32) []byte {
		var d []byte
		d = binary.LittleEndian.AppendUint32(d, 0) // Characteristics
		d = binary.LittleEndian.AppendUint32(d, 0) // TimeDateStamp
		d = binary.LittleEndian.AppendUint16(d, 0) // Major
		d = binary.LittleEndian.AppendUint16(d, 0) // Minor
		d = binary.LittleEndian.AppendUint16(d, 0) // named entries
		d = binary.LittleEndian.AppendUint16(d, 1) // id entries
		d = binary.LittleEndian.AppendUint32(d, entryID)
		d = binary.LittleEndian.AppendUint32(d, target)
		return d
	}
	rsrc = append(rsrc, dir(16, 0x80000000|0x18)...) // root  @0x00: type 16 -> dir @0x18
	rsrc = append(rsrc, dir(1, 0x80000000|0x30)...)  // names @0x18: id 1  -> dir @0x30
	rsrc = append(rsrc, dir(0x409, 0x48)...)         // langs @0x30: lang  -> data entry @0x48
	size := u32(len(block))
	if o.DataSize != 0 {
		size = o.DataSize
	}
	rsrc = binary.LittleEndian.AppendUint32(rsrc, 0x1000+0x58) // data entry @0x48: RVA
	rsrc = binary.LittleEndian.AppendUint32(rsrc, size)
	rsrc = binary.LittleEndian.AppendUint32(rsrc, 0)
	rsrc = binary.LittleEndian.AppendUint32(rsrc, 0)
	for len(rsrc) < 0x58 {
		rsrc = append(rsrc, 0)
	}
	rsrc = append(rsrc, block...)

	optSize := 240
	dirOff := 112
	magic := uint16(0x20b)
	if o.PE32 {
		optSize, dirOff, magic = 224, 96, 0x10b
	}

	// Import table, RVA 0x2000: descriptors, a zero terminator, then the names.
	var idata []byte
	if o.RawImportBytes != nil {
		idata = o.RawImportBytes
	} else if len(o.Imports) > 0 {
		nameOff := (len(o.Imports) + 1) * 20
		var names []byte
		for i, n := range o.Imports {
			var d [20]byte
			binary.LittleEndian.PutUint32(d[12:], u32(0x2000+nameOff+len(names)))
			idata = append(idata, d[:]...)
			_ = i
			names = append(names, n...)
			names = append(names, 0)
		}
		idata = append(idata, make([]byte, 20)...) // terminator
		idata = append(idata, names...)
	}

	img := make([]byte, 0x200)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], 0x80)
	copy(img[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(img[0x84:], o.Machine)
	nsec := 1
	if len(idata) > 0 {
		nsec = 2
	}
	binary.LittleEndian.PutUint16(img[0x86:], u16(nsec)) // sections
	binary.LittleEndian.PutUint16(img[0x94:], u16(optSize))
	opt := img[0x98:]
	binary.LittleEndian.PutUint16(opt, magic)
	nrva := uint32(16)
	if o.NoResDir && len(idata) == 0 {
		nrva = 0
	}
	binary.LittleEndian.PutUint32(opt[dirOff-4:], nrva)
	binary.LittleEndian.PutUint32(opt[dirOff+2*8:], 0x1000)
	binary.LittleEndian.PutUint32(opt[dirOff+2*8+4:], u32(len(rsrc)))
	if len(idata) > 0 {
		binary.LittleEndian.PutUint32(opt[dirOff+1*8:], 0x2000)
		binary.LittleEndian.PutUint32(opt[dirOff+1*8+4:], u32(len(idata)))
		sec2 := img[0x98+optSize+40:]
		copy(sec2, ".idata")
		binary.LittleEndian.PutUint32(sec2[8:], u32(len(idata)))  // virtual size
		binary.LittleEndian.PutUint32(sec2[12:], 0x2000)          // VA
		binary.LittleEndian.PutUint32(sec2[16:], u32(len(idata))) // raw size
		binary.LittleEndian.PutUint32(sec2[20:], u32(0x200+len(rsrc)))
	}
	sec := img[0x98+optSize:]
	copy(sec, ".rsrc")
	binary.LittleEndian.PutUint32(sec[8:], u32(len(rsrc)))  // virtual size
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)         // VA
	binary.LittleEndian.PutUint32(sec[16:], u32(len(rsrc))) // raw size
	binary.LittleEndian.PutUint32(sec[20:], 0x200)          // raw pointer
	img = append(img, rsrc...)
	return append(img, idata...)
}
