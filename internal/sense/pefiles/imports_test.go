package pefiles

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/example/cipherhorizon/internal/sense/pefiles/pefilestest"
)

func imports(t *testing.T, b []byte) []string {
	t.Helper()
	names, err := ReadImports(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("ReadImports: %v", err)
	}
	return names
}

func TestReadImportsReturnsLowerCasedNamesWithoutDuplicates(t *testing.T) {
	img := pefilestest.Build(pefilestest.Opts{Imports: []string{"KERNEL32.dll", "libcrypto-3-x64.dll", "libcrypto-3-x64.DLL"}}, 3<<16, 0, "3.0.0", "x")
	got := imports(t, img)
	want := []string{"kernel32.dll", "libcrypto-3-x64.dll"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("imports = %v, want %v", got, want)
	}
}

func TestImportsAndVersionAreReadFromTheSameImage(t *testing.T) {
	img := pefilestest.Build(pefilestest.Opts{Imports: []string{"libcrypto-3-x64.dll"}}, 3<<16|5, 7<<16, "3.5.7", "The OpenSSL Toolkit")
	if v := read(t, img); v.File != "3.5.7.0" || v.Product != "The OpenSSL Toolkit" {
		t.Errorf("version with an import table present = %+v", v)
	}
	if got := imports(t, img); len(got) != 1 || got[0] != "libcrypto-3-x64.dll" {
		t.Errorf("imports = %v", got)
	}
}

func TestReadImportsOfAnImageWithoutAnImportTable(t *testing.T) {
	if got := imports(t, pefilestest.Build(pefilestest.Opts{}, 1<<16, 0, "1.0", "x")); len(got) != 0 {
		t.Errorf("imports = %v, want none", got)
	}
	if got := imports(t, pefilestest.Build(pefilestest.Opts{NoResDir: true}, 1<<16, 0, "1.0", "x")); len(got) != 0 {
		t.Errorf("imports of an image with no directories = %v, want none", got)
	}
}

func TestReadImportsRejectsNonPE(t *testing.T) {
	for name, b := range map[string][]byte{"text": []byte("not a PE"), "empty": nil, "MZ only": []byte("MZ")} {
		if _, err := ReadImports(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrNotPE) {
			t.Errorf("%s: err = %v, want ErrNotPE", name, err)
		}
	}
}

// A hostile image controls every byte of the import table: names that are not
// printable, names that never end, names outside the section, and far more
// descriptors than any real image has.
func TestHostileImportTablesAreBoundedAndSkipped(t *testing.T) {
	desc := func(nameRVA uint32) []byte {
		var d [20]byte
		binary.LittleEndian.PutUint32(d[12:], nameRVA)
		return d[:]
	}
	t.Run("unprintable, unterminated, out of range and empty names are skipped", func(t *testing.T) {
		var raw []byte
		raw = append(raw, desc(0x2000+5*20)...)    // "ok.dll"
		raw = append(raw, desc(0x2000+5*20+7)...)  // "bad\x01.dll"
		raw = append(raw, desc(0x2000+5*20+16)...) // unterminated run to the end of the section
		raw = append(raw, desc(0x9000_0000)...)    // far outside every section
		raw = append(raw, make([]byte, 20)...)     // terminator
		raw = append(raw, "ok.dll\x00bad\x01.dll\x00"...)
		raw = append(raw, bytes.Repeat([]byte("A"), 200)...) // no NUL before the section ends
		got := imports(t, pefilestest.Build(pefilestest.Opts{RawImportBytes: raw}, 1<<16, 0, "1.0", "x"))
		if !reflect.DeepEqual(got, []string{"ok.dll"}) {
			t.Errorf("imports = %v, want only ok.dll", got)
		}
	})
	t.Run("a huge table is capped", func(t *testing.T) {
		const n = 5000
		nameOff := uint32(0x2000 + n*20)
		var raw []byte
		for i := 0; i < n; i++ {
			raw = append(raw, desc(nameOff)...)
		}
		raw = append(raw, "dup.dll\x00"...)
		got := imports(t, pefilestest.Build(pefilestest.Opts{RawImportBytes: raw}, 1<<16, 0, "1.0", "x"))
		if len(got) > maxImports {
			t.Errorf("%d names returned, cap is %d", len(got), maxImports)
		}
	})
	t.Run("a name longer than the cap is not reported", func(t *testing.T) {
		raw := append(desc(0x2000+40), make([]byte, 20)...)
		raw = append(raw, bytes.Repeat([]byte("a"), maxImportName+10)...)
		raw = append(raw, 0)
		if got := imports(t, pefilestest.Build(pefilestest.Opts{RawImportBytes: raw}, 1<<16, 0, "1.0", "x")); len(got) != 0 {
			t.Errorf("imports = %v, want none", got)
		}
	})
}

func TestImportTruncationsAndCorruptionsNeverPanic(t *testing.T) {
	img := pefilestest.Build(pefilestest.Opts{Imports: []string{"libcrypto-3-x64.dll", "kernel32.dll"}}, 3<<16, 0, "3.0.0", "x")
	for n := 0; n <= len(img); n += 3 {
		_, _ = ReadImports(bytes.NewReader(img[:n]), int64(n))
	}
	for i := 0; i < len(img); i += 7 {
		c := append([]byte(nil), img...)
		c[i] ^= 0xff
		_, _ = ReadImports(bytes.NewReader(c), int64(len(c)))
	}
}

func FuzzReadImports(f *testing.F) {
	f.Add(pefilestest.Build(pefilestest.Opts{Imports: []string{"libcrypto-3-x64.dll"}}, 3<<16, 0, "3.0.0", "x"))
	f.Add(pefilestest.Build(pefilestest.Opts{Imports: []string{"a.dll", "b.dll"}, PE32: true}, 1<<16, 0, "1.0", "x"))
	f.Add(pefilestest.Build(pefilestest.Opts{}, 1<<16, 0, "1.0", "x"))
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, b []byte) {
		names, err := ReadImports(bytes.NewReader(b), int64(len(b)))
		if err != nil && !errors.Is(err, ErrNotPE) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if len(names) > maxImports {
			t.Fatalf("%d names", len(names))
		}
		for _, n := range names {
			if !printableLibName(n) || len(n) > maxImportName {
				t.Fatalf("bad name %q", n)
			}
		}
	})
}
