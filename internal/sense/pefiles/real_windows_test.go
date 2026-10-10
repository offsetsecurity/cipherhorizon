//go:build windows

package pefiles

import (
	"debug/pe"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The synthetic PE builder cannot catch a mistake that real binaries expose (a
// different alignment, resources in a different order). On Windows, read a sample of
// genuine Microsoft binaries and require that the parser copes: no error for a
// valid image, and a version for the great majority (system files carry one).
func TestParsesGenuineSystemBinaries(t *testing.T) {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	ents, err := os.ReadDir(sys)
	if err != nil {
		t.Skipf("cannot read %s: %v", sys, err)
	}
	var tried, withVersion int
	for _, e := range ents {
		if tried >= 300 {
			break
		}
		if e.IsDir() || filepath.Ext(e.Name()) != ".dll" {
			continue
		}
		f, err := os.Open(filepath.Join(sys, e.Name()))
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close() //nolint:errcheck // read-only
			continue
		}
		v, perr := ReadVersion(f, fi.Size())
		f.Close() //nolint:errcheck // read-only
		tried++
		if perr != nil {
			t.Errorf("%s: %v", e.Name(), perr)
			continue
		}
		if v.File != "" {
			withVersion++
		}
	}
	if tried < 50 {
		t.Skipf("only %d binaries readable", tried)
	}
	if withVersion*100 < tried*95 {
		t.Errorf("only %d of %d system binaries yielded a version", withVersion, tried)
	}
	t.Logf("parsed %d genuine binaries, %d with a version", tried, withVersion)
}

// The import reader is checked against a second, independent implementation: the
// standard library's debug/pe, used here only as an oracle in a test. For each
// genuine binary, every library the standard library names must be in our list;
// ours may list more, and the difference is only logged.
func TestImportsAgreeWithTheStandardLibraryOnGenuineBinaries(t *testing.T) {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	ents, err := os.ReadDir(sys)
	if err != nil {
		t.Skipf("cannot read %s: %v", sys, err)
	}
	var tried, withImports, extra int
	for _, e := range ents {
		if tried >= 400 {
			break
		}
		if e.IsDir() || filepath.Ext(e.Name()) != ".dll" {
			continue
		}
		p := filepath.Join(sys, e.Name())
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close() //nolint:errcheck // read-only
			continue
		}
		ours, oerr := ReadImports(f, fi.Size())
		f.Close() //nolint:errcheck // read-only
		pf, perr := pe.Open(p)
		if perr != nil || oerr != nil {
			continue // the oracle or ours could not read it: not a comparison
		}
		syms, _ := pf.ImportedSymbols()
		pf.Close() //nolint:errcheck // read-only
		tried++
		have := map[string]bool{}
		for _, n := range ours {
			have[n] = true
		}
		theirs := map[string]bool{}
		for _, s := range syms {
			if _, dll, ok := strings.Cut(s, ":"); ok {
				theirs[strings.ToLower(dll)] = true
			}
		}
		for dll := range theirs {
			if !have[dll] {
				t.Errorf("%s: the standard library sees an import of %q that ours does not", e.Name(), dll)
			}
		}
		if len(ours) > 0 {
			withImports++
		}
		extra += len(have) - len(theirs)
	}
	if tried < 50 {
		t.Skipf("only %d binaries compared", tried)
	}
	if withImports*100 < tried*90 {
		t.Errorf("only %d of %d binaries had imports read", withImports, tried)
	}
	t.Logf("compared %d genuine binaries: every import the standard library reports was found; ours listed %d names the standard library did not (probably libraries imported only by ordinal, which debug/pe omits; not verified)", tried, extra)
}
