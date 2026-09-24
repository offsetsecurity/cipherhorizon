//go:build windows

package pefiles

import (
	"os"
	"path/filepath"
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
