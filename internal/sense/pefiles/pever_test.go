package pefiles

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/sense/pefiles/pefilestest"
)

func read(t *testing.T, b []byte) VersionInfo {
	t.Helper()
	v, err := ReadVersion(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReadVersion(t *testing.T) {
	// 3.5.7.0
	img := pefilestest.Build(pefilestest.Opts{}, 3<<16|5, 7<<16, "3.5.7", "The OpenSSL Toolkit")
	v := read(t, img)
	if v.File != "3.5.7.0" || v.Product != "The OpenSSL Toolkit" || v.Arch != "amd64" {
		t.Errorf("version = %+v", v)
	}
}

func TestReadVersionPE32AndArchitectures(t *testing.T) {
	for machine, want := range map[uint16]string{0x8664: "amd64", 0x14c: "x86", 0xaa64: "arm64", 0x1c0: ""} {
		v := read(t, pefilestest.Build(pefilestest.Opts{Machine: machine, PE32: machine == 0x14c}, 1<<16, 0, "1.0", "P"))
		if v.Arch != want || v.File != "1.0.0.0" {
			t.Errorf("machine %#x: %+v", machine, v)
		}
	}
}

func TestReadVersionFallsBackToTheStringWhenTheFixedInfoIsEmpty(t *testing.T) {
	v := read(t, pefilestest.Build(pefilestest.Opts{}, 0, 0, "1.1.1w", "OpenSSL"))
	if v.File != "1.1.1w" || v.Product != "OpenSSL" {
		t.Errorf("version = %+v", v)
	}
}

func TestReadVersionValidImageWithoutResources(t *testing.T) {
	v := read(t, pefilestest.Build(pefilestest.Opts{NoResDir: true}, 3, 0, "x", "y"))
	if v.File != "" || v.Product != "" || v.Arch != "amd64" {
		t.Errorf("version = %+v", v)
	}
}

func TestNotPE(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":      nil,
		"text":       []byte("this is a note about libcrypto, not a library"),
		"MZ only":    []byte("MZ"),
		"bad lfanew": append([]byte("MZ"), make([]byte, 100)...),
		"bad PE magic": func() []byte {
			b := pefilestest.Build(pefilestest.Opts{}, 1, 0, "1", "p")
			copy(b[0x80:], "XX\x00\x00")
			return b
		}(),
		"zero sections": func() []byte {
			b := pefilestest.Build(pefilestest.Opts{}, 1, 0, "1", "p")
			b[0x86], b[0x87] = 0, 0
			return b
		}(),
		"too many sections": func() []byte {
			b := pefilestest.Build(pefilestest.Opts{}, 1, 0, "1", "p")
			b[0x86] = 200
			return b
		}(),
	} {
		if _, err := ReadVersion(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrNotPE) {
			t.Errorf("%s: err = %v, want ErrNotPE", name, err)
		}
	}
}

// Strings from the file are attacker-controlled: they must come out bounded and printable.
func TestVersionStringsAreCleanedAndBounded(t *testing.T) {
	evil := "3.5\x1b[31m\x00hidden" + string(bytes.Repeat([]byte("A"), 1000))
	v := read(t, pefilestest.Build(pefilestest.Opts{}, 0, 0, evil, "Prod\r\nuct"+string(bytes.Repeat([]byte("B"), 500))))
	for _, s := range []string{v.File, v.Product} {
		if len(s) > maxString {
			t.Errorf("string of %d bytes escaped the cap", len(s))
		}
		for _, r := range s {
			if r < 0x20 || r >= 0x7f {
				t.Errorf("unprintable %q survived in %q", r, s)
			}
		}
	}
}

func TestHostileSizesDoNotOverrun(t *testing.T) {
	// A data entry that claims 4 GiB, and one that claims more than the section holds.
	for _, size := range []uint32{0xFFFFFFFF, 1 << 20, 100000} {
		b := pefilestest.Build(pefilestest.Opts{DataSize: size}, 1, 0, "1", "p")
		if v, err := ReadVersion(bytes.NewReader(b), int64(len(b))); err != nil || v.File != "" {
			t.Errorf("size %d: %+v %v (want a valid image with no readable version)", size, v, err)
		}
	}
}

// Every truncation and a batch of random corruptions of a valid image must return
// (an error or a partial result) without panicking, hanging or allocating from
// file-supplied sizes.
func TestTruncationsAndCorruptionsNeverPanic(t *testing.T) {
	good := pefilestest.Build(pefilestest.Opts{}, 3<<16|5, 7<<16, "3.5.7", "The OpenSSL Toolkit")
	for i := 0; i <= len(good); i++ {
		_, _ = ReadVersion(bytes.NewReader(good[:i]), int64(i))
	}
	rng := rand.New(rand.NewSource(1))
	for n := 0; n < 3000; n++ {
		b := append([]byte(nil), good...)
		for k := 0; k < 1+rng.Intn(8); k++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		_, _ = ReadVersion(bytes.NewReader(b), int64(len(b)))
	}
}

func FuzzReadVersion(f *testing.F) {
	f.Add(pefilestest.Build(pefilestest.Opts{}, 3<<16|5, 7<<16, "3.5.7", "The OpenSSL Toolkit"))
	f.Add(pefilestest.Build(pefilestest.Opts{PE32: true, Machine: 0x14c}, 0, 0, "1.1.1w", "OpenSSL"))
	f.Add(pefilestest.Build(pefilestest.Opts{NoResDir: true}, 0, 0, "", ""))
	f.Add([]byte("MZ"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := ReadVersion(bytes.NewReader(b), int64(len(b)))
		if err == nil && (len(v.File) > maxString || len(v.Product) > maxString) {
			t.Fatalf("string over cap: %+v", v)
		}
	})
}
