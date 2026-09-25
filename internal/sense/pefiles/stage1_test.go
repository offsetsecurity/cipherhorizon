package pefiles

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/sense/pefiles/pefilestest"
)

func peImage(fileVersion string, imports ...string) []byte {
	return pefilestest.Build(pefilestest.Opts{Imports: imports}, 3<<16|5, 7<<16, fileVersion, "The OpenSSL Toolkit")
}

func peObs(b evidence.Batch, name string) (evidence.Observation, bool) {
	for _, o := range byMethod(b, evidence.MethodPEVersion) {
		if o.Subject.Name == name {
			return o, true
		}
	}
	return evidence.Observation{}, false
}

func TestTheHashIsTheSHA256OfTheFile(t *testing.T) {
	img := peImage("3.5.7")
	b := collect(t, fstest.MapFS{"Program Files/Git/bin/libcrypto-3-x64.dll": file(img)})
	sum := sha256.Sum256(img)
	o, ok := peObs(b, "libcrypto-3-x64.dll")
	if !ok || o.Subject.Attrs["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %q, want %x", o.Subject.Attrs["sha256"], sum)
	}
	if n := b.Coverage[0].Limits["filesHashed"]; n != "1" {
		t.Errorf("coverage filesHashed = %q", n)
	}
	if b.Coverage[0].Limits["bytesHashed"] != strconv.Itoa(len(img)) {
		t.Errorf("coverage bytesHashed = %q, want %d", b.Coverage[0].Limits["bytesHashed"], len(img))
	}
}

func TestAFileThatIsNotAPEIsNeverHashed(t *testing.T) {
	b := collect(t, fstest.MapFS{"Program Files/Evil/libcrypto-3-x64.dll": file([]byte("not a PE at all"))})
	for _, o := range b.Observations {
		if _, has := o.Subject.Attrs["sha256"]; has {
			t.Errorf("a decoy was hashed: %+v", o.Subject.Attrs)
		}
	}
}

func TestTheHashingBudgetIsEnforcedAndReported(t *testing.T) {
	old := maxHashTotal
	maxHashTotal = int64(len(peImage("3.5.7"))) + 10 // room for one file, not two
	t.Cleanup(func() { maxHashTotal = old })
	b := collect(t, fstest.MapFS{
		"Program Files/A/libcrypto-3-x64.dll": file(peImage("3.5.7")),
		"Program Files/B/libcrypto-3-x64.dll": file(peImage("3.5.7")),
	})
	hashed := 0
	for _, o := range byMethod(b, evidence.MethodPEVersion) {
		if o.Subject.Attrs["sha256"] != "" {
			hashed++
		}
	}
	if hashed != 1 || b.Coverage[0].Limits["filesHashed"] != "1" {
		t.Errorf("hashed %d files (coverage %q); the budget allows exactly one", hashed, b.Coverage[0].Limits["filesHashed"])
	}
}

func boundBy(b evidence.Batch) map[string][]string {
	out := map[string][]string{}
	for _, o := range byMethod(b, evidence.MethodPEImports) {
		for _, r := range o.Relations {
			out[o.Subject.Name] = append(out[o.Subject.Name], r.To)
		}
	}
	return out
}

func key(p string) string { return evidence.ArtefactKey(p) }

// The consumers (libssl, the openssl command) are linked to the provider they
// import from the same directory, and only to recognised crypto libraries.
func TestConsumersAreLinkedToTheirProviderInTheSameDirectory(t *testing.T) {
	dir := "Program Files/Git/mingw64/bin/"
	b := collect(t, fstest.MapFS{
		dir + "libcrypto-3-x64.dll": file(peImage("3.5.7", "kernel32.dll")),
		dir + "libssl-3-x64.dll":    file(peImage("3.5.7", "kernel32.dll", "libcrypto-3-x64.dll", "ws2_32.dll")),
		dir + "openssl.exe":         file(peImage("3.5.7", "libssl-3-x64.dll", "libcrypto-3-x64.dll", "msvcrt.dll")),
	})
	got := boundBy(b)
	if len(got["libcrypto-3-x64.dll"]) != 0 {
		t.Errorf("the provider imports no crypto library: %v", got["libcrypto-3-x64.dll"])
	}
	if want := []string{key(dir + "libcrypto-3-x64.dll")}; !equal(got["libssl-3-x64.dll"], want) {
		t.Errorf("libssl links to %v, want %v", got["libssl-3-x64.dll"], want)
	}
	if want := []string{key(dir + "libcrypto-3-x64.dll"), key(dir + "libssl-3-x64.dll")}; !equal(got["openssl.exe"], want) {
		t.Errorf("openssl.exe links to %v, want %v", got["openssl.exe"], want)
	}

	// Every other import (kernel32, ws2_32, msvcrt) is dropped, not recorded.
	ssl, _ := peObs(b, "libssl-3-x64.dll")
	if ssl.Subject.Attrs["imports"] != "libcrypto-3-x64.dll" {
		t.Errorf("imports attribute = %q, want only the recognised crypto library", ssl.Subject.Attrs["imports"])
	}
	for _, o := range byMethod(b, evidence.MethodPEImports) {
		if q, _ := evidence.QualityOf(o); q != evidence.QualityParsed {
			t.Errorf("import evidence quality = %s, want parsed", q)
		}
		if o.Claim.Rung != evidence.RungBound || o.Claim.Binding != evidence.BindStaticImport {
			t.Errorf("import claim = %+v, want bound / static-import", o.Claim)
		}
		if evidence.ClassOf(o.Claim) != evidence.E1Reachable {
			t.Errorf("import evidence class = %v; a static import is reachability, never use", evidence.ClassOf(o.Claim))
		}
	}
}

// The import table proves a name, not which file that name resolves to: a library
// in another directory is not linked, but the name is still reported.
func TestALibraryInAnotherDirectoryIsNotLinked(t *testing.T) {
	b := collect(t, fstest.MapFS{
		"Program Files/App/libssl-3-x64.dll":          file(peImage("3.5.7", "libcrypto-3-x64.dll")),
		"Program Files/Elsewhere/libcrypto-3-x64.dll": file(peImage("3.5.7")),
	})
	if got := boundBy(b); len(got) != 0 {
		t.Errorf("linked across directories: %v", got)
	}
	if o, _ := peObs(b, "libssl-3-x64.dll"); o.Subject.Attrs["imports"] != "libcrypto-3-x64.dll" {
		t.Errorf("the imported name should still be reported: %q", o.Subject.Attrs["imports"])
	}
}

func TestOnlyUnrelatedImportsLeaveNoTraceOfThem(t *testing.T) {
	b := collect(t, fstest.MapFS{"Program Files/App/libssl-3-x64.dll": file(peImage("3.5.7", "kernel32.dll", "user32.dll"))})
	o, _ := peObs(b, "libssl-3-x64.dll")
	if _, has := o.Subject.Attrs["imports"]; has {
		t.Errorf("unrelated imports were recorded: %q", o.Subject.Attrs["imports"])
	}
	if len(byMethod(b, evidence.MethodPEImports)) != 0 {
		t.Error("an import observation without a resolved link")
	}
}

func TestAFileNeverLinksToItself(t *testing.T) {
	b := collect(t, fstest.MapFS{"Program Files/App/libcrypto-3-x64.dll": file(peImage("3.5.7", "libcrypto-3-x64.dll"))})
	if got := boundBy(b); len(got) != 0 {
		t.Errorf("self link: %v", got)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
