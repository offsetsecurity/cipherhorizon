package pefiles

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
	"github.com/offsetsecurity/cipherhorizon/internal/sense/pefiles/pefilestest"
)

var openssl357 = pefilestest.Build(pefilestest.Opts{}, 3<<16|5, 7<<16, "3.5.7", "The OpenSSL Toolkit")

// spyFS records every file opened and every directory read, so a test can assert
// what the sensor touched (and, more importantly, did not).
type spyFS struct {
	fs.FS
	mu      sync.Mutex
	opened  []string
	denyDir map[string]bool
}

func (s *spyFS) Open(name string) (fs.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.denyDir[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	f, err := s.FS.Open(name)
	if err == nil {
		if fi, serr := f.Stat(); serr == nil && !fi.IsDir() {
			s.opened = append(s.opened, name)
		}
	}
	return f, err
}

func (s *spyFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if s.denyDir[name] {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrPermission}
	}
	return fs.ReadDir(s.FS, name)
}

func file(data []byte) *fstest.MapFile { return &fstest.MapFile{Data: data} }

func collect(t *testing.T, fsys fs.FS) evidence.Batch {
	t.Helper()
	b, err := New(sense.Env{FS: fsys, OS: "windows", Tier: "user"}).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range b.Observations {
		if err := evidence.Validate(o); err != nil {
			t.Errorf("invalid observation: %v", err)
		}
	}
	return b
}

func byMethod(b evidence.Batch, method string) []evidence.Observation {
	var out []evidence.Observation
	for _, o := range b.Observations {
		if o.Method == method {
			out = append(out, o)
		}
	}
	return out
}

func TestFindsABundledOpenSSLAndReadsItsVersion(t *testing.T) {
	b := collect(t, fstest.MapFS{"Program Files/Git/mingw64/bin/libcrypto-3-x64.dll": file(openssl357)})

	names, pes := byMethod(b, evidence.MethodFSWalkName), byMethod(b, evidence.MethodPEVersion)
	if len(names) != 1 || len(pes) != 1 {
		t.Fatalf("observations: %d by name, %d by PE; want 1 and 1", len(names), len(pes))
	}
	if names[0].Subject.Key != pes[0].Subject.Key {
		t.Error("the two observations must be about the same subject, so the graph merges them")
	}
	a := pes[0].Subject.Attrs
	if a["family"] != "openssl" || a["fileVersion"] != "3.5.7.0" || a["productName"] != "The OpenSSL Toolkit" || a["arch"] != "amd64" || a["peValid"] != "true" {
		t.Errorf("PE attrs = %v", a)
	}
	if q, _ := evidence.QualityOf(names[0]); q != evidence.QualityHeuristic {
		t.Errorf("name observation quality = %s", q)
	}
	if q, _ := evidence.QualityOf(pes[0]); q != evidence.QualityParsed {
		t.Errorf("PE observation quality = %s", q)
	}
	if names[0].Claim.Rung != evidence.RungPresent || len(names[0].Relations) != 0 {
		t.Errorf("the sensor may only claim presence: %+v", names[0])
	}
	if a["path"] != "Program Files/Git/mingw64/bin/libcrypto-3-x64.dll" {
		t.Errorf("path = %q", a["path"])
	}
}

// The decoy control: a file with the right name that is not a PE image is listed
// as present by name only, flagged invalid, and gets no parsed observation.
func TestDecoyIsPresentByNameOnly(t *testing.T) {
	b := collect(t, fstest.MapFS{"Program Files/Evil/libcrypto-3-x64.dll": file([]byte("this is not a PE image"))})
	if len(byMethod(b, evidence.MethodPEVersion)) != 0 {
		t.Error("a non-PE file got a parsed observation")
	}
	names := byMethod(b, evidence.MethodFSWalkName)
	if len(names) != 1 || names[0].Subject.Attrs["peValid"] != "false" {
		t.Errorf("decoy = %+v", names)
	}
}

// SR-1: only files whose names match a recognised library are ever opened.
// Anything that looks like a key, certificate or secret is never read.
func TestNeverOpensAnythingButRecognisedLibraries(t *testing.T) {
	m := fstest.MapFS{
		"Program Files/App/libcrypto-3-x64.dll":            file(openssl357),
		"Program Files/App/private.key":                    file([]byte("-----BEGIN PRIVATE KEY-----")),
		"Program Files/App/id_rsa":                         file([]byte("-----BEGIN OPENSSH PRIVATE KEY-----")),
		"Program Files/App/libcrypto.key":                  file([]byte("secret")),
		"Program Files/App/server.pfx":                     file([]byte("pkcs12")),
		"Program Files/App/passwords.txt":                  file([]byte("hunter2")),
		"Program Files/App/libssl-3-x64.dll.bak":           file([]byte("backup")),
		"ProgramData/cert/token.json":                      file([]byte(`{"token":"x"}`)),
		"Users/alice/AppData/Local/Programs/x/credentials": file([]byte("aws_secret")),
	}
	spy := &spyFS{FS: m}
	collect(t, spy)
	if len(spy.opened) != 1 || spy.opened[0] != "Program Files/App/libcrypto-3-x64.dll" {
		t.Errorf("opened %v; only the recognised library may be opened", spy.opened)
	}
}

func TestUserNamesAreRedacted(t *testing.T) {
	b := collect(t, fstest.MapFS{"Users/alice/AppData/Local/Programs/Tool/nss3.dll": file(pefilestest.Build(pefilestest.Opts{}, 3<<16|100, 0, "3.100", "NSS"))})
	if len(b.Observations) == 0 {
		t.Fatal("nothing found under a per-user Programs directory")
	}
	for _, o := range b.Observations {
		blob := o.Subject.Key + o.Subject.Attrs["path"] + o.Source.Location
		if strings.Contains(strings.ToLower(blob), "alice") {
			t.Errorf("user name leaked: %q", blob)
		}
		if !strings.Contains(o.Subject.Attrs["path"], "%USER%") {
			t.Errorf("path not tokenised: %q", o.Subject.Attrs["path"])
		}
	}
}

func TestSymlinksAreNeverFollowed(t *testing.T) {
	m := fstest.MapFS{
		"Program Files/App/libcrypto-3-x64.dll": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("../../../secret")},
		"Program Files/Link":                    &fstest.MapFile{Mode: fs.ModeSymlink | fs.ModeDir},
	}
	spy := &spyFS{FS: m}
	b := collect(t, spy)
	if len(b.Observations) != 0 || len(spy.opened) != 0 {
		t.Errorf("a link was followed: %d observations, opened %v", len(b.Observations), spy.opened)
	}
}

func TestDepthIsBounded(t *testing.T) {
	deep := "Program Files"
	for i := 0; i < maxDepth+2; i++ {
		deep += "/d"
	}
	b := collect(t, fstest.MapFS{deep + "/libcrypto-3-x64.dll": file(openssl357)})
	if len(b.Observations) != 0 {
		t.Error("a file below the depth limit was reported")
	}
}

func TestPermissionDeniedIsCountedNotHidden(t *testing.T) {
	m := fstest.MapFS{
		"Users/bob/AppData/Local/Programs/a/libsodium.dll":   file(pefilestest.Build(pefilestest.Opts{}, 1<<16, 0, "1.0", "sodium")),
		"Users/carol/AppData/Local/Programs/a/libsodium.dll": file(pefilestest.Build(pefilestest.Opts{}, 1<<16, 0, "1.0", "sodium")),
		"Program Files/App/libcrypto-3-x64.dll":              file(openssl357),
	}
	spy := &spyFS{FS: m, denyDir: map[string]bool{"Users/carol/AppData/Local/Programs": true}}
	b := collect(t, spy)

	if len(byMethod(b, evidence.MethodFSWalkName)) != 2 {
		t.Errorf("readable locations must still be reported: %d name observations", len(byMethod(b, evidence.MethodFSWalkName)))
	}
	if len(b.Coverage) != 1 {
		t.Fatalf("coverage = %+v", b.Coverage)
	}
	c := b.Coverage[0]
	if c.Denied != 1 || c.Status != evidence.CoveragePartial || c.Reason != evidence.UnknownPermission {
		t.Errorf("coverage = %+v; want 1 denied, partial, permission", c)
	}
}

func TestBudgetHitIsReportedNotSilent(t *testing.T) {
	old := maxEntries
	maxEntries = 5
	defer func() { maxEntries = old }()

	m := fstest.MapFS{}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		m["Program Files/"+n+"/nss3.dll"] = file([]byte("x"))
	}
	b := collect(t, m)
	c := b.Coverage[0]
	if c.Status != evidence.CoveragePartial || c.Reason != evidence.UnknownBudget {
		t.Errorf("coverage = %+v; a budget hit must be partial with reason budget", c)
	}
}

func TestOversizedFilesAreListedButNeverOpened(t *testing.T) {
	spy := &spyFS{FS: fstest.MapFS{"Program Files/App/nss3.dll": file([]byte("small"))}}
	b := collect(t, &bigDirs{spy})
	if len(spy.opened) != 0 {
		t.Errorf("an oversized file was opened: %v", spy.opened)
	}
	if len(b.Observations) != 1 || b.Observations[0].Subject.Attrs["peValid"] != "false" {
		t.Errorf("observations = %+v", b.Observations)
	}
}

// bigDirs reports every regular file as huge, through the directory entries.
type bigDirs struct{ *spyFS }

func (b *bigDirs) ReadDir(name string) ([]fs.DirEntry, error) {
	ents, err := b.spyFS.ReadDir(name)
	for i, e := range ents {
		if !e.IsDir() {
			ents[i] = bigEntry{e}
		}
	}
	return ents, err
}

type bigEntry struct{ fs.DirEntry }

func (b bigEntry) Info() (fs.FileInfo, error) {
	fi, err := b.DirEntry.Info()
	if err != nil {
		return nil, err
	}
	return sizedInfo{fi, maxFileSize + 1}, nil
}

type sizedInfo struct {
	fs.FileInfo
	size int64
}

func (s sizedInfo) Size() int64 { return s.size }

func TestDetect(t *testing.T) {
	ctx := context.Background()
	if ok, err := New(sense.Env{FS: fstest.MapFS{"Program Files/x": file(nil)}}).Detect(ctx); !ok || err != nil {
		t.Errorf("Detect on a Windows-like host = %v, %v", ok, err)
	}
	if ok, err := New(sense.Env{FS: fstest.MapFS{"usr/lib/x": file(nil)}}).Detect(ctx); ok || err != nil {
		t.Errorf("Detect on a Linux host = %v, %v; want false, nil", ok, err)
	}
}

func TestDeterministic(t *testing.T) {
	m := fstest.MapFS{
		"Program Files/A/libcrypto-3-x64.dll": file(openssl357),
		"Program Files/B/nss3.dll":            file(pefilestest.Build(pefilestest.Opts{}, 3<<16|100, 0, "3.100", "NSS")),
		"ProgramData/C/libsodium.dll":         file(pefilestest.Build(pefilestest.Opts{}, 1<<16, 0, "1.0", "sodium")),
	}
	ids := func() string {
		var s []string
		for _, o := range collect(t, m).Observations {
			s = append(s, o.ID)
		}
		return strings.Join(s, ",")
	}
	if a, b := ids(), ids(); a != b || a == "" {
		t.Errorf("runs differ or empty:\n%s\n%s", a, b)
	}
}

func TestCoverageStatesWhatIsNotSeen(t *testing.T) {
	c := collect(t, fstest.MapFS{"Program Files/x/y": file(nil)}).Coverage[0]
	joined := strings.Join(c.Unseen, " | ")
	for _, want := range []string{"statically linked", "renamed", "signatures are not verified", "certificates", "actually does"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unseen list does not mention %q", want)
		}
	}
	if c.Status != evidence.CoverageComplete {
		t.Errorf("status = %s", c.Status)
	}
}

func TestCancellationReturnsPartialWithAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b, err := New(sense.Env{FS: fstest.MapFS{"Program Files/A/nss3.dll": file(nil)}}).Collect(ctx)
	if !errors.Is(err, context.Canceled) || b.Coverage[0].Status != evidence.CoveragePartial {
		t.Errorf("err = %v, coverage = %+v", err, b.Coverage)
	}
}

func TestRegisteredAndValid(t *testing.T) {
	s, err := sense.Default.New(Name, sense.Env{FS: fstest.MapFS{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Info().Validate(); err != nil {
		t.Error(err)
	}
	if _, err := sense.Default.New(Name, sense.Env{}); err == nil {
		t.Error("nil host FS accepted")
	}
}

// A hostile name (control characters, invalid UTF-8) must be skipped and reported, and
// must not stop the rest of the inventory: a single crafted directory must not be able
// to abort a run.
func TestHostileNamesAreSkippedAndReportedNotFatal(t *testing.T) {
	m := fstest.MapFS{
		"Program Files/good/libcrypto-3-x64.dll":        file(openssl357),
		"Program Files/evil\nname/libcrypto-3-x64.dll":  file(openssl357),
		"Program Files/bad\xffutf8/libcrypto-3-x64.dll": file(openssl357),
		"Program Files/esc\x1b[31m/libcrypto-3-x64.dll": file(openssl357),
	}
	b := collect(t, m) // collect also validates every observation: none may be invalid
	if n := len(byMethod(b, evidence.MethodFSWalkName)); n != 1 {
		t.Errorf("%d observations, want only the safely named one", n)
	}
	c := b.Coverage[0]
	// (fstest.MapFS may not list a directory whose name is invalid UTF-8, so two or three are seen.)
	if n := c.Limits["skippedUnsafeNames"]; c.Status != evidence.CoveragePartial || c.Reason != evidence.UnknownUnsupported || (n != "2" && n != "3") {
		t.Errorf("coverage = %+v; the skipped names must be reported", c)
	}
}
