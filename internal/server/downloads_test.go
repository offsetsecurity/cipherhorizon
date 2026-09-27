package server_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/example/cipherhorizon/internal/server"
)

type binariesReply struct {
	Binaries []struct {
		OS       string `json:"os"`
		Arch     string `json:"arch"`
		Filename string `json:"filename"`
		Size     int64  `json:"sizeBytes"`
		SHA256   string `json:"sha256"`
		Primary  bool   `json:"primary"`
	} `json:"binaries"`
}

func withExecDir(t *testing.T, dir string) {
	t.Helper()
	restore := server.SetExecPathForTest(func() (string, error) { return filepath.Join(dir, "cipherhorizon"), nil })
	t.Cleanup(restore)
}

func writeFixtureBinary(t *testing.T, path string, content []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Nothing on disk: the list is empty, never an error, and a download is a plain 404.
func TestNoCollectorBinaryIsAnEmptyListNotAnError(t *testing.T) {
	e := newEnv(t)
	withExecDir(t, t.TempDir())
	var out binariesReply
	if s := e.call("GET", "/api/v1/collector/binaries", nil, &out); s != 200 {
		t.Fatalf("%d", s)
	}
	if len(out.Binaries) != 0 {
		t.Errorf("binaries = %+v", out.Binaries)
	}
	if s, _ := e.do("GET", "/api/v1/collector/binaries/cipherhorizon-collector", nil); s != 404 {
		t.Errorf("download with nothing present: %d", s)
	}
}

// The same-platform companion beside the server binary is found, described accurately, marked
// primary, and its exact bytes come back on download with the checksum the list gave.
func TestTheCompanionCollectorBinaryIsServed(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	withExecDir(t, dir)
	name := "cipherhorizon-collector"
	if runtime.GOOS == "windows" {
		name = "cipherhorizon-collector.exe"
	}
	content := []byte("not a real binary, just fixture bytes for the test\x00\x01\x02")
	wantSum := writeFixtureBinary(t, filepath.Join(dir, name), content)

	var out binariesReply
	if s := e.call("GET", "/api/v1/collector/binaries", nil, &out); s != 200 {
		t.Fatalf("%d", s)
	}
	if len(out.Binaries) != 1 {
		t.Fatalf("binaries = %+v", out.Binaries)
	}
	b := out.Binaries[0]
	if b.OS != runtime.GOOS || b.Arch != runtime.GOARCH || b.Filename != name || b.Size != int64(len(content)) || b.SHA256 != wantSum || !b.Primary {
		t.Errorf("binary = %+v, want os=%s arch=%s size=%d sha256=%s primary=true", b, runtime.GOOS, runtime.GOARCH, len(content), wantSum)
	}

	s, body := e.do("GET", "/api/v1/collector/binaries/"+name, nil)
	if s != 200 || string(body) != string(content) {
		t.Errorf("download: %d %q", s, body)
	}
}

// A collectors/ subdirectory of per-platform binaries is listed too, the one matching this server's
// own platform is marked primary and sorted first, and a name that does not match any discovered
// file (including a path-traversal attempt) is refused rather than read from disk.
func TestPerPlatformCollectorsAreListedAndDownloadNamesAreExact(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	withExecDir(t, dir)
	linux := writeFixtureBinary(t, filepath.Join(dir, "collectors", "cipherhorizon-collector_linux_amd64"), []byte("linux build"))
	mine := "cipherhorizon-collector_" + runtime.GOOS + "_" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		mine += ".exe"
	}
	mineSum := writeFixtureBinary(t, filepath.Join(dir, "collectors", mine), []byte("this platform's build"))
	// Not a recognised name: ignored, not served.
	writeFixtureBinary(t, filepath.Join(dir, "collectors", "readme.txt"), []byte("not a binary"))

	var out binariesReply
	e.call("GET", "/api/v1/collector/binaries", nil, &out)
	if len(out.Binaries) != 2 {
		t.Fatalf("binaries = %+v", out.Binaries)
	}
	if !out.Binaries[0].Primary || out.Binaries[0].SHA256 != mineSum {
		t.Errorf("this platform's build is not listed first and primary: %+v", out.Binaries)
	}
	_ = linux

	if s, _ := e.do("GET", "/api/v1/collector/binaries/readme.txt", nil); s != 404 {
		t.Errorf("an unlisted file was served: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/collector/binaries/..%2f..%2fetc%2fpasswd", nil); s != 404 {
		t.Errorf("a path-traversal name was not refused: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/collector/binaries/"+mine, nil); s != 200 {
		t.Errorf("this platform's own file: %d", s)
	}
}

func TestCollectorBinaryRoutesRequireTheToken(t *testing.T) {
	e := newEnv(t, withToken("s3cret-token-0123456789"))
	e.token = ""
	for _, p := range []string{"/api/v1/collector/binaries", "/api/v1/collector/binaries/x"} {
		if s, _, _ := e.req("GET", p, nil, nil); s != 401 {
			t.Errorf("%s without a token: %d", p, s)
		}
	}
}
