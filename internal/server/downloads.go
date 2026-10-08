package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Serving the collector binary from the running server (raised directly by a person running the
// product: nothing else offers it to a browser). The server never builds, downloads or embeds one:
// distribution.md still ships the collector as its own release archive. What this does is let an
// operator who has put a copy on disk hand it out to a fleet from the one page everyone already has
// open — the "offline bundle" pattern the product already uses for registries and rule packs (ADR-0007),
// applied to its own companion binary. Nothing here executes a file; each one is read and streamed as
// bytes, exactly like the CBOM downloads already on this server.
//
// Two places are read, both beside the server's own executable, so the common case — both release
// archives unpacked into one directory — needs no configuration:
//
//   - a same-platform companion file, named "cipherhorizon-collector[.exe]";
//   - a "collectors" subdirectory holding one file per platform, named
//     "cipherhorizon-collector_<goos>_<goarch>[.exe]" (goreleaser's own naming), for an operator who
//     wants to hand the collector to a fleet of more than one platform from a single server.
//
// Neither is required: with nothing on disk, the API says so and the UI falls back to the existing
// build-from-source instructions.

// execPath is os.Executable, a seam so tests can point discovery at a fixture directory.
var execPath = os.Executable

// CollectorBinary is one collector binary this server found on disk and can serve.
type CollectorBinary struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Filename string `json:"filename"`
	Size     int64  `json:"sizeBytes"`
	SHA256   string `json:"sha256"`
	// Primary is true for the binary built for the platform this server itself runs on: the
	// obvious one to offer first, since it is very likely also the platform of the machine
	// being inventoried.
	Primary bool `json:"primary"`

	path string
}

// platformSuffix reads "_<goos>_<goarch>" (optionally ".exe") from a filename in collectors/.
var platformSuffix = regexp.MustCompile(`^cipherhorizon-collector_([a-z0-9]+)_([a-z0-9]+)(?:\.exe)?$`)

func companionName(goos string) string {
	if goos == "windows" {
		return "cipherhorizon-collector.exe"
	}
	return "cipherhorizon-collector"
}

// discoverCollectors lists every collector binary found, most useful first. A file that cannot be
// read (permissions, a directory of the same name) is silently skipped: this is informational, and a
// broken entry must never make the whole list fail.
func discoverCollectors() []CollectorBinary {
	exe, err := execPath()
	if err != nil {
		return nil
	}
	dir := filepath.Dir(exe)
	var out []CollectorBinary
	seen := map[string]bool{}

	add := func(path, goos, arch string) {
		if seen[path] {
			return
		}
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() || fi.Size() == 0 {
			return
		}
		sum, err := cachedSHA256(path, fi)
		if err != nil {
			return
		}
		seen[path] = true
		out = append(out, CollectorBinary{OS: goos, Arch: arch, Filename: filepath.Base(path), Size: fi.Size(), SHA256: sum,
			Primary: goos == runtime.GOOS && arch == runtime.GOARCH, path: path})
	}

	add(filepath.Join(dir, companionName(runtime.GOOS)), runtime.GOOS, runtime.GOARCH)

	collectorsDir := filepath.Join(dir, "collectors")
	entries, _ := os.ReadDir(collectorsDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := platformSuffix.FindStringSubmatch(strings.ToLower(e.Name()))
		if m == nil {
			continue
		}
		add(filepath.Join(collectorsDir, e.Name()), m[1], m[2])
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		if out[i].OS != out[j].OS {
			return out[i].OS < out[j].OS
		}
		return out[i].Arch < out[j].Arch
	})
	return out
}

// hashCache remembers each binary's SHA-256 by path, size and modification time, so listing or
// downloading does not re-read every binary (tens of MiB each) on every request.
var hashCache = struct {
	sync.Mutex
	m map[string]hashEntry
}{m: map[string]hashEntry{}}

type hashEntry struct {
	size int64
	mod  time.Time
	sum  string
}

func cachedSHA256(path string, fi os.FileInfo) (string, error) {
	hashCache.Lock()
	e, ok := hashCache.m[path]
	hashCache.Unlock()
	if ok && e.size == fi.Size() && e.mod.Equal(fi.ModTime()) {
		return e.sum, nil
	}
	sum, err := sha256File(path)
	if err != nil {
		return "", err
	}
	hashCache.Lock()
	hashCache.m[path] = hashEntry{size: fi.Size(), mod: fi.ModTime(), sum: sum}
	hashCache.Unlock()
	return sum, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path) // path is built from a fixed, non-user-controlled directory listing
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// listCollectorBinaries answers what this server has on disk to hand out.
func (s *Server) listCollectorBinaries(w http.ResponseWriter, _ *http.Request) {
	out := discoverCollectors()
	if out == nil {
		out = []CollectorBinary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"binaries": out})
}

// downloadCollectorBinary streams one binary by the exact filename the list gave. The name is matched
// against the current discovery, never turned into a path itself, so nothing about the request can
// name a file this server did not already choose to offer.
func (s *Server) downloadCollectorBinary(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, b := range discoverCollectors() {
		if b.Filename != name {
			continue
		}
		f, err := os.Open(b.path) // path came from discovery, not from the request
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		defer f.Close() //nolint:errcheck // read-only
		extendWriteDeadline(w, s.log, downloadWriteTimeout)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+b.Filename+`"`)
		http.ServeContent(w, r, b.Filename, time.Time{}, f)
		return
	}
	writeErr(w, http.StatusNotFound, "no such collector binary on this server")
}
