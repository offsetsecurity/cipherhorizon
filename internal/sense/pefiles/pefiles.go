// Package pefiles is the sensor for cryptographic libraries that live as loose
// files rather than in a package database, which is how most of them exist on
// Windows (an application bundles its own OpenSSL, NSS or GnuTLS).
//
// It walks a small, allow-listed set of install locations and opens only files
// whose *names* match a recognised crypto-library pattern. For each it reports a
// `present` observation by name (heuristic) and, when the file is a well-formed PE
// image, a second one from its version resource (parsed). It never opens keys,
// certificates or any other file, never loads or runs anything, and never verifies
// signatures (Authenticode's revocation checks can reach the network, which a
// collector must not do: ADR-0004).
//
// A name match alone never yields a capability (ADR-0002): a decoy file called
// libcrypto-3-x64.dll that is not a PE is listed as present and nothing more.
package pefiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/knowledge"
	"github.com/example/cipherhorizon/internal/sense"
)

const (
	// Name is the sensor's registry name.
	Name = "pe-files"
	// Version is the version of this sensor's behaviour.
	Version = "0.1.0"

	maxDepth    = 8         // directory depth below a root
	maxFileSize = 256 << 20 // larger files are listed by name and never opened

	maxHashFile    = 128 << 20 // a larger file is not hashed
	maxImportsKept = 32        // recognised crypto libraries kept from one file's import table
)

// maxHashTotal bounds the bytes hashed in one run, so a host full of very large
// matching files cannot make a run slow. A variable only so a test can lower it.
var maxHashTotal int64 = 2 << 30

// maxEntries bounds the directory entries examined in one run. A variable only so
// a test can lower it; nothing else changes it.
var maxEntries = 500_000

// roots are the locations searched, host-relative. A "*" component stands for
// every user profile; profiles a standard user cannot read are counted, not hidden.
var roots = []string{
	"Program Files",
	"Program Files (x86)",
	"ProgramData",
	"Users/*/AppData/Local/Programs",
}

func init() {
	sense.Register(Name, func(env sense.Env) (sense.Sensor, error) {
		if env.FS == nil {
			return nil, errors.New("pe-files: host filesystem is nil")
		}
		return New(env), nil
	})
}

// Sensor implements sense.Sensor.
type Sensor struct {
	fsys fs.FS
	tier string
}

var _ sense.Sensor = (*Sensor)(nil)

// New returns a sensor reading the host described by env.
func New(env sense.Env) *Sensor {
	tier := env.Tier
	if tier == "" {
		tier = hostinfo.TierUser
	}
	return &Sensor{fsys: env.FS, tier: tier}
}

// Info implements sense.Sensor.
func (*Sensor) Info() sense.Info {
	return sense.Info{Name: Name, Version: Version, Methods: []string{evidence.MethodFSWalkName, evidence.MethodPEVersion, evidence.MethodPEImports}}
}

// Detect reports whether any search location exists on the host.
func (s *Sensor) Detect(context.Context) (bool, error) {
	for _, r := range roots {
		if strings.Contains(r, "*") {
			continue
		}
		if fi, err := fs.Stat(s.fsys, r); err == nil && fi.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

var unseen = []string{
	"cryptography statically linked into applications or embedded in custom software",
	"libraries outside the searched locations (other drives, portable applications, per-user installs elsewhere)",
	"libraries whose file name is not a recognised crypto-library name (renamed or unrecognised)",
	"whether a file is genuine: version strings are what the file claims, a SHA-256 identifies the exact file but not who made it, and signatures are not verified",
	"registry-installed products, certificates, configuration and key material (not collected by this version)",
	"what any library actually does: a file being present says nothing about use",
}

type walk struct {
	s       *Sensor
	ctx     context.Context
	batch   evidence.Batch
	entries int
	opened  int
	matched int
	denied  int
	errs    int
	unsafe  int // matched files skipped because their path is not safe text
	budget  bool

	hashedFiles int
	hashedBytes int64

	found   map[string]string // "dir/lower-name" -> artefact key, every matched file
	pending []pendingImports  // files whose import table names recognised crypto libraries
}

// pendingImports is one file's recognised static imports, resolved after the walk
// against the files the walk found.
type pendingImports struct {
	key, name, path, family, kind string
	imports                       []string
}

// Collect walks the search locations and returns the observations.
func (s *Sensor) Collect(ctx context.Context) (evidence.Batch, error) {
	w := &walk{s: s, ctx: ctx, found: map[string]string{}}
	for _, root := range expandRoots(s.fsys) {
		if w.stop() {
			break
		}
		w.dir(root, 0)
	}

	w.resolveImports()

	cov := evidence.Coverage{
		Sensor: Name, Method: evidence.MethodFSWalkName,
		Scope:  "crypto-library files under Program Files, Program Files (x86), ProgramData and per-user Programs",
		Status: evidence.CoverageComplete, Unseen: unseen, Denied: w.denied,
		Limits: map[string]string{
			"maxDepth": strconv.Itoa(maxDepth), "maxEntries": strconv.Itoa(maxEntries),
			"entriesExamined": strconv.Itoa(w.entries), "filesMatched": strconv.Itoa(w.matched), "filesOpened": strconv.Itoa(w.opened),
			"filesHashed": strconv.Itoa(w.hashedFiles), "bytesHashed": strconv.FormatInt(w.hashedBytes, 10),
		},
	}
	switch {
	case w.budget:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownBudget
	case w.denied > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownPermission
	case w.unsafe > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownUnsupported
	}
	if w.unsafe > 0 {
		cov.Limits["skippedUnsafeNames"] = strconv.Itoa(w.unsafe)
	}
	if w.errs > 0 {
		cov.Limits["unreadable"] = strconv.Itoa(w.errs)
	}
	w.batch.Coverage = []evidence.Coverage{cov}

	if err := ctx.Err(); err != nil {
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownBudget
		w.batch.Coverage = []evidence.Coverage{cov}
		return w.batch, fmt.Errorf("pe-files: %w", err)
	}
	return w.batch, nil
}

// expandRoots resolves the per-user wildcard against the host. Listing Users
// needs no privilege; individual profiles a standard user cannot enter are
// counted when they are read.
func expandRoots(fsys fs.FS) []string {
	var out []string
	for _, r := range roots {
		if !strings.Contains(r, "*") {
			if fi, err := fs.Stat(fsys, r); err == nil && fi.IsDir() {
				out = append(out, r)
			}
			continue
		}
		head, tail, _ := strings.Cut(r, "/*/")
		ents, err := fs.ReadDir(fsys, head)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				out = append(out, path.Join(head, e.Name(), tail))
			}
		}
	}
	return out
}

func (w *walk) stop() bool {
	if w.budget {
		return true
	}
	return w.ctx.Err() != nil
}

// dir reads one directory. Entries come back sorted, so output is deterministic.
// Symlinks and other irregular entries (junctions) are never followed.
func (w *walk) dir(p string, depth int) {
	if w.stop() {
		return
	}
	ents, err := fs.ReadDir(w.s.fsys, p)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrPermission):
			w.denied++
		case errors.Is(err, fs.ErrNotExist):
			// a per-user root that does not exist: nothing to report
		default:
			w.errs++
		}
		return
	}
	for _, e := range ents {
		if w.stop() {
			return
		}
		w.entries++
		if w.entries > maxEntries {
			w.budget = true
			return
		}
		full := path.Join(p, e.Name())
		typ := e.Type()
		switch {
		case typ&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			// never follow links or junctions out of the searched locations
		case e.IsDir():
			if depth+1 <= maxDepth {
				w.dir(full, depth+1)
			}
		case typ.IsRegular():
			w.file(full, e)
		}
	}
}

// file handles one regular file. It is opened only if its name matches a
// recognised crypto-library pattern: nothing else on the host is ever read.
func (w *walk) file(full string, e fs.DirEntry) {
	name := e.Name()
	fam := knowledge.RecognizeFile(strings.ToLower(name))
	if fam == nil {
		return
	}
	// A path is attacker-controlled data. One with control characters or invalid
	// UTF-8 is skipped and counted, never passed on: it would fail validation and a
	// single hostile name must not be able to abort the whole inventory.
	if !evidence.SafeText(full, 1024) {
		w.unsafe++
		return
	}
	w.matched++

	redacted := evidence.RedactPath(full)
	key := evidence.ArtefactKey(redacted)
	kind := fam.KindForFile(strings.ToLower(name))

	attrs := map[string]string{"path": redacted, "family": fam.ID, "kind": kind}
	var info peInfo
	var peOK bool
	// The size comes from the directory entry: no extra open of the file.
	if fi, err := e.Info(); err == nil {
		attrs["size"] = strconv.FormatInt(fi.Size(), 10)
		if fi.Size() <= maxFileSize {
			info, peOK = w.readPE(full, fi.Size())
		}
	}
	if !peOK {
		attrs["peValid"] = "false"
	}
	w.found[path.Dir(redacted)+"/"+strings.ToLower(name)] = key
	w.batch.Observations = append(w.batch.Observations, w.observe(evidence.MethodFSWalkName, key, name, attrs, redacted))

	if peOK {
		pa := map[string]string{"path": redacted, "family": fam.ID, "kind": kind, "peValid": "true"}
		if info.Version.File != "" {
			pa["fileVersion"] = info.Version.File
		}
		if info.Version.Product != "" {
			pa["productName"] = info.Version.Product
		}
		if info.Version.Arch != "" {
			pa["arch"] = info.Version.Arch
		}
		if info.SHA256 != "" {
			pa["sha256"] = info.SHA256
		}
		if len(info.Imports) > 0 {
			pa["imports"] = strings.Join(info.Imports, ",")
			w.pending = append(w.pending, pendingImports{key: key, name: name, path: redacted, family: fam.ID, kind: kind, imports: info.Imports})
		}
		w.batch.Observations = append(w.batch.Observations, w.observe(evidence.MethodPEVersion, key, name, pa, redacted))
	}
}

// resolveImports links a file to the recognised crypto libraries its static import
// table names, when the walk found that library in the SAME directory. The import
// table is parsed evidence of a name; choosing the file that name refers to is not
// (Windows searches the application directory first, then others, and this sensor
// does not evaluate that order), so a library found elsewhere is not linked. The
// claim is `bound`, "could use", never "uses".
func (w *walk) resolveImports() {
	sort.Slice(w.pending, func(i, j int) bool { return w.pending[i].key < w.pending[j].key })
	for _, p := range w.pending {
		dir := path.Dir(p.path)
		var rels []evidence.Relation
		for _, n := range p.imports {
			if to, ok := w.found[dir+"/"+n]; ok && to != p.key {
				rels = append(rels, evidence.Relation{Kind: "imports", To: to, Claim: evidence.Claim{Rung: evidence.RungBound, Binding: evidence.BindStaticImport}})
			}
		}
		if len(rels) == 0 {
			continue
		}
		o := evidence.Observation{
			Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
			Subject:   evidence.Subject{Kind: evidence.KindArtefact, Key: p.key, Name: p.name, Attrs: map[string]string{"path": p.path, "family": p.family, "kind": p.kind}},
			Claim:     evidence.Claim{Rung: evidence.RungBound, Binding: evidence.BindStaticImport},
			Outcome:   evidence.OutcomeObserved,
			Relations: rels,
			Method:    evidence.MethodPEImports, Source: evidence.Source{Kind: "file", Location: p.path},
			Privilege: w.s.tier,
		}
		evidence.Finish(&o)
		w.batch.Observations = append(w.batch.Observations, o)
	}
}

// peInfo is what one open of a matching file yields.
type peInfo struct {
	Version VersionInfo
	// Imports are the recognised crypto libraries in the static import table (names
	// only, sorted); every other import is discarded, not recorded.
	Imports []string
	// SHA256 is the digest of the whole file, or "" when it was not hashed.
	SHA256 string
}

// readPE opens the file once and reads its version resource, its import table and
// its SHA-256. A file that is not a PE image (or cannot be read) is simply not
// corroborated.
func (w *walk) readPE(full string, size int64) (peInfo, bool) {
	f, err := w.s.fsys.Open(full)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			w.denied++
		} else {
			w.errs++
		}
		return peInfo{}, false
	}
	defer f.Close() //nolint:errcheck // read-only
	w.opened++

	ra, ok := f.(io.ReaderAt)
	if !ok {
		// Not seekable (an unusual fs.FS): read at most the bounded amount into memory.
		b, err := io.ReadAll(io.LimitReader(f, maxFileSize))
		if err != nil {
			w.errs++
			return peInfo{}, false
		}
		ra, size = bytesAt(b), int64(len(b))
	}
	v, err := ReadVersion(ra, size)
	if err != nil {
		return peInfo{}, false
	}
	info := peInfo{Version: v}
	if names, err := ReadImports(ra, size); err == nil {
		info.Imports = recognisedImports(names)
	}
	info.SHA256 = w.hash(ra, size)
	return info, true
}

// recognisedImports keeps only the imported libraries that are themselves
// recognised crypto libraries. A file's other imports say nothing about
// cryptography and are not collected.
func recognisedImports(names []string) []string {
	var out []string
	for _, n := range names {
		if knowledge.RecognizeFile(n) != nil {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	if len(out) > maxImportsKept {
		out = out[:maxImportsKept]
	}
	return out
}

// hash returns the SHA-256 of the file, or "" when the file or the run's hashing
// budget is too large. It reads only files already opened because their name
// matched a recognised crypto library; it is never applied to a key or a secret.
func (w *walk) hash(ra io.ReaderAt, size int64) string {
	if size > maxHashFile || w.hashedBytes+size > maxHashTotal {
		return ""
	}
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(ra, 0, size))
	if err != nil || n != size {
		return ""
	}
	w.hashedFiles++
	w.hashedBytes += n
	return hex.EncodeToString(h.Sum(nil))
}

func (w *walk) observe(method, key, name string, attrs map[string]string, location string) evidence.Observation {
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindArtefact, Key: key, Name: name, Attrs: attrs},
		Claim:   evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
		Method: method, Source: evidence.Source{Kind: "file", Location: location},
		Privilege: w.s.tier,
	}
	evidence.Finish(&o)
	return o
}

type bytesAt []byte

// ReadAt implements io.ReaderAt over the in-memory bytes.
func (b bytesAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
