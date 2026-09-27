// Package certfiles is the sensor for X.509 certificates that a Linux host keeps as
// files: the system trust store, CA anchors, and the certificates of the services that
// run on it. It describes certificates, never keys.
//
// What it will not do (ADR-0005, PRD-003 REQ-CERT-4, SECARCH-001 SR-06, SR-16):
//
//   - It never opens a file whose name says it holds a key or a key store (*.key, *.p12,
//     *.pfx, *.jks, "privkey", "private", ...), and never enters a directory called
//     private. Those are counted, not read.
//   - In a file it does open, it decodes CERTIFICATE blocks only. A block whose label
//     names a private key is skipped without being decoded, copied or kept, and only
//     noted ("a private key is stored alongside this certificate"). See scanPEM.
//   - It follows a symbolic link only when the link stays inside the searched host root,
//     names a regular file, and is followed once (no chains); every directory on the
//     way must be a real directory. A link that fails any of these is refused and counted.
//   - It reads only within the allow-listed directories below, with bounds on depth,
//     entries, file size, certificates per file and certificates per run.
//
// Each certificate becomes one host-stream observation at the `provisioned` rung (the
// host holds this certificate), keyed by its SHA-256 fingerprint so it is the same entity
// as the certificate a TLS scan sees on the wire.
package certfiles

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/example/cipherhorizon/internal/certinfo"
	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/sense"
)

const (
	// Name is the sensor's registry name.
	Name = "cert-files"
	// Version is the version of this sensor's behaviour.
	Version = "0.1.0"

	maxDepth       = 6
	maxFileSize    = 4 << 20 // a larger file is counted and never opened
	maxDERFileSize = maxCertDER
	maxCertsPerRun = 20_000
	maxNameLen     = 512
	maxLocationLen = 1024
	maxAttrLen     = 1024
)

// maxEntries bounds the directory entries examined in one run. A variable only so a
// test can lower it.
var maxEntries = 200_000

// roots are the locations searched, host-relative. Trust stores first, then the places
// services keep their certificates. Key directories are never entered (see skipDir).
var roots = []string{
	"etc/ssl/certs",
	"etc/pki/ca-trust/source/anchors",
	"etc/pki/ca-trust/extracted/pem",
	"etc/pki/tls/certs",
	"usr/local/share/ca-certificates",
	"usr/share/ca-certificates",
	"etc/letsencrypt/live",
	"etc/nginx",
	"etc/apache2",
	"etc/httpd",
	"etc/haproxy",
	"etc/postfix",
	"etc/dovecot",
}

// skipDir names directories that exist to hold keys. They are never entered.
var skipDir = map[string]bool{"private": true, "private_keys": true, "keys": true, "keystore": true, "secrets": true, ".git": true}

// keyName matches file names that announce a key or a key store: they are never opened.
// The words must stand alone between separators, so "monkey.crt" is not caught and
// "server-key.pem" and "privkey.pem" are.
var keyName = regexp.MustCompile(`(?i)(^|[-_.])(priv|privkey|private|key|keys|secret|pkcs12|p12|pfx|jks|keystore)([-_.]|$)`)

// keyExt are extensions of key material and key stores.
var keyExt = map[string]bool{".key": true, ".p12": true, ".pfx": true, ".jks": true, ".keystore": true, ".p8": true, ".kdb": true, ".pk8": true}

// certExt are the extensions of files that may hold certificates.
var certExt = map[string]bool{".crt": true, ".cer": true, ".pem": true, ".der": true}

// hashedLink matches the OpenSSL subject-hash names ("5ad8a5d6.0") a trust-store
// directory is indexed by. They are almost always links to a certificate elsewhere.
var hashedLink = regexp.MustCompile(`^[0-9a-f]{8}\.[0-9]+$`)

func init() {
	sense.Register(Name, func(env sense.Env) (sense.Sensor, error) {
		if env.FS == nil {
			return nil, errors.New("cert-files: host filesystem is nil")
		}
		return New(env), nil
	})
}

// Sensor implements sense.Sensor.
type Sensor struct {
	fsys fs.FS
	os   string
	tier string
}

var _ sense.Sensor = (*Sensor)(nil)

// New returns a sensor reading the host described by env.
func New(env sense.Env) *Sensor {
	tier := env.Tier
	if tier == "" {
		tier = hostinfo.TierUser
	}
	return &Sensor{fsys: env.FS, os: env.OS, tier: tier}
}

// Info implements sense.Sensor.
func (*Sensor) Info() sense.Info {
	return sense.Info{Name: Name, Version: Version, Methods: []string{evidence.MethodCertFile}}
}

// Detect reports whether this is a Linux host with any of the searched directories.
func (s *Sensor) Detect(context.Context) (bool, error) {
	if s.os != "linux" {
		return false, nil
	}
	for _, r := range roots {
		if fi, err := fs.Stat(s.fsys, r); err == nil && fi.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

var unseen = []string{
	"certificates kept in application stores: Java keystores, NSS databases, browser and language runtime stores",
	"certificates embedded in software, in databases or in configuration values",
	"certificates in directories outside the searched trust-store and service locations",
	"private keys: never read; a key file is counted by its name and a key block inside a certificate file only noted",
	"whether the system trusts a certificate: trust configuration is not evaluated",
	"whether a certificate is in use: a certificate on disk says nothing about which service presents it",
}

type walk struct {
	s     *Sensor
	ctx   context.Context
	batch evidence.Batch

	entries   int
	candidate int
	opened    int
	certs     int
	seen      map[string]bool // fingerprint + location: one observation each

	keyFilesSkipped int
	keyBlocks       int
	otherBlocks     int
	unparseable     int
	malformed       int
	oversized       int
	linksFollowed   int
	linksRefused    int
	unsafe          int
	denied          int
	errs            int
	truncated       bool
	budget          bool
}

// Collect walks the searched locations and returns the observations.
func (s *Sensor) Collect(ctx context.Context) (evidence.Batch, error) {
	w := &walk{s: s, ctx: ctx, seen: map[string]bool{}}
	for _, r := range roots {
		if w.stop() {
			break
		}
		if fi, err := fs.Stat(s.fsys, r); err != nil || !fi.IsDir() {
			continue
		}
		w.dir(r, 0)
	}

	cov := evidence.Coverage{
		Sensor: Name, Method: evidence.MethodCertFile,
		Scope:  "certificate files in the system trust store and service directories under etc and usr",
		Status: evidence.CoverageComplete, Unseen: unseen, Denied: w.denied,
		Limits: map[string]string{
			"maxDepth": strconv.Itoa(maxDepth), "maxEntries": strconv.Itoa(maxEntries),
			"entriesExamined": strconv.Itoa(w.entries), "filesOpened": strconv.Itoa(w.opened), "certificates": strconv.Itoa(w.certs),
			"keyFilesNotOpened": strconv.Itoa(w.keyFilesSkipped), "keyBlocksSkipped": strconv.Itoa(w.keyBlocks),
			"linksFollowed": strconv.Itoa(w.linksFollowed), "linksRefused": strconv.Itoa(w.linksRefused),
		},
	}
	if w.unparseable > 0 {
		cov.Limits["unparseableCertificates"] = strconv.Itoa(w.unparseable)
	}
	if w.malformed > 0 {
		cov.Limits["malformedBlocks"] = strconv.Itoa(w.malformed)
	}
	if w.oversized > 0 {
		cov.Limits["oversizedFilesNotOpened"] = strconv.Itoa(w.oversized)
	}
	if w.unsafe > 0 {
		cov.Limits["skippedUnsafeNames"] = strconv.Itoa(w.unsafe)
	}
	if w.errs > 0 {
		cov.Limits["unreadable"] = strconv.Itoa(w.errs)
	}
	switch {
	case w.budget || w.truncated:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownBudget
	case w.denied > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownPermission
	case w.unsafe > 0 || w.oversized > 0 || w.unparseable > 0 || w.malformed > 0 || w.linksRefused > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownUnsupported
	}
	w.batch.Coverage = []evidence.Coverage{cov}
	if err := ctx.Err(); err != nil {
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownBudget
		w.batch.Coverage = []evidence.Coverage{cov}
		return w.batch, fmt.Errorf("cert-files: %w", err)
	}
	return w.batch, nil
}

func (w *walk) stop() bool { return w.budget || w.ctx.Err() != nil }

// dir reads one directory. Entries come back sorted, so output is deterministic.
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
		case typ&fs.ModeSymlink != 0:
			// A link to a directory is never entered; a link to a regular file is a candidate.
			w.candidateFile(full, e.Name(), true)
		case typ&fs.ModeIrregular != 0:
		case e.IsDir():
			if skipDir[strings.ToLower(e.Name())] {
				continue
			}
			if depth+1 <= maxDepth {
				w.dir(full, depth+1)
			}
		case typ.IsRegular():
			w.candidateFile(full, e.Name(), false)
		}
	}
}

// candidate reports whether a file name may hold certificates, and whether it announces a key.
func classify(name string) (maybeCert, isKey bool) {
	lower := strings.ToLower(name)
	ext := path.Ext(lower)
	if keyExt[ext] || keyName.MatchString(lower) {
		return false, true
	}
	if certExt[ext] || hashedLink.MatchString(lower) {
		return true, false
	}
	return false, false
}

func (w *walk) candidateFile(full, name string, isLink bool) {
	maybe, isKey := classify(name)
	if isKey {
		w.keyFilesSkipped++ // counted by name; never opened
		return
	}
	if !maybe {
		return
	}
	if !evidence.SafeText(full, maxLocationLen) {
		w.unsafe++
		return
	}
	w.candidate++
	target := full
	if isLink {
		t, ok := w.resolve(full)
		if !ok {
			w.linksRefused++
			return
		}
		w.linksFollowed++
		target = t
		// The link's target may itself be a key file under a certificate-looking link name.
		if _, k := classify(path.Base(target)); k {
			w.keyFilesSkipped++
			return
		}
	}
	w.read(full, target)
}

// resolve applies the symbolic-link rule (ENG-HANDOFF-002 DN-4, SR-16): the link's target,
// resolved against the host root, must stay inside it, must be a regular file, and every
// directory on the way must be a real directory. A link to a link is refused: links are
// followed once.
func (w *walk) resolve(link string) (string, bool) {
	t, err := fs.ReadLink(w.s.fsys, link)
	if err != nil || t == "" || len(t) > maxLocationLen {
		return "", false
	}
	var resolved string
	if path.IsAbs(t) {
		resolved = path.Clean(strings.TrimPrefix(t, "/"))
	} else {
		resolved = path.Join(path.Dir(link), t)
	}
	if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") || !fs.ValidPath(resolved) {
		return "", false
	}
	// every directory on the way is a real directory, not a link
	parts := strings.Split(resolved, "/")
	for i := 1; i < len(parts); i++ {
		fi, err := fs.Lstat(w.s.fsys, strings.Join(parts[:i], "/"))
		if err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
			return "", false
		}
	}
	fi, err := fs.Lstat(w.s.fsys, resolved)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return resolved, true
}

// read opens one candidate file and turns each certificate in it into an observation.
// location is where the certificate was found (the link name when a link was followed),
// target is the file actually read.
func (w *walk) read(location, target string) {
	fi, err := fs.Stat(w.s.fsys, target)
	if err != nil {
		w.errs++
		return
	}
	if fi.Size() > maxFileSize {
		w.oversized++
		return
	}
	data, err := fs.ReadFile(w.s.fsys, target)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			w.denied++
		} else {
			w.errs++
		}
		return
	}
	w.opened++

	var ders [][]byte
	keyAlongside := false
	if strings.Contains(string(data[:min(len(data), 1<<20)]), "-----BEGIN ") {
		res := scanPEM(data)
		ders = res.certs
		w.keyBlocks += res.keyBlocks
		w.otherBlocks += res.other
		w.malformed += res.malformed
		w.truncated = w.truncated || res.truncated
		keyAlongside = res.keyBlocks > 0
	} else if len(data) > 0 && data[0] == 0x30 && len(data) <= maxDERFileSize {
		// A bare DER file. A DER private key also starts with a SEQUENCE and simply fails to
		// parse as a certificate below: nothing of it is kept.
		if der, ok := firstElement(data); ok {
			ders = [][]byte{der}
		}
	}

	privateKey := "unknown"
	if keyAlongside {
		privateKey = "yes"
	}
	redacted := evidence.RedactPath(location)
	for _, der := range ders {
		if w.certs >= maxCertsPerRun {
			w.truncated = true
			return
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			w.unparseable++
			continue
		}
		w.observe(c, redacted, privateKey)
	}
}

func (w *walk) observe(c *x509.Certificate, location, privateKey string) {
	f := certinfo.Describe(c)
	id := f.SHA256 + "|" + location
	if w.seen[id] {
		return
	}
	w.seen[id] = true
	w.certs++

	attrs := map[string]string{
		"sha256":     f.SHA256,
		"serial":     evidence.Clean(f.SerialHex, 128),
		"subject":    evidence.Clean(f.Subject, maxAttrLen),
		"issuer":     evidence.Clean(f.Issuer, maxAttrLen),
		"notBefore":  f.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		"notAfter":   f.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		"keyAlg":     evidence.Clean(f.KeyAlgorithm, 64),
		"sigAlg":     evidence.Clean(f.SigName, 64),
		"isCA":       strconv.FormatBool(f.IsCA),
		"selfSigned": strconv.FormatBool(f.SelfSigned),
	}
	if f.KeyBits > 0 {
		attrs["keyBits"] = strconv.Itoa(f.KeyBits)
	}
	if f.Curve != "" {
		attrs["curve"] = evidence.Clean(f.Curve, 64)
	}
	if names := append(append([]string{}, f.DNSNames...), f.IPAddresses...); len(names) > 0 {
		attrs["dnsNames"] = evidence.Clean(strings.Join(names, ","), maxAttrLen)
	}
	if len(f.KeyUsage) > 0 {
		attrs["keyUsage"] = strings.Join(f.KeyUsage, ",")
	}
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	name := evidence.Clean(f.Subject, maxNameLen)
	if name == "" {
		name = f.SHA256
	}
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindCertificate, Key: evidence.CertificateKey(f.SHA256), Name: name, Attrs: attrs},
		Claim:   evidence.Claim{Rung: evidence.RungProvisioned}, Outcome: evidence.OutcomeObserved,
		Method: evidence.MethodCertFile, Source: evidence.Source{Kind: "file", Location: location, Attrs: map[string]string{"privateKey": privateKey}},
		Privilege: w.s.tier,
	}
	evidence.Finish(&o)
	w.batch.Observations = append(w.batch.Observations, o)
}
