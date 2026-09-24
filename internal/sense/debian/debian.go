// Package debian is the sensor for Debian-family hosts (Debian, Ubuntu, Kali and
// derivatives). It reads the dpkg database directly, in pure Go, so it needs no
// subprocess, no root, and works unchanged against a host filesystem mounted into
// a container.
//
// It reports one thing: which crypto-relevant packages are installed
// (evidence rung `present`, method debian.dpkg.status, authoritative). It says
// nothing about what those packages can do: that is knowledge, applied later by
// internal/derive from internal/knowledge.
package debian

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/package-url/packageurl-go"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/knowledge"
	"github.com/example/cipherhorizon/internal/sense"
)

const (
	// Name is the sensor's registry name. It is "apt" (not "debian") so existing
	// plugins.enabled / plugins.disabled configuration keeps working.
	Name = "apt"

	// Version is the version of this sensor's behaviour.
	Version = "0.2.0"

	statusPath = "var/lib/dpkg/status" // fs.FS-style: unrooted
)

func init() {
	sense.Register(Name, func(env sense.Env) (sense.Sensor, error) {
		if env.FS == nil {
			return nil, errors.New("apt: host filesystem is nil")
		}
		return New(env), nil
	})
}

// Sensor implements sense.Sensor for dpkg-managed hosts.
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
	return sense.Info{Name: Name, Version: Version, Methods: []string{evidence.MethodDpkgStatus}}
}

// Detect reports whether a dpkg database exists on the host.
func (s *Sensor) Detect(context.Context) (bool, error) {
	_, err := fs.Stat(s.fsys, statusPath)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("apt: %w", err)
	}
}

// unseen names what this sensor's scope cannot show, so silence is never read as safety.
var unseen = []string{
	"cryptography statically linked into applications or embedded in custom software",
	"libraries bundled inside applications, containers and language-runtime environments",
	"software not installed through dpkg",
	"configuration, certificates, key material and application association (not collected by this version)",
	"what any installed software actually does: a package being installed says nothing about use",
}

// Collect reads the dpkg database and returns a `present` observation for every
// installed crypto-relevant package.
func (s *Sensor) Collect(ctx context.Context) (evidence.Batch, error) {
	var batch evidence.Batch
	cov := evidence.Coverage{
		Sensor: Name, Method: evidence.MethodDpkgStatus, Scope: "installed packages (dpkg status database)",
		Status: evidence.CoverageComplete, Unseen: unseen,
	}

	f, err := s.fsys.Open(statusPath)
	if err != nil {
		cov.Status, cov.Reason = evidence.CoverageFailed, evidence.UnknownError
		batch.Coverage = []evidence.Coverage{cov}
		return batch, fmt.Errorf("apt: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only

	osr := hostinfo.ReadOSRelease(s.fsys)
	parseErr := parseStatus(ctx, f, func(p pkg) {
		if !p.installed() {
			return
		}
		fam := knowledge.RecognizePackage(p.Name)
		if fam == nil {
			return
		}
		batch.Observations = append(batch.Observations, s.observe(p, fam, osr))
	})
	if parseErr != nil {
		// Everything parsed before the failure is kept; the error marks it incomplete.
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownError
		batch.Coverage = []evidence.Coverage{cov}
		return batch, fmt.Errorf("apt: reading /%s: %w", statusPath, parseErr)
	}
	batch.Coverage = []evidence.Coverage{cov}
	return batch, nil
}

func (s *Sensor) observe(p pkg, fam *knowledge.Family, osr hostinfo.OSRelease) evidence.Observation {
	// Everything in the status file is host-supplied text: make it safe to carry so a
	// malformed stanza cannot break the run.
	p.Name, p.Version, p.Arch = evidence.Clean(p.Name, 128), evidence.Clean(p.Version, 128), evidence.Clean(p.Arch, 32)
	key := purlFor(p, osr)
	if key == "" {
		key = fmt.Sprintf("apt/%s@%s/%s", p.Name, p.Version, p.Arch)
	}
	attrs := map[string]string{
		"name": p.Name, "version": p.Version, "arch": p.Arch, "family": fam.ID, "kind": fam.KindFor(p.Name),
	}
	if osr.ID != "" && osr.VersionID != "" {
		attrs["distro"] = osr.ID + "-" + osr.VersionID
	}
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindPackage, Key: key, Name: p.Name, Attrs: attrs},
		Claim:   evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
		Method: evidence.MethodDpkgStatus,
		Source: evidence.Source{Kind: "database", Location: statusPath},
		// The tier the run actually has, not the tier the method needs.
		Privilege: s.tier,
	}
	evidence.Finish(&o)
	return o
}

// purlFor builds a Package URL for a Debian package, or "" when the vendor cannot
// be established (the purl deb type requires one).
func purlFor(p pkg, osr hostinfo.OSRelease) string {
	if osr.ID == "" || p.Version == "" {
		return ""
	}
	q := map[string]string{}
	if p.Arch != "" {
		q["arch"] = p.Arch
	}
	if osr.VersionID != "" {
		q["distro"] = osr.ID + "-" + osr.VersionID
	}
	return packageurl.NewPackageURL(packageurl.TypeDebian, osr.ID, p.Name, p.Version,
		packageurl.QualifiersFromMap(q), "").ToString()
}
