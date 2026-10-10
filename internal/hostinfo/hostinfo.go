// Package hostinfo identifies the machine being inventoried and the privilege
// the run has: the two facts every report about a host needs and no sensor
// should have to work out for itself.
//
// Everything platform-specific is behind build tags in tier_*.go and
// machineid_*.go; the rest is ordinary Go that compiles and is tested everywhere.
package hostinfo

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
)

// Privilege tiers. The default and complete-in-itself tier is user; elevation is
// the operator's choice and is never taken by the tool (ADR-0009).
const (
	TierUser  = "user"
	TierAdmin = "admin"
)

// OSRelease holds the os-release(5) fields the tool uses.
type OSRelease struct {
	ID        string // e.g. "ubuntu": the purl namespace
	VersionID string // e.g. "24.04"; absent on Debian testing/sid
	Name      string // e.g. "Ubuntu"
}

// ReadOSRelease reads os-release(5) from the host, preferring /etc and falling
// back to /usr/lib as the specification says. A missing file is not an error: it
// yields the zero value and callers omit what depends on it rather than guess.
func ReadOSRelease(fsys fs.FS) OSRelease {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := fsys.Open(p)
		if err != nil {
			continue
		}
		defer f.Close() //nolint:errcheck // read-only
		var r OSRelease
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok {
				continue
			}
			// os-release is host-supplied text: keep only what is safe to carry.
			val = evidence.Clean(strings.Trim(val, `"'`), 64)
			switch key {
			case "ID":
				r.ID = strings.ToLower(val)
			case "VERSION_ID":
				r.VersionID = val
			case "NAME":
				r.Name = val
			}
		}
		return r
	}
	return OSRelease{}
}

// ErrNoMachineID means the platform offers no stable machine identifier.
var ErrNoMachineID = errors.New("hostinfo: no machine id available")

// HostLabel turns a platform machine id into the label used when the host name is
// redacted. It is stable per machine and one-way: the raw machine id is never
// emitted. The 12 hex digits are 48 bits, ample to tell hosts apart.
func HostLabel(machineID string) string {
	sum := sha256.Sum256([]byte("cipherhorizon:host:" + strings.ToLower(strings.TrimSpace(machineID))))
	return "host-" + hex.EncodeToString(sum[:6])
}

// LinuxMachineID reads /etc/machine-id (or the D-Bus fallback) from the host filesystem.
func LinuxMachineID(fsys fs.FS) (string, error) {
	for _, p := range []string{"etc/machine-id", "var/lib/dbus/machine-id"} {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(b)); id != "" && len(id) <= 64 {
			return id, nil
		}
	}
	return "", ErrNoMachineID
}
