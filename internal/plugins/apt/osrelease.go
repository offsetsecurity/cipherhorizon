package apt

import (
	"bufio"
	"io/fs"
	"strings"
)

// osRelease holds the two os-release(5) fields that shape a Debian package URL.
type osRelease struct {
	ID        string // e.g. "ubuntu": the purl namespace
	VersionID string // e.g. "24.04": part of the purl distro qualifier; absent on Debian testing/sid
}

// readOSRelease reads os-release(5) from the host, preferring /etc and falling
// back to /usr/lib as the specification says. A missing file is not an error:
// it yields the zero value and the plugin omits the purl rather than guess a vendor.
func readOSRelease(fsys fs.FS) osRelease {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := fsys.Open(p)
		if err != nil {
			continue
		}
		defer f.Close() //nolint:errcheck // read-only
		var r osRelease
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok {
				continue
			}
			val = strings.Trim(val, `"'`)
			switch key {
			case "ID":
				r.ID = strings.ToLower(val)
			case "VERSION_ID":
				r.VersionID = val
			}
		}
		return r
	}
	return osRelease{}
}
