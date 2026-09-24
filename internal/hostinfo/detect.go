package hostinfo

import (
	"io/fs"
	"runtime"

	"github.com/example/cipherhorizon/internal/evidence"
)

// Describe builds the evidence.Host for a scan of fsys on the given OS family.
// name is the host name to record (already resolved by the caller) and tier the
// privilege tier of the run (CurrentTier in production; injected in tests).
//
// On Windows the machine id and OS version come from the running system, because
// a Windows scan is always of the live machine; elsewhere they come from the host
// filesystem, so a host mounted into a container is identified rather than the
// container.
func Describe(fsys fs.FS, osFamily, name, tier string) evidence.Host {
	h := evidence.Host{Name: name, OSFamily: osFamily, Arch: runtime.GOARCH, PrivilegeTier: tier}
	if osFamily == "windows" {
		h.OSVersion = PlatformOSVersion()
		if id, err := PlatformMachineID(); err == nil {
			h.ID = HostLabel(id)
		}
		return h
	}
	if r := ReadOSRelease(fsys); r.ID != "" {
		h.OSVersion = r.ID
		if r.VersionID != "" {
			h.OSVersion += " " + r.VersionID
		}
	}
	if id, err := LinuxMachineID(fsys); err == nil {
		h.ID = HostLabel(id)
	}
	return h
}
