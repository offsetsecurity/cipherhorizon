//go:build !windows

package hostinfo

import "os"

// CurrentTier reports whether the process is root. Being root is the admin tier;
// any other user is the user tier. The tool never escalates.
func CurrentTier() string {
	if os.Geteuid() == 0 {
		return TierAdmin
	}
	return TierUser
}

// PlatformOSVersion is empty off Windows: the version comes from os-release.
func PlatformOSVersion() string { return "" }

// PlatformMachineID is not used off Windows (Linux reads /etc/machine-id from the
// host filesystem, so a mounted host is identified, not the scanner).
func PlatformMachineID() (string, error) {
	return "", ErrNoMachineID
}
