//go:build windows

package hostinfo

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// CurrentTier reports whether the process token is elevated (an Administrator
// running "as administrator"). A member of the Administrators group in a
// non-elevated shell is still the user tier: that is what the process can do.
func CurrentTier() string {
	if windows.GetCurrentProcessToken().IsElevated() {
		return TierAdmin
	}
	return TierUser
}

// PlatformOSVersion is the Windows version, e.g. "10.0.26200".
func PlatformOSVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// PlatformMachineID reads the machine GUID from the registry. It is readable by a
// standard user and is a single value: nothing else is enumerated.
func PlatformMachineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", ErrNoMachineID
	}
	defer k.Close() //nolint:errcheck // read-only
	id, _, err := k.GetStringValue("MachineGuid")
	if err != nil || id == "" {
		return "", ErrNoMachineID
	}
	return id, nil
}
