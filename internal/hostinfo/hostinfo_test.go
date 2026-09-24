package hostinfo

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestReadOSRelease(t *testing.T) {
	fsys := fstest.MapFS{"etc/os-release": {Data: []byte("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=Ubuntu\n")}}
	got := ReadOSRelease(fsys)
	if got.ID != "ubuntu" || got.VersionID != "24.04" || got.Name != "Ubuntu" {
		t.Errorf("got %+v", got)
	}
	// /usr/lib is the fallback location.
	if r := ReadOSRelease(fstest.MapFS{"usr/lib/os-release": {Data: []byte("ID=debian\n")}}); r.ID != "debian" || r.VersionID != "" {
		t.Errorf("fallback: %+v", r)
	}
	if r := ReadOSRelease(fstest.MapFS{}); r != (OSRelease{}) {
		t.Errorf("missing file must give the zero value, got %+v", r)
	}
}

func TestHostLabelIsStableOneWayAndDoesNotRevealTheID(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	a, b := HostLabel(id), HostLabel("  "+strings.ToUpper(id)+"\n")
	if a != b {
		t.Errorf("not stable across formatting: %s %s", a, b)
	}
	if !strings.HasPrefix(a, "host-") || len(a) != len("host-")+12 {
		t.Errorf("label = %q", a)
	}
	if strings.Contains(a, id[:8]) {
		t.Error("the label contains part of the machine id")
	}
	if HostLabel(id) == HostLabel(id+"x") {
		t.Error("different machines share a label")
	}
}

func TestLinuxMachineID(t *testing.T) {
	if id, err := LinuxMachineID(fstest.MapFS{"etc/machine-id": {Data: []byte("abc123\n")}}); err != nil || id != "abc123" {
		t.Errorf("id = %q, %v", id, err)
	}
	if id, err := LinuxMachineID(fstest.MapFS{"var/lib/dbus/machine-id": {Data: []byte("dbus1")}}); err != nil || id != "dbus1" {
		t.Errorf("fallback = %q, %v", id, err)
	}
	if _, err := LinuxMachineID(fstest.MapFS{}); !errors.Is(err, ErrNoMachineID) {
		t.Errorf("err = %v", err)
	}
	if _, err := LinuxMachineID(fstest.MapFS{"etc/machine-id": {Data: []byte(strings.Repeat("a", 500))}}); err == nil {
		t.Error("an absurd machine id was accepted")
	}
}

func TestDescribeLinux(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/os-release": {Data: []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n")},
		"etc/machine-id": {Data: []byte("deadbeef\n")},
	}
	h := Describe(fsys, "linux", "web01", TierUser)
	if h.Name != "web01" || h.OSFamily != "linux" || h.OSVersion != "ubuntu 24.04" || !strings.HasPrefix(h.ID, "host-") {
		t.Errorf("host = %+v", h)
	}
	if h.PrivilegeTier != TierUser {
		t.Errorf("tier = %q, want the one passed in", h.PrivilegeTier)
	}
}

func TestCurrentTierIsOneOfTheTwo(t *testing.T) {
	if got := CurrentTier(); got != TierUser && got != TierAdmin {
		t.Errorf("tier = %q", got)
	}
}
