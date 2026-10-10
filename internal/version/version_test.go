package version

import (
	"strings"
	"testing"
)

func TestInfoString(t *testing.T) {
	got := Info{Version: "1.2.3", Commit: "0123456789abcdef", Date: "2026-01-02T03:04:05Z", GoVersion: "go1.25.0", Platform: "linux/amd64"}.String()
	want := "1.2.3 (commit 0123456789ab, built 2026-01-02T03:04:05Z, go1.25.0 linux/amd64)"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestInfoStringWithoutStamp(t *testing.T) {
	got := Info{Version: "0.0.0-dev", GoVersion: "go1.25.0", Platform: "linux/amd64"}.String()
	if got != "0.0.0-dev (go1.25.0 linux/amd64)" {
		t.Fatalf("String() = %q", got)
	}
}

func TestGetHasVersionAndPlatform(t *testing.T) {
	i := Get()
	if i.Version == "" || !strings.Contains(i.Platform, "/") || !strings.HasPrefix(i.GoVersion, "go") {
		t.Fatalf("Get() = %+v", i)
	}
}
