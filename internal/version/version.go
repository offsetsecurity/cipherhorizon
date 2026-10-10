// Package version holds the build identity, stamped at link time by the release build:
//
//	go build -ldflags "-X github.com/offsetsecurity/cipherhorizon/internal/version.Version=1.2.3 \
//	  -X github.com/offsetsecurity/cipherhorizon/internal/version.Commit=abc1234 \
//	  -X github.com/offsetsecurity/cipherhorizon/internal/version.Date=2026-01-02T03:04:05Z" ./cmd/cipherhorizon
//
// A plain "go build" or "go install ...@vX.Y.Z" leaves the variables at their defaults; Info then
// falls back to what the Go toolchain embedded, so those builds still identify themselves.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the program version (SemVer, without a leading "v"). "0.0.0-dev" marks an unstamped build.
var Version = "0.0.0-dev"

// Commit is the source revision the binary was built from, when known.
var Commit = ""

// Date is the build time (RFC 3339, UTC), when known. Release builds take it from the commit,
// not the clock, so a rebuilt tag is byte-identical.
var Date = ""

// Info is the build identity shown by "cipherhorizon version" and recorded in reports.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns the build identity, filling gaps from the module and VCS data the toolchain embeds.
func Get() Info {
	info := Info{Version: Version, Commit: Commit, Date: Date, GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	// "go install module@vX.Y.Z" records the module version but is not stamped with ldflags.
	if info.Version == "0.0.0-dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = strings.TrimPrefix(bi.Main.Version, "v")
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		}
	}
	return info
}

// String is the one-line form: "1.2.3 (commit abc1234, built 2026-01-02T03:04:05Z, go1.25.0 linux/amd64)".
func (i Info) String() string {
	var parts []string
	if i.Commit != "" {
		c := i.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		parts = append(parts, "commit "+c)
	}
	if i.Date != "" {
		parts = append(parts, "built "+i.Date)
	}
	parts = append(parts, i.GoVersion+" "+i.Platform)
	return i.Version + " (" + strings.Join(parts, ", ") + ")"
}
