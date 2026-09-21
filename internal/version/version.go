// Package version holds the build version, overridable at link time:
//
//	go build -ldflags "-X github.com/example/cbom-scan/internal/version.Version=1.2.3" ./cmd/cbom-scan
package version

// Version is the program version.
var Version = "0.0.0-dev"
