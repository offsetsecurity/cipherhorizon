//go:build !windows

package app

import (
	"context"
	"runtime"
)

// serviceCmd exists on Windows only; elsewhere the operating system's own service manager runs
// "cipherhorizon serve" (docs/engineering/INSTALL.md).
func serviceCmd(_ context.Context, _ []string, env Env) int {
	how := "install the .deb or .rpm package (it brings a systemd unit), or use deploy/cipherhorizon.service"
	if runtime.GOOS == "darwin" {
		how = "use deploy/net.offsetsecurity.cipherhorizon.plist with launchctl"
	}
	return fatalf(env, "\"service\" manages the Windows service. On %s, %s; see docs/engineering/INSTALL.md", runtime.GOOS, how)
}
