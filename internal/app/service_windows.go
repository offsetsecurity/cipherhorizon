//go:build windows

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/winsvc"
)

// The Windows service (docs/engineering/INSTALL.md). It runs "cipherhorizon serve" under the
// low-privilege LocalService account, from a copy of the program in Program Files (an account
// that is not you cannot read files in your user folder, Downloads included), with its database
// and log in ProgramData, a folder only SYSTEM, Administrators and the service can open.
// internal/winsvc does the talking to Windows.
const (
	serviceName    = "CipherHorizon"
	serviceDisplay = "CipherHorizon"
	serviceDesc    = "Post-quantum readiness for TLS and SSH: the CipherHorizon web interface and API."
	serviceAccount = `NT AUTHORITY\LocalService`
	// Protected DACL, inherited by everything below: SYSTEM and Administrators full control,
	// LocalService modify (read, write, create, delete its own files), nobody else.
	serviceDataSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;LS)"
	serviceLogLimit = 10 << 20
)

func serviceDirs() (programDir, dataDir string) {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pf, "CipherHorizon"), filepath.Join(pd, "CipherHorizon")
}

func serviceLogPath(dataDir string) string {
	return filepath.Join(dataDir, "logs", "cipherhorizon.log")
}

func serviceCmd(_ context.Context, args []string, env Env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(env.Stderr, serviceUsage)
		return ExitFatal
	}
	switch args[0] {
	case "install":
		return serviceInstall(args[1:], env)
	case "uninstall", "remove":
		return serviceUninstall(env)
	case "start":
		return serviceStart(env)
	case "stop":
		if err := winsvc.Stop(serviceName, 20*time.Second); err != nil {
			return serviceFail(env, "stopping", err)
		}
		_, _ = fmt.Fprintln(env.Stdout, "stopped")
		return ExitOK
	case "status":
		return serviceStatus(env)
	case "run":
		return serviceRun(args[1:], env)
	default:
		_, _ = fmt.Fprint(env.Stderr, serviceUsage)
		return ExitFatal
	}
}

const serviceUsage = `usage: cipherhorizon service <command>

  install [serve options]   install and start the Windows service (run as administrator). Options are
                            passed to "serve", e.g.  --sign-in on  or  --addr 0.0.0.0:8443 --tls-cert C:\certs\ch.pem --tls-key C:\certs\ch.key
  status                    is it installed and running; where its data and log are
  start | stop              start or stop it
  uninstall                 stop and remove it (the database is kept)
`

// serviceFail reports err, naming the log when the service itself failed.
func serviceFail(env Env, doing string, err error) int {
	_, dataDir := serviceDirs()
	switch {
	case errors.Is(err, winsvc.ErrNotInstalled):
		return fatalf(env, "the %s service is not installed (cipherhorizon service install)", serviceName)
	case errors.Is(err, winsvc.ErrStopped):
		return fatalf(env, "the service stopped right after starting; the reason is at the end of %s", serviceLogPath(dataDir))
	case errors.Is(err, winsvc.ErrNeedAdmin):
		return fatalf(env, "%v", err)
	}
	return fatalf(env, "%s: %v", doing, err)
}

func serviceInstall(serveArgs []string, env Env) int {
	for _, a := range serveArgs {
		if a == "--db" || strings.HasPrefix(a, "--db=") || a == "-db" || strings.HasPrefix(a, "-db=") {
			return fatalf(env, "the service keeps its database in ProgramData; leave out --db")
		}
	}
	if st, err := winsvc.Query(serviceName); err == nil {
		return fatalf(env, "the %s service is already installed (%s); cipherhorizon service uninstall first, to change its options", serviceName, st.State)
	}
	programDir, dataDir := serviceDirs()
	exe, err := installProgram(programDir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fatalf(env, "%v", winsvc.ErrNeedAdmin)
		}
		return fatalf(env, "copying the program to %s: %v", programDir, err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "logs"), 0o700); err != nil {
		return fatalf(env, "creating %s: %v", dataDir, err)
	}
	if err := winsvc.LockDown(dataDir, serviceDataSDDL); err != nil {
		return fatalf(env, "restricting %s: %v", dataDir, err)
	}
	err = winsvc.Install(winsvc.Config{
		Name: serviceName, Display: serviceDisplay, Description: serviceDesc, Account: serviceAccount,
		Exe:  exe,
		Args: append([]string{"service", "run", "--db", filepath.Join(dataDir, "cipherhorizon.db")}, serveArgs...),
	})
	if err != nil {
		return serviceFail(env, "creating the service", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "installed the %s service: program %s, data %s\n", serviceName, exe, dataDir)
	if err := winsvc.Start(serviceName, 15*time.Second); err != nil {
		return serviceFail(env, "starting the service", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "it is running and starts with Windows. Open %s\n", serviceURL(serveArgs))
	_, _ = fmt.Fprintf(env.Stdout, "log: %s   status: cipherhorizon service status\n", serviceLogPath(dataDir))
	return ExitOK
}

// installProgram copies this executable into programDir (unless it already runs from there)
// and returns the installed path. It inherits Program Files' permissions (readable by all,
// writable by administrators); the mode bits below only matter on other systems.
func installProgram(programDir string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return "", err
	}
	dst := filepath.Join(programDir, "cipherhorizon.exe")
	if strings.EqualFold(filepath.Clean(self), filepath.Clean(dst)) {
		return dst, nil
	}
	if err := os.MkdirAll(programDir, 0o750); err != nil {
		return "", err
	}
	in, err := os.Open(self) // #nosec G304 -- our own executable
	if err != nil {
		return "", err
	}
	defer in.Close() //nolint:errcheck // read only
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dst, nil
}

// serviceURL is where the installed service can be opened, from its --addr (default loopback).
func serviceURL(serveArgs []string) string {
	addr, scheme := "127.0.0.1:8080", "http"
	for i, a := range serveArgs {
		switch {
		case (a == "--addr" || a == "-addr") && i+1 < len(serveArgs):
			addr = serveArgs[i+1]
		case strings.HasPrefix(a, "--addr="):
			addr = strings.TrimPrefix(a, "--addr=")
		case a == "--tls-cert" || strings.HasPrefix(a, "--tls-cert="):
			scheme = "https"
		}
	}
	if strings.HasPrefix(addr, ":") || strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, "[::]:") {
		addr = "127.0.0.1:" + addr[strings.LastIndex(addr, ":")+1:]
	}
	return scheme + "://" + addr
}

func serviceStart(env Env) int {
	if err := winsvc.Start(serviceName, 15*time.Second); err != nil {
		return serviceFail(env, "starting", err)
	}
	_, _ = fmt.Fprintln(env.Stdout, "started")
	return ExitOK
}

func serviceUninstall(env Env) int {
	if err := winsvc.Remove(serviceName); err != nil {
		return serviceFail(env, "removing the service", err)
	}
	programDir, dataDir := serviceDirs()
	_ = os.Remove(filepath.Join(programDir, "cipherhorizon.exe")) // fails harmlessly if this is the running copy
	_ = os.Remove(programDir)
	_, _ = fmt.Fprintf(env.Stdout, "removed the %s service. The database and log are kept in %s; delete that folder to remove them.\n", serviceName, dataDir)
	return ExitOK
}

func serviceStatus(env Env) int {
	st, err := winsvc.Query(serviceName)
	if errors.Is(err, winsvc.ErrNotInstalled) {
		_, _ = fmt.Fprintf(env.Stdout, "the %s service is not installed\n", serviceName)
		return ExitFatal
	}
	if err != nil {
		return fatalf(env, "querying the service: %v", err)
	}
	_, dataDir := serviceDirs()
	_, _ = fmt.Fprintf(env.Stdout, "%s: %s\n  command  %s\n  data     %s\n  log      %s\n", serviceName, st.State,
		st.Command, dataDir, serviceLogPath(dataDir))
	if !st.Running {
		return ExitFatal
	}
	return ExitOK
}

// serviceRun is what the service manager starts. It runs "serve" with its output in the log
// file, and stops it cleanly when Windows asks.
func serviceRun(serveArgs []string, env Env) int {
	if isSvc, err := winsvc.IsService(); err != nil || !isSvc {
		return fatalf(env, "\"service run\" is started by Windows; use \"cipherhorizon serve\" to run in this window")
	}
	_, dataDir := serviceDirs()
	logFile, err := openServiceLog(serviceLogPath(dataDir))
	if err != nil {
		return ExitFatal
	}
	defer logFile.Close() //nolint:errcheck // exiting
	env.Stdout, env.Stderr = logFile, logFile
	code, err := winsvc.Run(serviceName, func(ctx context.Context) int { return serveCmd(ctx, serveArgs, env) })
	if err != nil {
		_, _ = fmt.Fprintf(logFile, "service: %v\n", err)
		return ExitFatal
	}
	return code
}

// openServiceLog appends to the log, first moving a log past serviceLogLimit to ".1".
func openServiceLog(path string) (*os.File, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > serviceLogLimit {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- fixed path under ProgramData
	if err != nil {
		return nil, err
	}
	_, _ = fmt.Fprintf(f, "\n---- %s service starting\n", time.Now().UTC().Format(time.RFC3339))
	return f, nil
}
