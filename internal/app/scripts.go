package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/machinefacts"
)

// ScriptsSumsFile is the name of the checksum list `scripts export` writes beside the scripts,
// in the format `sha256sum --check` reads. Releases ship it, covered by the signed checksums.
const ScriptsSumsFile = "inventory-scripts.sha256"

// scriptsCmd lets anyone check an inventory script without trusting the server that handed it
// out (PRD-007 REQ-TR-7, audit L-04): the binary carries the same scripts, signatures included,
// so the hashes it prints are the hashes the server must serve.
func scriptsCmd(args []string, env Env) int {
	if len(args) == 0 {
		scriptsUsage(env.Stderr)
		return ExitFatal
	}
	switch {
	case args[0] == "list" && len(args) == 1:
		_, _ = fmt.Fprint(env.Stdout, scriptSums())
		return ExitOK
	case args[0] == "export" && len(args) == 2:
		dir := args[1]
		// The scripts and their checksums are published files (a release attaches them): readable by all.
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // published, not secret
			return fatalf(env, "creating %s: %v", dir, err)
		}
		for _, s := range machinefacts.Scripts() {
			if err := os.WriteFile(filepath.Join(dir, s.Name), s.Body(), 0o644); err != nil { //nolint:gosec // published, not secret
				return fatalf(env, "writing %s: %v", s.Name, err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, ScriptsSumsFile), []byte(scriptSums()), 0o644); err != nil { //nolint:gosec // published, not secret
			return fatalf(env, "writing %s: %v", ScriptsSumsFile, err)
		}
		_, _ = fmt.Fprintf(env.Stderr, "wrote the inventory scripts and %s to %s\n", ScriptsSumsFile, dir)
		return ExitOK
	default:
		scriptsUsage(env.Stderr)
		return ExitFatal
	}
}

// scriptSums is one "<sha256>  <name>" line per script, as sha256sum prints them.
func scriptSums() string {
	var b strings.Builder
	for _, s := range machinefacts.Scripts() {
		fmt.Fprintf(&b, "%s  %s\n", s.SHA256, s.Name)
	}
	return b.String()
}

func scriptsUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `usage: cipherhorizon scripts list | export DIR

  list    print the SHA-256 of each inventory script this version serves, in sha256sum format
  export  write the scripts and `+ScriptsSumsFile+` to DIR

A script downloaded from a CipherHorizon server must have the hash this command prints for the
same version (both carry the same signature database). Check it before you run it:
  sha256sum cipherhorizon-inventory.sh             (Linux)
  Get-FileHash .\cipherhorizon-inventory.ps1       (Windows PowerShell)
`)
}
