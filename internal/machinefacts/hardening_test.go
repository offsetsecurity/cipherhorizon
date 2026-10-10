package machinefacts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// PRD-007 REQ-TR-4 (audit L-10..L-12): the engines write nothing another local user can read,
// never fall back to a guessable temporary name, and never let the shell expand a signature's
// file pattern against the folder the script was started in.
func TestShellEngineIsHardened(t *testing.T) {
	sh, err := Engine("cipherhorizon-inventory.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(sh)
	umask := strings.Index(body, "\numask 077\n")
	if umask < 0 || umask > strings.Index(body, `> "$OUT"`) || umask > strings.Index(body, "mktemp") {
		t.Error("sh: umask 077 must come before anything is written")
	}
	if strings.Contains(body, "/tmp/") || !strings.Contains(body, "mktemp is needed") {
		t.Error("sh: without mktemp the script must stop, not fall back to a name under /tmp")
	}
	start := strings.Index(body, "cap_file() {")
	if start < 0 {
		t.Fatal("sh: cap_file is gone")
	}
	capFile, _, _ := strings.Cut(body[start:], "\n}\n")
	if f, loop, on := strings.Index(capFile, "set -f"), strings.Index(capFile, `for nm in $(`), strings.Index(capFile, "set +f"); f < 0 || f > loop || on < loop {
		t.Error("sh: the names loop in cap_file must run with globbing off (set -f … set +f)")
	}

	ps, err := Engine("cipherhorizon-inventory.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SetAccessRuleProtection($true, $false)", "Set-Acl -LiteralPath $OutFile", "S-1-5-32-544", "S-1-5-18"} {
		if !strings.Contains(string(ps), want) {
			t.Errorf("ps1: the facts file's owner-only ACL is missing %q", want)
		}
	}

	switch runtime.GOOS {
	case "windows":
		runWindowsEngine(t)
	default:
		runShellEngine(t)
	}
}

// runShellEngine runs the real engine with one file signature whose pattern also matches a file
// in the working directory. Expanded by the shell, the pattern would become that one file's name
// and find would miss the real ones.
func runShellEngine(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root, cwd := t.TempDir(), t.TempDir()
	for _, name := range []string{"libdemo-1.so", "libdemo-2.so"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cwd, "libdemo-decoy.so"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sigs := filepath.Join(t.TempDir(), "sigs.txt")
	if err := os.WriteFile(sigs, []byte("signatures\ttest\nsig\tTEST.FILE\tfile\tnames=libdemo-*.so\troots="+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "s.sh")
	if err := os.WriteFile(script, Scripts()[1].Body(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "facts.txt")
	cmd := exec.Command("sh", script, out, sigs)
	cmd.Dir = cwd
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"libdemo-1.so", "libdemo-2.so"} {
		if !strings.Contains(string(raw), name) {
			t.Errorf("the file signature missed %s (the shell expanded its pattern?)\n%s", name, raw)
		}
	}
	if strings.Contains(string(raw), "decoy") {
		t.Errorf("the working directory leaked into the facts:\n%s", raw)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("facts file mode %o, want 600", mode)
	}

	// Without mktemp on the PATH the script stops before writing anything.
	bin := t.TempDir()
	for _, tool := range []string{"hostname", "id", "cat", "tr", "date"} {
		if p, err := exec.LookPath(tool); err == nil {
			_ = os.Symlink(p, filepath.Join(bin, tool))
		}
	}
	shPath, _ := exec.LookPath("sh")
	out2 := filepath.Join(t.TempDir(), "facts.txt")
	cmd = exec.Command(shPath, script, out2, sigs)
	cmd.Env = []string{"PATH=" + bin}
	b, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(b), "mktemp is needed") {
		t.Errorf("without mktemp: err %v, output %s", err, b)
	}
	if _, err := os.Stat(out2); err == nil {
		t.Error("without mktemp the script still wrote a facts file")
	}
}

// runWindowsEngine runs the real PowerShell engine with no signatures (fast) and reads back the
// facts file's ACL: inheritance off, and only the current user, Administrators and SYSTEM.
func runWindowsEngine(t *testing.T) {
	ps, err := exec.LookPath("powershell")
	if err != nil {
		t.Skip("no powershell")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "s.ps1")
	if err := os.WriteFile(script, Scripts()[0].Body(), 0o600); err != nil {
		t.Fatal(err)
	}
	sigs := filepath.Join(dir, "sigs.txt")
	if err := os.WriteFile(sigs, []byte("signatures\ttest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "facts.txt")
	b, err := windowsPowerShell(ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-OutFile", out, "-SignatureFile", sigs).CombinedOutput()
	if err != nil || strings.Contains(string(b), "could not limit") {
		t.Fatalf("script: %v\n%s", err, b)
	}
	acl := string(aclOf(t, ps, out))
	if !strings.Contains(acl, "protected=True") {
		t.Errorf("the facts file still inherits its folder's permissions:\n%s", acl)
	}
	for _, line := range strings.Split(strings.TrimSpace(acl), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "protected=") {
			continue
		}
		if line != "S-1-5-32-544" && line != "S-1-5-18" && !strings.HasPrefix(line, "S-1-5-21-") {
			t.Errorf("the facts file is readable by %s", line)
		}
	}
}

// aclOf prints the facts file's ACL as SIDs, one per line, after a protected= line.
// windowsPowerShell runs Windows PowerShell 5.1 without the caller's PSModulePath. Started from
// PowerShell 7 (as a CI step is), 5.1 inherits 7's module folders and then cannot load its own
// Microsoft.PowerShell.Security module, so Set-Acl and Get-Acl are missing. A person who runs the
// script from Windows PowerShell does not have that problem.
func windowsPowerShell(ps string, args ...string) *exec.Cmd {
	cmd := exec.Command(ps, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "PSMODULEPATH=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	return cmd
}

func aclOf(t *testing.T, ps, file string) []byte {
	t.Helper()
	cmd := `$a = Get-Acl -LiteralPath '` + strings.ReplaceAll(file, "'", "''") + `'; "protected=$($a.AreAccessRulesProtected)"; ` +
		`$a.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }`
	b, err := windowsPowerShell(ps, "-NoProfile", "-Command", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("reading the ACL: %v\n%s", err, b)
	}
	return b
}
