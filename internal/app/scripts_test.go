package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// PRD-007 REQ-TR-7 (audit L-04): the hashes the binary prints are the hashes of the bytes a
// running server hands out, and `scripts export` writes those same bytes with a checksum list
// sha256sum can check.
func TestScriptsCommandMatchesTheServer(t *testing.T) {
	code, out, errOut := run(t, "scripts", "list")
	if code != 0 {
		t.Fatalf("scripts list: %d %s", code, errOut)
	}
	line := regexp.MustCompile(`^([0-9a-f]{64})  (cipherhorizon-inventory\.(?:sh|ps1))$`)
	want := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		m := line.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("not a sha256sum line: %q", l)
		}
		want[m[2]] = m[1]
	}
	if len(want) != 2 {
		t.Fatalf("scripts list printed %d scripts, want 2:\n%s", len(want), out)
	}

	// A real server from the same binary.
	const token = "scripts-test-token-0123456789abcdef"
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	ctx, cancel := context.WithCancel(context.Background())
	errb := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- app.Main(ctx, []string{"serve", "--addr", "127.0.0.1:0", "--db", filepath.Join(t.TempDir(), "x.db"), "--token", token},
			app.Env{Stdout: io.Discard, Stderr: errb})
	}()
	defer func() { cancel(); <-done }()
	re := regexp.MustCompile(`on http://(127\.0\.0\.1:\d+)`)
	var base string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && base == ""; time.Sleep(20 * time.Millisecond) {
		if m := re.FindStringSubmatch(errb.String()); m != nil {
			base = "http://" + m[1]
		}
	}
	if base == "" {
		t.Fatalf("the server never announced its address:\n%s", errb.String())
	}
	served := map[string][]byte{}
	for name, sum := range want {
		req, _ := http.NewRequest("GET", base+"/api/v1/collector/scripts/"+name+"?download=1", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		got := sha256.Sum256(body)
		if res.StatusCode != 200 || hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s: served %d bytes with SHA-256 %x (status %d); the binary says %s", name, len(body), got, res.StatusCode, sum)
		}
		served[name] = body
	}

	dir := filepath.Join(t.TempDir(), "scripts")
	if code, _, errOut := run(t, "scripts", "export", dir); code != 0 {
		t.Fatalf("scripts export: %d %s", code, errOut)
	}
	for name, body := range served {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(b) != string(body) {
			t.Errorf("%s: exported bytes differ from the served bytes (%v)", name, err)
		}
	}
	sums, err := os.ReadFile(filepath.Join(dir, app.ScriptsSumsFile))
	if err != nil || string(sums) != out {
		t.Errorf("%s differs from scripts list: %v\n%s", app.ScriptsSumsFile, err, sums)
	}

	for _, args := range [][]string{{"scripts"}, {"scripts", "nope"}, {"scripts", "list", "x"}, {"scripts", "export"}} {
		if code, _, _ := run(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

// PRD-007 REQ-DP-5: `db backup` writes a consistent, owner-only copy that opens as the database,
// and never overwrites a file.
func TestDBBackup(t *testing.T) {
	db := filepath.Join(t.TempDir(), "live.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("alice", "Alice", "admin", "hash", false, "test"); err != nil {
		t.Fatal(err)
	}
	// The database stays open, as it is under a running server.
	defer st.Close() //nolint:errcheck // test

	dst := filepath.Join(t.TempDir(), "copy.db")
	code, out, errOut := run(t, "db", "backup", "--db", db, dst)
	if code != 0 || !strings.Contains(out, dst) {
		t.Fatalf("db backup: %d %q %q", code, out, errOut)
	}
	cp, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	users, err := cp.ListUsers()
	_ = cp.Close()
	if err != nil || len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("the copy holds %+v, %v", users, err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("copy mode %v, %v; want 0600", fi.Mode(), err)
		}
	}
	if code, _, errOut := run(t, "db", "backup", "--db", db, dst); code != 1 || !strings.Contains(errOut, "already exists") {
		t.Errorf("a second backup to the same file: %d %q; want a refusal", code, errOut)
	}
	missing := filepath.Join(t.TempDir(), "nope.db")
	if code, _, errOut := run(t, "db", "backup", "--db", missing, filepath.Join(t.TempDir(), "c.db")); code != 1 || !strings.Contains(errOut, "no database") {
		t.Errorf("backing up a missing database: %d %q; want a refusal", code, errOut)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("backing up a missing database created it")
	}
	if code, _, _ := run(t, "db", "backup", "--db", db); code != 1 {
		t.Error("db backup without a destination must be refused")
	}
}
