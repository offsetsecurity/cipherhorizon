package hostcmd

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/cipherhorizon/internal/config"
)

// SR-16: for a root that is not this machine's own, a symbolic link inside the tree cannot
// lead a sensor out of it.
func TestAnOverriddenRootCannotBeEscapedBySymlinks(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside the root"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "ssl", "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "ssl", "certs", "inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc", "ssl", "escape")); err != nil {
		t.Skipf("cannot create symbolic links here: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "etc", "ssl", "certs", "abs-link.pem")); err != nil {
		t.Skipf("cannot create symbolic links here: %v", err)
	}

	fsys, closeFS, err := openHostFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFS()

	if b, err := fs.ReadFile(fsys, "etc/ssl/certs/inside.txt"); err != nil || string(b) != "inside" {
		t.Errorf("a file inside the root: %q, %v", b, err)
	}
	if _, err := fs.ReadFile(fsys, "etc/ssl/escape/secret.txt"); err == nil {
		t.Error("a symlinked directory led out of the root")
	}
	if _, err := fs.ReadFile(fsys, "etc/ssl/certs/abs-link.pem"); err == nil {
		t.Error("a symlink to an absolute path outside the root was followed")
	}
	if _, err := fs.ReadFile(fsys, "../"+filepath.Base(outside)+"/secret.txt"); err == nil || !errors.Is(err, fs.ErrInvalid) && !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a path with .. was not refused: %v", err)
	}
}

func TestTheMachinesOwnRootIsAnOrdinaryTree(t *testing.T) {
	fsys, closeFS, err := openHostFS(config.DefaultRoot())
	if err != nil {
		t.Fatal(err)
	}
	closeFS()
	if fsys == nil {
		t.Fatal("no filesystem")
	}
}
