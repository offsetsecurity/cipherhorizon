package machinefacts

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpScripts writes the scripts as served to DUMP_SCRIPTS_DIR when it is set: a QA
// helper for running the real engines with the real signatures.
func TestDumpScripts(t *testing.T) {
	dir := os.Getenv("DUMP_SCRIPTS_DIR")
	if dir == "" {
		t.Skip("set DUMP_SCRIPTS_DIR to write the served scripts")
	}
	for _, s := range Scripts() {
		if err := os.WriteFile(filepath.Join(dir, s.Name), s.Body(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
