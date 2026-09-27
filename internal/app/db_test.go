package app_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// REQ-MOD-5: the graph can be rebuilt from the stored documents by a documented command.
func TestDBRebuildGraphAndStats(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	code, out, errOut := run(t, "db", "rebuild-graph", "--db", db)
	if code != 0 || !strings.Contains(out, "rebuilt the estate graph") {
		t.Fatalf("rebuild-graph: %d %q %q", code, out, errOut)
	}
	code, out, errOut = run(t, "db", "stats", "--db", db)
	if code != 0 || !strings.Contains(out, `"projectionVersion"`) || !strings.Contains(out, `"stale": false`) {
		t.Fatalf("stats: %d %q %q", code, out, errOut)
	}
	for _, args := range [][]string{{"db"}, {"db", "nonsense"}, {"db", "stats", "extra"}, {"db", "stats", "--nope"}} {
		if code, _, _ := run(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}
