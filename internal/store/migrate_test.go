package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// A database written by the build that stored letter grades must open, keep its scans, and
// show no rating for them (the old letters came from a different scale) until they are repeated.
func TestMigrationFromLetterGrades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		migrations[0],
		`INSERT INTO schema_migrations VALUES (1, '2026-01-01T00:00:00Z')`,
		`INSERT INTO assets (kind, name, host, port, created_at, updated_at) VALUES ('tls-endpoint', 'a', 'a.example', 443, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		`INSERT INTO scans (asset_id, status, trigger, queued_at, finished_at, grade, readiness_level) VALUES (1, 'done', 'manual', '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z', 'A', 3)`,
	} {
		if _, err := old.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("opening a database from the previous build: %v", err)
	}
	defer s.Close() //nolint:errcheck // test
	sc, err := s.GetScan(1)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status != StatusDone || sc.ReadinessLevel == nil || *sc.ReadinessLevel != 3 {
		t.Errorf("the scan was not kept: %+v", sc)
	}
	if sc.Band != "" || sc.Score != -1 {
		t.Errorf("an old letter grade leaked into the new rating: band %q score %d", sc.Band, sc.Score)
	}
}
