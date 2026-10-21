package store_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// REQ-UXF-1: a database made before the band rename carries every stored scan's band over to its
// new name, and leaves the score and the not-rated scans alone.
func TestOldBandsAreMigrated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v14.db")
	if err := store.BuildLegacyDB(path, 14); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	now := "2026-10-01T00:00:00Z"
	if _, err := db.Exec(`INSERT INTO assets (id, kind, name, host, port, created_at, updated_at) VALUES (1, 'tls-endpoint', 'a.example.test:443', 'a.example.test', 443, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	old := []string{"Strong", "Sound", "Fair", "Weak", "Broken", ""}
	for i, b := range old {
		if _, err := db.Exec(`INSERT INTO scans (id, asset_id, status, trigger, queued_at, finished_at, band, score) VALUES (?, 1, 'done', 'manual', ?, ?, ?, ?)`,
			i+1, now, now, b, 90-10*i); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()

	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	db, err = sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	want := []string{"Excellent", "Good", "Fair", "Poor", "Failing", ""}
	for i := range old {
		var band string
		var score int
		if err := db.QueryRow(`SELECT band, score FROM scans WHERE id = ?`, i+1).Scan(&band, &score); err != nil {
			t.Fatal(err)
		}
		if band != want[i] || score != 90-10*i {
			t.Errorf("scan %d: band %q score %d, want %q %d (was %q)", i+1, band, score, want[i], 90-10*i, old[i])
		}
	}
}
