package store

import (
	"database/sql"
	"time"
)

// ForceSchemaVersion stamps a database with a schema version (tests).
func ForceSchemaVersion(path string, v int) error {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // test
	_, err = db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, 'x')`, v)
	return err
}

// BuildLegacyDB creates a database at path as an older release would have left it: only
// the first upTo migrations applied. The migrations it replays are history and must
// never be edited; TestFrozenMigrationsAreUnchanged pins them.
func BuildLegacyDB(path string, upTo int) error {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // test
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	for v := 1; v <= upTo; v++ {
		if _, err := db.Exec(migrations[v-1]); err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, 'legacy')`, v); err != nil {
			return err
		}
	}
	return nil
}

// FrozenMigration returns migration v (1-based) for hashing.
func FrozenMigration(v int) string { return migrations[v-1] }

// SetPostMigration replaces the Go step of migration v and returns a restore function.
func SetPostMigration(v int, fn func(tx *sql.Tx, now time.Time) error) (restore func()) {
	old := postMigrations[v]
	postMigrations[v] = fn
	return func() { postMigrations[v] = old }
}

// ExecForTest runs raw SQL against the store's database.
func (s *Store) ExecForTest(q string, args ...any) error {
	_, err := s.db.Exec(q, args...)
	return err
}

// QueryIntForTest runs a query returning one integer.
func (s *Store) QueryIntForTest(q string, args ...any) (int, error) {
	var n int
	err := s.db.QueryRow(q, args...).Scan(&n)
	return n, err
}

// QueryStringForTest runs a query returning one string.
func (s *Store) QueryStringForTest(q string, dest *string, args ...any) error {
	return s.db.QueryRow(q, args...).Scan(dest)
}
