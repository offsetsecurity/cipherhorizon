package store

import "database/sql"

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
