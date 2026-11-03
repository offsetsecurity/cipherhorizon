package store_test

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// One server per database: a second exclusive open is refused with who holds it, and an upgrade
// by another version waits for the server to stop rather than changing the file under it.
func TestExclusiveOpenLocksTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ch.db")
	s, err := store.OpenWith(path, store.OpenOptions{Exclusive: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.OpenWith(path, store.OpenOptions{Exclusive: true})
	var le *store.LockedError
	if !errors.As(err, &le) || !errors.Is(err, store.ErrLocked) {
		t.Fatalf("second exclusive open = %v, want a LockedError", err)
	}
	if !strings.Contains(le.Holder, "pid ") {
		t.Errorf("holder %q does not say who holds it", le.Holder)
	}
	if held, _, err := store.LockHolder(path); err != nil || !held {
		t.Errorf("LockHolder = %v, %v; want held", held, err)
	}
	// A plain open of an up-to-date database needs no lock (db backup while the server runs).
	plain, err := store.Open(path)
	if err != nil {
		t.Fatalf("plain open while a server holds the lock: %v", err)
	}
	_ = plain.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := store.OpenWith(path, store.OpenOptions{Exclusive: true})
	if err != nil {
		t.Fatalf("after the first closed: %v", err)
	}
	_ = again.Close()
}

func TestUpgradeWaitsForTheServer(t *testing.T) {
	path, _ := legacy(t)
	// A server of the old version holds the lock: the upgrade must not start.
	release, err := store.HoldLockForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := store.Open(path); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("upgrade while locked = %v, want ErrLocked", err)
	}
	if v := schemaOn(t, path); v != 3 {
		t.Errorf("schema after a refused upgrade = %d, want 3 (unchanged)", v)
	}
	if bs, _ := filepath.Glob(path + ".bak-v*"); len(bs) != 0 {
		t.Errorf("a refused upgrade made backups: %v", bs)
	}
}

func TestRefuseModeLeavesAnOldDatabaseAlone(t *testing.T) {
	path, _ := legacy(t)
	_, err := store.OpenWith(path, store.OpenOptions{Migrate: store.MigrateRefuse})
	var me *store.MigrationNeededError
	if !errors.As(err, &me) || me.Have != 3 || me.Want != store.SchemaVersion() {
		t.Fatalf("OpenWith(refuse) = %v, want MigrationNeededError 3 -> %d", err, store.SchemaVersion())
	}
	if !strings.Contains(err.Error(), "cipherhorizon db migrate") {
		t.Errorf("the error does not say how to upgrade: %v", err)
	}
	if v := schemaOn(t, path); v != 3 {
		t.Errorf("schema = %d, want 3", v)
	}
	// A new database is created whatever the mode: there is nothing to protect.
	s, err := store.OpenWith(filepath.Join(t.TempDir(), "new.db"), store.OpenOptions{Migrate: store.MigrateRefuse})
	if err != nil {
		t.Fatalf("new database under refuse: %v", err)
	}
	_ = s.Close()
}

// A step that fails part-way through a multi-step upgrade puts the file back as it was before the
// upgrade began, not at the last step that worked; the failed copy is kept for diagnosis.
func TestFailedUpgradeIsPutBack(t *testing.T) {
	path, _ := legacy(t) // at schema 3, with data
	before := schemaDumpOf(t, path)
	restore := store.SetPostMigration(8, func(*sql.Tx, time.Time) error { return errors.New("injected failure at 8") })
	defer restore()
	_, err := store.Open(path)
	if err == nil || !strings.Contains(err.Error(), "injected failure at 8") || !strings.Contains(err.Error(), "put back exactly as it was") {
		t.Fatalf("Open = %v, want the failure and that the file was put back", err)
	}
	if v := schemaOn(t, path); v != 3 {
		t.Fatalf("schema after the failed upgrade = %d, want 3 (as before), not a half-upgraded 7", v)
	}
	if after := schemaDumpOf(t, path); after != before {
		t.Error("the restored file differs from the original")
	}
	failed, _ := filepath.Glob(path + ".failed-upgrade-*")
	if len(failed) != 1 {
		t.Errorf("failed copies kept: %v, want one", failed)
	}
	restore()
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("retry after the fix: %v", err)
	}
	_ = s.Close()
}

func TestUpgradeIsRecorded(t *testing.T) {
	path, _ := legacy(t)
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	st, err := store.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Schema != store.SchemaVersion() || len(st.Pending) != 0 || st.Newer || st.InUse {
		t.Errorf("status = %+v", st)
	}
	if st.StructureOK == nil || !*st.StructureOK {
		t.Error("an upgraded database does not match the structure this version builds")
	}
	if len(st.Upgrades) != 1 || st.Upgrades[0].FromSchema != 3 || st.Upgrades[0].ToSchema != store.SchemaVersion() || st.Upgrades[0].Backup == "" {
		t.Fatalf("upgrade history = %+v", st.Upgrades)
	}
	if len(st.Backups) != 1 || st.Backups[0].Schema != 3 || st.Backups[0].Path != st.Upgrades[0].Backup {
		t.Errorf("backups = %+v", st.Backups)
	}
}

func TestInspectDoesNotChangeAnything(t *testing.T) {
	path, _ := legacy(t)
	st, err := store.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Schema != 3 || len(st.Pending) != store.SchemaVersion()-3 || st.Pending[0] != 4 || st.StructureOK != nil {
		t.Errorf("status of an old database = %+v", st)
	}
	if v := schemaOn(t, path); v != 3 {
		t.Errorf("Inspect changed the schema to %d", v)
	}
	missing := filepath.Join(t.TempDir(), "nothing.db")
	if st, err := store.Inspect(missing); err != nil || st.Exists {
		t.Errorf("Inspect(missing) = %+v, %v", st, err)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("Inspect created a database")
	}
}

func TestCheckFindsAHandEditedSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ch.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	res, err := store.Check(path)
	if err != nil || !res.OK() {
		t.Fatalf("fresh database: %+v, %v", res, err)
	}
	db, _ := sql.Open("sqlite", "file:"+path)
	if _, err := db.Exec(`CREATE INDEX hand_made ON assets(name)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	res, err = store.Check(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || res.StructureOK == nil || *res.StructureOK {
		t.Fatalf("hand-edited database passed: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Differences, "\n"), "+   index hand_made") && !strings.Contains(strings.Join(res.Differences, "\n"), "hand_made") {
		t.Errorf("differences do not name the extra index: %v", res.Differences)
	}
}

func TestRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ch.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "kept", Host: "kept.test", Port: 443}); err != nil {
		t.Fatal(err)
	}
	bak := filepath.Join(dir, "backup.db")
	if err := s.BackupTo(bak); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "later", Host: "later.test", Port: 443}); err != nil {
		t.Fatal(err)
	}

	// Refused while the database is in use.
	_ = s.Close()
	srv, err := store.OpenWith(path, store.OpenOptions{Exclusive: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Restore(path, bak); !errors.Is(err, store.ErrLocked) {
		t.Errorf("Restore while a server runs = %v, want ErrLocked", err)
	}
	_ = srv.Close()

	// Refuses what is not a sound CipherHorizon database.
	junk := filepath.Join(dir, "junk.db")
	_ = os.WriteFile(junk, []byte("not a database"), 0o600)
	if _, err := store.Restore(path, junk); err == nil {
		t.Error("restored a file that is not a database")
	}
	empty := filepath.Join(dir, "empty.db")
	edb, _ := sql.Open("sqlite", "file:"+empty)
	_, _ = edb.Exec(`CREATE TABLE x (a)`)
	_ = edb.Close()
	if _, err := store.Restore(path, empty); err == nil || !strings.Contains(err.Error(), "not a CipherHorizon database") {
		t.Errorf("Restore(non-CipherHorizon) = %v", err)
	}
	if _, err := store.Restore(path, path); err == nil {
		t.Error("restored a database onto itself")
	}

	res, err := store.Restore(path, bak)
	if err != nil {
		t.Fatal(err)
	}
	if res.Schema != store.SchemaVersion() || res.MovedTo == "" {
		t.Errorf("result = %+v", res)
	}
	if _, err := os.Stat(res.MovedTo); err != nil {
		t.Errorf("the replaced database was not kept: %v", err)
	}
	if _, err := os.Stat(bak); err != nil {
		t.Errorf("the backup itself is gone: %v", err)
	}
	s, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	as, err := s.ListAssets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Name != "kept" {
		t.Errorf("after restore: %d assets (%v), want only the one in the backup", len(as), as)
	}
}

// ---- helpers -------------------------------------------------------------------------------------

func schemaOn(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func schemaDumpOf(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	rows, err := db.Query(`SELECT type || ' ' || name || ' ' || COALESCE(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck // test
	var b strings.Builder
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		b.WriteString(s + "\n")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM assets`).Scan(&n)
	b.WriteString("assets " + string(rune('0'+n)))
	return b.String()
}
