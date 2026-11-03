package store

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/osfile"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
)

// Upgrading a database (PRD-016 §5). Every command that opens the database upgrades it when it is
// older than this program: serve at launch, and the user and db commands. The steps, in order:
//
//  1. take the database's lock, so no other CipherHorizon process uses it while it changes;
//  2. check there is room for a backup;
//  3. back it up (VACUUM INTO, next to it);
//  4. run each missing migration, one transaction each;
//  5. verify: SQLite's own consistency check, no new foreign-key violations, and the schema's
//     fingerprint against the one this program was built with;
//  6. record the upgrade in upgrade_log.
//
// If step 4 or 5 fails, the database is put back exactly as it was (from the step-3 backup) and the
// program refuses to start, saying why. Nothing is ever left half-upgraded.

// MigrateMode says what Open does with an older database.
type MigrateMode int

const (
	// MigrateAuto upgrades it (the default).
	MigrateAuto MigrateMode = iota
	// MigrateRefuse leaves it alone and fails with *MigrationNeededError, for sites whose change
	// control wants the upgrade run as its own step (cipherhorizon db migrate).
	MigrateRefuse
)

// OpenOptions changes how OpenWith opens a database. The zero value is what Open does.
type OpenOptions struct {
	// Exclusive holds the database's lock for as long as the Store is open: a server takes it, so
	// a second server (or an upgrade by another version) on the same file is refused.
	Exclusive bool
	// Migrate says whether an older database is upgraded.
	Migrate MigrateMode
}

// MigrationNeededError is returned under MigrateRefuse when the database is older than this program.
type MigrationNeededError struct {
	Path       string
	Have, Want int
}

func (e *MigrationNeededError) Error() string {
	return fmt.Sprintf("store: %s is at schema %d and this program needs %d; it was not changed. Upgrade it with: cipherhorizon db migrate --db %s", e.Path, e.Have, e.Want, e.Path)
}

// SchemaVersion is the database schema this program reads and writes.
func SchemaVersion() int { return len(migrations) }

// backupHeadroom is the space a backup needs beyond the database's own size: VACUUM INTO writes a
// compacted copy, never larger than the original, plus its journal while it works.
const backupHeadroom = 16 << 20

// upgradeResult is what migrate leaves for OpenWith to finish.
type upgradeResult struct {
	restoreFrom string    // a backup to put back because the upgrade failed
	lock        *fileLock // taken for the upgrade alone; OpenWith releases it when done
}

func (s *Store) migrate(o OpenOptions) (res upgradeResult, err error) {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return res, err
	}
	have, err := schemaOf(s.db)
	if err != nil {
		return res, err
	}
	want := len(migrations)
	if have > want {
		return res, fmt.Errorf("store: database schema version %d is newer than this program understands (%d); run the newer version, or restore a backup made before the upgrade (cipherhorizon db restore)", have, want)
	}
	if have == want {
		return res, nil
	}
	if have > 0 && o.Migrate == MigrateRefuse {
		return res, &MigrationNeededError{Path: s.path, Have: have, Want: want}
	}
	if s.lock == nil && lockable(s.path) {
		l, err := acquireLock(s.path)
		if err != nil {
			return res, fmt.Errorf("store: not upgrading the database from schema %d to %d: %w", have, want, err)
		}
		res.lock = l
	}

	var fkBefore int
	if have > 0 {
		// An existing database is about to change shape: keep a copy first (SR-10). If the copy
		// cannot be made, nothing is changed.
		if err := s.checkBackupSpace(); err != nil {
			return res, fmt.Errorf("store: cannot back up %s before upgrading it from schema %d, so it was not changed: %w", s.path, have, err)
		}
		dst, err := s.backup(have)
		if err != nil {
			return res, fmt.Errorf("store: cannot back up %s before migrating from version %d, so it was not changed: %w", s.path, have, err)
		}
		// Violations already in the file are not this upgrade's doing and must not block it; new ones are.
		if fkBefore, err = countFKViolations(s.db); err != nil {
			return res, err
		}
		res.restoreFrom = dst // until the upgrade has succeeded
	}

	for v := have + 1; v <= want; v++ {
		if err := s.applyStep(v); err != nil {
			return res, err
		}
	}

	if have > 0 {
		if err := s.verifyUpgrade(fkBefore); err != nil {
			return res, fmt.Errorf("store: the upgrade from schema %d to %d failed its checks: %w", have, want, err)
		}
	}
	backup := res.restoreFrom
	res.restoreFrom = ""
	s.checkFingerprint(have)
	if _, err := s.db.Exec(`INSERT INTO upgrade_log (at, from_schema, to_schema, app_version, backup) VALUES (?, ?, ?, ?, ?)`,
		ts(s.now()), have, want, version.Version, backup); err != nil {
		s.notice("could not record the upgrade in upgrade_log", "err", err.Error())
	}
	if have > 0 {
		s.notice("upgraded the database", "from_schema", have, "to_schema", want, "version", version.Version, "backup", backup)
	}
	return res, nil
}

// applyStep runs migration v and its Go step, if any, in one transaction.
func (s *Store) applyStep(v int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(migrations[v-1]); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: migration %d: %w", v, err)
	}
	if post := postMigrations[v]; post != nil {
		if err := post(tx, s.now()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", v, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, v, ts(s.now())); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// verifyUpgrade runs after the last step: the file is consistent and the upgrade added no
// foreign-key violations.
func (s *Store) verifyUpgrade(fkBefore int) error {
	msgs, err := integrity(s.db, "quick_check")
	if err != nil {
		return err
	}
	if len(msgs) > 0 {
		return fmt.Errorf("SQLite reports the file inconsistent: %s", strings.Join(msgs, "; "))
	}
	after, err := countFKViolations(s.db)
	if err != nil {
		return err
	}
	if after > fkBefore {
		return fmt.Errorf("%d rows now point at rows that do not exist (%d before)", after, fkBefore)
	}
	return nil
}

// checkFingerprint compares the schema with the one this program was built with. A difference after
// an upgrade means the file did not come only from released migrations (an early pre-release build, or
// a hand edit). It is reported, not refused: such a file has worked with every release so far, and
// refusing would lock its owner out. cipherhorizon db check reports it too.
func (s *Store) checkFingerprint(from int) {
	sum, _, err := schemaFingerprint(s.db)
	if err != nil {
		s.notice("could not read the schema to check it", "err", err.Error())
		return
	}
	if sum != schemaFingerprintWant {
		s.notice("the database's structure differs from what this version expects; it still works, but run cipherhorizon db check and report the output",
			"from_schema", from, "fingerprint", sum, "expected", schemaFingerprintWant)
	}
}

// checkBackupSpace refuses when the backup would not fit next to the database.
func (s *Store) checkBackupSpace() error {
	need := int64(backupHeadroom)
	for _, p := range []string{s.path, s.path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			need += fi.Size()
		}
	}
	free, err := osfile.FreeBytes(filepath.Dir(s.path))
	if err != nil {
		return nil //nolint:nilerr // unknown free space: try, and let VACUUM INTO fail if it must
	}
	if free < uint64(need) {
		return fmt.Errorf("the backup needs about %s free next to it and only %s is left; free some space and start again", humanBytes(uint64(need)), humanBytes(free))
	}
	return nil
}

func humanBytes(n uint64) string {
	const mib = 1 << 20
	if n < 10*mib {
		return fmt.Sprintf("%.1f MiB", float64(n)/mib)
	}
	return fmt.Sprintf("%d MiB", n/mib)
}

// ---- reading a database without changing it ------------------------------------------------------

type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// schemaOf reads the schema version (0 for a database with no migrations table).
func schemaOf(q queryer) (int, error) {
	var have int
	err := q.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&have)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return 0, nil
	}
	return have, err
}

// integrity runs PRAGMA quick_check or integrity_check and returns its complaints (none when "ok").
func integrity(q queryer, pragma string) ([]string, error) {
	rows, err := q.Query(`PRAGMA ` + pragma + `(20)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		if m != "ok" {
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

func countFKViolations(q queryer) (int, error) {
	rows, err := q.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return 0, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}

// schemaFingerprint describes the schema structurally — every table's columns, keys and indexes,
// every trigger and view — one line each, and hashes the lines. Two databases with the same
// fingerprint have the same shape however they got there.
func schemaFingerprint(q queryer) (string, []string, error) {
	var lines []string
	objs, err := collect(q, `SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master
		WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY type, name`, 4)
	if err != nil {
		return "", nil, err
	}
	for _, o := range objs {
		typ, name, tbl, text := o[0], o[1], o[2], strings.Join(strings.Fields(o[3]), " ")
		switch typ {
		case "table":
			lines = append(lines, "table "+name)
			cols, err := collect(q, `SELECT name, type, "notnull", COALESCE(dflt_value, 'NULL'), pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid`, 6, name)
			if err != nil {
				return "", nil, err
			}
			for _, c := range cols {
				lines = append(lines, "  column "+strings.Join(c, " "))
			}
			fks, err := collect(q, `SELECT "table", "from", COALESCE("to", ''), on_update, on_delete FROM pragma_foreign_key_list(?) ORDER BY id, seq`, 5, name)
			if err != nil {
				return "", nil, err
			}
			for _, f := range fks {
				lines = append(lines, "  foreign-key "+strings.Join(f, " "))
			}
			idx, err := collect(q, `SELECT name, "unique", origin, partial FROM pragma_index_list(?) ORDER BY name`, 4, name)
			if err != nil {
				return "", nil, err
			}
			for _, ix := range idx {
				cs, err := collect(q, `SELECT COALESCE(name, '<expr>'), "desc", COALESCE(coll, '') FROM pragma_index_xinfo(?) WHERE key = 1 ORDER BY seqno`, 3, ix[0])
				if err != nil {
					return "", nil, err
				}
				parts := make([]string, 0, len(cs))
				for _, c := range cs {
					parts = append(parts, strings.Join(c, ":"))
				}
				lines = append(lines, "  index "+strings.Join(ix, " ")+" ("+strings.Join(parts, ", ")+")")
			}
		case "index":
			// Columns are covered under the table; a partial index's condition and an expression
			// index's expression are only in its SQL.
			if text != "" && (strings.Contains(strings.ToUpper(text), " WHERE ") || strings.Contains(text, "(") && strings.Count(text, "(") > 1) {
				lines = append(lines, "index-sql "+name+" on "+tbl+": "+text)
			}
		default: // trigger, view
			lines = append(lines, typ+" "+name+" on "+tbl+": "+text)
		}
	}
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return fmt.Sprintf("%x", h), lines, nil
}

// collect runs a query whose columns are all read as text.
func collect(q queryer, query string, n int, args ...any) ([][]string, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, n)
		ptrs := make([]any, n)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, n)
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// openReadOnly opens a database file for reading only: nothing is created, migrated or locked.
func openReadOnly(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	esc := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
	db, err := sql.Open("sqlite", "file:"+esc+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// ---- status, check, restore -----------------------------------------------------------------------

// BackupFile is a pre-migration backup next to the database.
type BackupFile struct {
	Path     string    `json:"path"`
	Schema   int       `json:"schema"` // the schema it holds, from its name
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// UpgradeRecord is one row of upgrade_log.
type UpgradeRecord struct {
	At         time.Time `json:"at"`
	FromSchema int       `json:"fromSchema"`
	ToSchema   int       `json:"toSchema"`
	AppVersion string    `json:"appVersion"`
	Backup     string    `json:"backup,omitempty"`
}

// Status describes a database without changing it.
type Status struct {
	Path          string          `json:"path"`
	Exists        bool            `json:"exists"`
	Size          int64           `json:"size"`
	Schema        int             `json:"schema"`
	ProgramSchema int             `json:"programSchema"`
	Pending       []int           `json:"pending,omitempty"` // migrations this program would run
	Newer         bool            `json:"newer"`             // made by a newer version: this one refuses it
	StructureOK   *bool           `json:"structureOk,omitempty"`
	Backups       []BackupFile    `json:"backups"`
	Upgrades      []UpgradeRecord `json:"upgrades"`
	InUse         bool            `json:"inUse"`
	InUseBy       string          `json:"inUseBy,omitempty"`
}

// Inspect reports a database's state: its schema, what an upgrade would do, its backups and
// upgrade history, and whether a process is using it. It changes nothing and creates nothing.
func Inspect(path string) (Status, error) {
	st := Status{Path: path, ProgramSchema: len(migrations), Backups: []BackupFile{}, Upgrades: []UpgradeRecord{}}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Exists, st.Size = true, fi.Size()
	if st.InUse, st.InUseBy, err = LockHolder(path); err != nil {
		return st, err
	}
	st.Backups = listBackups(path)
	db, err := openReadOnly(path)
	if err != nil {
		return st, err
	}
	defer db.Close() //nolint:errcheck // read-only
	if st.Schema, err = schemaOf(db); err != nil {
		return st, fmt.Errorf("%s does not look like a CipherHorizon database: %w", path, err)
	}
	st.Newer = st.Schema > st.ProgramSchema
	for v := st.Schema + 1; v <= st.ProgramSchema; v++ {
		st.Pending = append(st.Pending, v)
	}
	if st.Schema == st.ProgramSchema {
		sum, _, err := schemaFingerprint(db)
		if err != nil {
			return st, err
		}
		ok := sum == schemaFingerprintWant
		st.StructureOK = &ok
	}
	rows, err := db.Query(`SELECT at, from_schema, to_schema, app_version, backup FROM upgrade_log ORDER BY id DESC LIMIT 10`)
	if err == nil {
		defer rows.Close() //nolint:errcheck // read-only
		for rows.Next() {
			var r UpgradeRecord
			var at string
			if err := rows.Scan(&at, &r.FromSchema, &r.ToSchema, &r.AppVersion, &r.Backup); err != nil {
				return st, err
			}
			if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
				r.At = *t
			}
			st.Upgrades = append(st.Upgrades, r)
		}
	}
	return st, nil
}

// listBackups finds the pre-migration backups next to a database, newest first.
func listBackups(path string) []BackupFile {
	names, _ := filepath.Glob(path + ".bak-v*")
	out := []BackupFile{}
	for _, n := range names {
		fi, err := os.Stat(n)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		b := BackupFile{Path: n, Size: fi.Size(), Modified: fi.ModTime()}
		rest := strings.TrimPrefix(n, path+".bak-v")
		if i := strings.IndexByte(rest, '-'); i > 0 {
			b.Schema, _ = strconv.Atoi(rest[:i])
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	return out
}

// CheckResult is what Check found.
type CheckResult struct {
	Schema        int      `json:"schema"`
	ProgramSchema int      `json:"programSchema"`
	Integrity     []string `json:"integrity"`             // SQLite's complaints; empty is good
	FKViolations  int      `json:"foreignKeyViolations"`  // rows pointing at rows that do not exist
	StructureOK   *bool    `json:"structureOk,omitempty"` // only judged when the schema is this program's
	Fingerprint   string   `json:"fingerprint,omitempty"`
	Differences   []string `json:"differences,omitempty"` // structure lines that differ from this program's
}

// OK reports whether the check found nothing wrong.
func (c CheckResult) OK() bool {
	return len(c.Integrity) == 0 && c.FKViolations == 0 && (c.StructureOK == nil || *c.StructureOK) && c.Schema <= c.ProgramSchema
}

// Check examines a database thoroughly without changing it: SQLite's full integrity check, foreign
// keys, and, when it is at this program's schema, its structure against this program's.
func Check(path string) (CheckResult, error) {
	res := CheckResult{ProgramSchema: len(migrations), Integrity: []string{}}
	db, err := openReadOnly(path)
	if err != nil {
		return res, err
	}
	defer db.Close() //nolint:errcheck // read-only
	if res.Schema, err = schemaOf(db); err != nil {
		return res, err
	}
	if res.Integrity, err = integrity(db, "integrity_check"); err != nil {
		return res, err
	}
	if res.FKViolations, err = countFKViolations(db); err != nil {
		return res, err
	}
	if res.Schema == res.ProgramSchema {
		sum, lines, err := schemaFingerprint(db)
		if err != nil {
			return res, err
		}
		ok := sum == schemaFingerprintWant
		res.StructureOK, res.Fingerprint = &ok, sum
		if !ok {
			res.Differences = diffLines(lines, freshSchemaLines())
		}
	}
	return res, nil
}

// freshSchemaLines builds this program's schema in memory and describes it.
func freshSchemaLines() []string {
	s, err := Open("file:fresh-schema?mode=memory")
	if err != nil {
		return nil
	}
	defer s.Close() //nolint:errcheck // in memory
	_, lines, _ := schemaFingerprint(s.db)
	return lines
}

// diffLines lists lines only in have ("+") or only in want ("-").
func diffLines(have, want []string) []string {
	in := func(xs []string) map[string]bool {
		m := make(map[string]bool, len(xs))
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	h, w := in(have), in(want)
	var out []string
	for _, x := range have {
		if !w[x] {
			out = append(out, "+ "+strings.TrimSpace(x))
		}
	}
	for _, x := range want {
		if !h[x] {
			out = append(out, "- "+strings.TrimSpace(x))
		}
	}
	return out
}

// RestoreResult says what Restore did.
type RestoreResult struct {
	Schema   int    // the schema the restored file holds; the next start upgrades it if older
	MovedTo  string // where the database it replaced was moved ("" if there was none)
	Restored string
}

// Restore puts a backup in place of the database at path. It refuses while any CipherHorizon
// process uses the database, refuses a file that is not a sound CipherHorizon database or that
// is newer than this program, and never deletes anything: the database it replaces is moved aside
// (with its -wal and -shm, so that copy stays complete).
func Restore(path, backup string) (RestoreResult, error) {
	var res RestoreResult
	if !lockable(path) {
		return res, fmt.Errorf("cannot restore into %q: name a database file", path)
	}
	if abs1, err1 := filepath.Abs(path); err1 == nil {
		if abs2, err2 := filepath.Abs(backup); err2 == nil && abs1 == abs2 {
			return res, errors.New("the backup and the database are the same file")
		}
	}
	db, err := openReadOnly(backup)
	if err != nil {
		return res, fmt.Errorf("reading the backup: %w", err)
	}
	msgs, ierr := integrity(db, "quick_check")
	v, verr := schemaOf(db)
	_ = db.Close()
	switch {
	case ierr != nil:
		return res, fmt.Errorf("the backup cannot be read as a database: %w", ierr)
	case len(msgs) > 0:
		return res, fmt.Errorf("the backup is damaged (%s); it was not restored", strings.Join(msgs, "; "))
	case verr != nil || v == 0:
		return res, errors.New("the file is not a CipherHorizon database (it has no schema version)")
	case v > len(migrations):
		return res, fmt.Errorf("the backup is at schema %d, newer than this program understands (%d); restore it with the version that made it", v, len(migrations))
	}
	l, err := acquireLock(path)
	if err != nil {
		return res, err
	}
	defer l.release()
	moved, err := replaceWith(path, backup, "replaced")
	if err != nil {
		return res, err
	}
	return RestoreResult{Schema: v, MovedTo: moved, Restored: path}, nil
}

// replaceWith copies src over path. A database already at path is first renamed to
// "<path>.<why>-<time>" together with its -wal and -shm files; that name is returned.
func replaceWith(path, src, why string) (string, error) {
	moved := ""
	if _, err := os.Stat(path); err == nil {
		moved = fmt.Sprintf("%s.%s-%s", path, why, time.Now().UTC().Format("20060102T150405Z"))
		for n := 2; ; n++ {
			if _, err := os.Stat(moved); err != nil {
				break
			}
			moved = fmt.Sprintf("%s.%s-%s-%d", path, why, time.Now().UTC().Format("20060102T150405Z"), n)
		}
		if err := os.Rename(path, moved); err != nil {
			return "", fmt.Errorf("moving the current database aside: %w", err)
		}
		for _, sfx := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(path + sfx); err == nil {
				if err := os.Rename(path+sfx, moved+sfx); err != nil {
					return moved, fmt.Errorf("moving %s aside: %w", path+sfx, err)
				}
			}
		}
	}
	tmp := path + ".restoring"
	if err := copyFile(src, tmp); err != nil {
		_ = os.Remove(tmp)
		return moved, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return moved, err
	}
	return moved, restrictFile(path)
}

// copyFile copies src to dst (created owner-only) and syncs it to disk.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // read-only
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// keepFailedUpgrades is how many copies of a database whose upgrade failed are kept for diagnosis.
// A service that restarts after each failure would otherwise leave one per attempt.
const keepFailedUpgrades = 1

// restoreAfterFailedUpgrade puts the pre-upgrade backup back after an upgrade failed. The failed file
// is kept (owner-only) as "<db>.failed-upgrade-<time>" for diagnosis; older ones are deleted.
func restoreAfterFailedUpgrade(path, backup string) (string, error) {
	moved, err := replaceWith(path, backup, "failed-upgrade")
	if err != nil {
		return moved, err
	}
	names, _ := filepath.Glob(path + ".failed-upgrade-*")
	var dbs []string
	for _, n := range names {
		if !strings.HasSuffix(n, "-wal") && !strings.HasSuffix(n, "-shm") {
			dbs = append(dbs, n)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dbs))) // the name holds the time: newest first
	for _, n := range dbs[min(keepFailedUpgrades, len(dbs)):] {
		_ = os.Remove(n)
		_ = os.Remove(n + "-wal")
		_ = os.Remove(n + "-shm")
	}
	return moved, nil
}
