package store_test

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// The upgrade promise (PRD-016 §4): any released version upgrades straight to this one. Each file in
// testdata/upgrade was written by a released binary (testing/upgrade/make-fixture.sh), so this is the
// data real installs of that version hold, not a reconstruction.

const fixtureDir = "testdata/upgrade"

var fixtureName = regexp.MustCompile(`^v\d+\.\d+\.\d+\.db$`)

func fixtures(t *testing.T) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(fixtureDir, "*.db"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	for _, n := range names {
		if !fixtureName.MatchString(filepath.Base(n)) {
			t.Errorf("%s: fixtures are named after the release that wrote them (vX.Y.Z.db)", n)
		}
	}
	return names
}

// Every release that shipped a migration has a fixture: those are the files whose upgrade differs.
func TestEveryReleaseWithAMigrationHasAFixture(t *testing.T) {
	have := map[string]bool{}
	for _, f := range fixtures(t) {
		have[strings.TrimSuffix(filepath.Base(f), ".db")] = true
	}
	lock, err := os.Open("migrations.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close() //nolint:errcheck // read-only
	sc := bufio.NewScanner(lock)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) == 3 && !strings.HasPrefix(fs[0], "#") && !have[fs[2]] {
			t.Errorf("no fixture for %s, which shipped migration %s: run testing/upgrade/make-fixture.sh %s", fs[2], fs[0], fs[2])
		}
	}
}

func TestUpgradeFromEveryRelease(t *testing.T) {
	for _, fx := range fixtures(t) {
		t.Run(filepath.Base(fx), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cipherhorizon.db")
			copyFixture(t, fx, path)
			before := snapshot(t, path)
			if before.schema == 0 || before.counts["assets"] == 0 || before.counts["scans"] == 0 {
				t.Fatalf("fixture holds too little to test: %+v", before.counts)
			}

			s, err := store.Open(path)
			if err != nil {
				t.Fatalf("upgrade from %s: %v", filepath.Base(fx), err)
			}
			// What the product reads still reads.
			as, err := s.ListAssets("")
			if err != nil || len(as) != before.counts["assets"] {
				t.Errorf("ListAssets after the upgrade: %d, %v; want %d", len(as), err, before.counts["assets"])
			}
			us, err := s.ListUsers()
			if err != nil || len(us) != before.counts["users"] {
				t.Errorf("ListUsers after the upgrade: %d, %v; want %d", len(us), err, before.counts["users"])
			}
			_ = s.Close()

			after := snapshot(t, path)
			if after.schema != store.SchemaVersion() {
				t.Fatalf("schema after the upgrade = %d, want %d", after.schema, store.SchemaVersion())
			}
			// Nothing is lost: every table keeps its rows. The estate graph (sources, entities,
			// observations) is a projection rebuilt from the documents, so only its presence is compared.
			for table, n := range before.counts {
				if projection[table] {
					if n > 0 && after.counts[table] == 0 {
						t.Errorf("%s: emptied by the upgrade (%d rows before)", table, n)
					}
					continue
				}
				if table == "schema_migrations" {
					continue
				}
				if after.counts[table] != n {
					t.Errorf("%s: %d rows before the upgrade, %d after", table, n, after.counts[table])
				}
			}
			// Evidence is never rewritten (PRD-016 §5.2), and neither are accounts or decisions.
			for what, sum := range before.content {
				if after.content[what] != sum {
					t.Errorf("%s changed in the upgrade", what)
				}
			}

			// The upgraded file is sound and has exactly the structure a fresh install has.
			res, err := store.Check(path)
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK() {
				t.Errorf("check after the upgrade: %+v", res)
			}
			st, err := store.Inspect(path)
			if err != nil {
				t.Fatal(err)
			}
			if before.schema < store.SchemaVersion() {
				if len(st.Upgrades) == 0 || st.Upgrades[0].FromSchema != before.schema || st.Upgrades[0].Backup == "" {
					t.Errorf("the upgrade is not recorded with its backup: %+v", st.Upgrades)
				} else if _, err := os.Stat(st.Upgrades[0].Backup); err != nil {
					t.Errorf("the recorded backup is missing: %v", err)
				}
			}

			// Opening again changes nothing: no second backup, no second record.
			s, err = store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			st2, _ := store.Inspect(path)
			if len(st2.Upgrades) != len(st.Upgrades) || len(st2.Backups) != len(st.Backups) {
				t.Errorf("a second open upgraded again: %d -> %d records, %d -> %d backups", len(st.Upgrades), len(st2.Upgrades), len(st.Backups), len(st2.Backups))
			}
		})
	}
}

// A database from a newer version is refused, and left exactly as it was.
func TestNewerDatabaseIsRefusedUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cipherhorizon.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := store.ForceSchemaVersion(path, store.SchemaVersion()+1); err != nil {
		t.Fatal(err)
	}
	before := fileSum(t, path)
	_, err = store.Open(path)
	if err == nil || !strings.Contains(err.Error(), "newer than this program") {
		t.Fatalf("Open(newer) = %v", err)
	}
	if fileSum(t, path) != before {
		t.Error("the newer database was changed")
	}
	if bs, _ := filepath.Glob(path + ".bak-v*"); len(bs) != 0 {
		t.Errorf("backups made of a database that was refused: %v", bs)
	}
}

// ---- helpers -------------------------------------------------------------------------------------

var projection = map[string]bool{"sources": true, "entities": true, "observations": true, "projection_state": true}

type dbSnapshot struct {
	schema  int
	counts  map[string]int
	content map[string]string // what must survive an upgrade unchanged -> hash
}

func snapshot(t *testing.T, path string) dbSnapshot {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	snap := dbSnapshot{counts: map[string]int{}, content: map[string]string{}}
	_ = db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&snap.schema)
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	_ = rows.Close()
	for _, tb := range tables {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM "` + tb + `"`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		snap.counts[tb] = n
	}
	for what, q := range map[string]string{
		"scan evidence (report_json)": `SELECT id, report_json FROM scans ORDER BY id`,
		"scan results (eval_json)":    `SELECT id, eval_json FROM scans ORDER BY id`,
		"assets":                      `SELECT id, kind, name, host, port, tags, notes FROM assets ORDER BY id`,
		"accounts":                    `SELECT id, username, role, password_hash, disabled FROM users ORDER BY id`,
		"triage decisions":            `SELECT asset_id, finding_key, status, note FROM finding_status ORDER BY asset_id, finding_key`,
		"host inventories":            `SELECT id, asset_id, cbom_json FROM host_snapshots ORDER BY id`,
	} {
		snap.content[what] = hashQuery(t, db, q)
	}
	return snap
}

func hashQuery(t *testing.T, db *sql.DB, q string) string {
	t.Helper()
	rows, err := db.Query(q)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	defer rows.Close() //nolint:errcheck // test
	cols, _ := rows.Columns()
	h := sha256.New()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			_, _ = fmt.Fprintf(h, "%v\x00", v)
		}
		_, _ = h.Write([]byte{'\n'})
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func copyFixture(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close() //nolint:errcheck // read-only
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func fileSum(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
