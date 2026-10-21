// Package store keeps assets, scans and their history in one SQLite file.
//
// It uses the pure-Go modernc.org/sqlite driver, so the program stays a single
// static binary (CGO_ENABLED=0). Invariants that matter to the product are
// enforced by the schema, not only by callers: at most one active scan per asset
// (a partial unique index), history deleted with its asset (a cascading foreign
// key), and the next queued scan claimed by a single atomic statement.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"modernc.org/sqlite" // registers the "sqlite" driver
	sqlite3 "modernc.org/sqlite/lib"
)

// Errors callers can test for.
var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
)

// Scan statuses.
const (
	StatusQueued   = "queued"
	StatusRunning  = "running"
	StatusDone     = "done"
	StatusFailed   = "failed"
	StatusCanceled = "canceled"
)

// Asset kinds.
const (
	KindTLS  = "tls-endpoint"
	KindSSH  = "ssh-endpoint" // PRD-008: an SSH server, scanned by internal/sshprobe
	KindHost = "host"
	// KindEndpoint is not stored: ListAssets reads it as every network endpoint (TLS and SSH).
	KindEndpoint = "endpoint"
)

// IsEndpoint reports whether an asset kind is a network endpoint (scanned, as opposed to a host).
func IsEndpoint(kind string) bool { return kind == KindTLS || kind == KindSSH }

// Store is the database handle. It is safe for concurrent use.
type Store struct {
	db   *sql.DB
	path string
	now  func() time.Time
	log  *slog.Logger

	// opened holds what Open did on its own (a backup, a deleted old backup) until SetLogger
	// gives it somewhere to go: Open runs before the caller has set a logger.
	noticeMu sync.Mutex
	holding  bool
	opened   [][]any

	// correlation runs are coalesced: see correlateQuietly.
	corrMu      sync.Mutex
	corrCond    *sync.Cond
	corrRunning bool
	corrWanted  uint64 // requests made so far
	corrDone    uint64 // requests covered by a finished run
}

// Open opens (creating if needed) the database at path and applies migrations.
//
// The file holds an organisation's scan results and host inventories, so it is
// created owner-only (0600) and an existing one is tightened. SQLite gives its
// -wal and -shm files the same mode as the database. On Windows the mode bits
// are not enforced and the profile's ACL applies instead.
// Every transaction is opened IMMEDIATE: a write transaction takes the write lock when it begins,
// so two of them queue behind the busy timeout instead of one failing at its first write with
// "database is locked" (a deferred transaction that read first cannot be upgraded under WAL).
func Open(path string) (*Store, error) {
	if err := restrictFile(path); err != nil {
		return nil, fmt.Errorf("store: securing %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", dsnFor(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	s := &Store{db: db, path: path, now: time.Now, log: slog.New(slog.DiscardHandler), holding: true}
	s.corrCond = sync.NewCond(&s.corrMu)
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.noticeMu.Lock()
	s.holding = false
	s.noticeMu.Unlock()
	if err := s.ensureProjection(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// dsnParams are the connection settings every connection gets.
const dsnParams = "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"

// dsnFor turns a database path into the driver's URI. A plain path is escaped, so a '?', '#' or
// '%' in a directory name is part of the name and never read as the start of URI parameters
// (which could otherwise switch off foreign keys or WAL). A path that is already a "file:" URI
// is the caller's own and only gets the parameters appended.
func dsnFor(path string) string {
	if strings.HasPrefix(path, "file:") {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return path + sep + dsnParams
	}
	esc := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
	return "file:" + esc + "?" + dsnParams
}

// SetLogger sets where the store reports what it does on its own (derived data it could not
// rebuild, maintenance that failed). Default: discarded.
func (s *Store) SetLogger(l *slog.Logger) {
	if l == nil {
		return
	}
	s.noticeMu.Lock()
	s.log = l
	held := s.opened
	s.opened = nil
	s.noticeMu.Unlock()
	for _, n := range held {
		l.Info(n[0].(string), n[1:]...)
	}
}

// notice reports something the store did on its own: logged now, or, during Open, held for the
// logger SetLogger sets.
func (s *Store) notice(msg string, args ...any) {
	s.noticeMu.Lock()
	defer s.noticeMu.Unlock()
	if s.holding {
		s.opened = append(s.opened, append([]any{msg}, args...))
		return
	}
	s.log.Info(msg, args...)
}

// SetClock replaces the time source (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

var migrations = []string{
	// 1: initial schema
	`CREATE TABLE assets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT NOT NULL,
		name TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 0,
		tags TEXT NOT NULL DEFAULT '[]',
		notes TEXT NOT NULL DEFAULT '',
		interval_seconds INTEGER NOT NULL DEFAULT 0,
		next_scan_at TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		UNIQUE (kind, host, port)
	);
	CREATE TABLE scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		status TEXT NOT NULL,
		trigger TEXT NOT NULL,
		stage TEXT NOT NULL DEFAULT '',
		progress_pct INTEGER NOT NULL DEFAULT 0,
		connections INTEGER NOT NULL DEFAULT 0,
		queued_at TEXT NOT NULL,
		started_at TEXT,
		finished_at TEXT,
		error TEXT NOT NULL DEFAULT '',
		report_json BLOB,
		eval_json BLOB,
		grade TEXT NOT NULL DEFAULT '',
		readiness_level INTEGER,
		hndl_exposed INTEGER NOT NULL DEFAULT 0,
		crit INTEGER NOT NULL DEFAULT 0,
		high INTEGER NOT NULL DEFAULT 0,
		medium INTEGER NOT NULL DEFAULT 0,
		cert_not_after TEXT,
		incomplete INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX scans_asset ON scans(asset_id, id DESC);
	CREATE INDEX scans_status ON scans(status, id);
	CREATE UNIQUE INDEX one_active_scan ON scans(asset_id) WHERE status IN ('queued','running');
	CREATE TABLE scan_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		at TEXT NOT NULL,
		message TEXT NOT NULL
	);
	CREATE INDEX scan_events_scan ON scan_events(scan_id, id);
	CREATE TABLE host_snapshots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		at TEXT NOT NULL,
		cbom_json BLOB NOT NULL,
		summary_json BLOB NOT NULL
	);
	CREATE INDEX host_snapshots_asset ON host_snapshots(asset_id, id DESC);`,
	// 2: the TLS hygiene rating replaces the earlier letter grade. Old letters are not carried over:
	// they came from a different scale, so a scan made before this migration shows no rating until it is repeated.
	`ALTER TABLE scans RENAME COLUMN grade TO band;
	ALTER TABLE scans ADD COLUMN score INTEGER NOT NULL DEFAULT -1;
	UPDATE scans SET band = '';`,
	// 3: finding triage (a decision persists across rescans instead of being
	// silently recomputed away) and user-asserted links between a TLS endpoint
	// asset and a host asset that are known to be the same machine. A link is
	// never inferred by the product itself, only recorded when a person says so.
	`CREATE TABLE finding_status (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		finding_key TEXT NOT NULL,
		status TEXT NOT NULL,
		note TEXT NOT NULL DEFAULT '',
		set_at TEXT NOT NULL,
		PRIMARY KEY (asset_id, finding_key)
	);
	CREATE TABLE asset_links (
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		linked_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		created_at TEXT NOT NULL,
		PRIMARY KEY (asset_id, linked_asset_id),
		CHECK (asset_id != linked_asset_id)
	);`,
	// 4: the estate model (PRD-003, ENG-HANDOFF-002). A system is the owned unit that
	// carries the operator's metadata; every asset belongs to one (backfilled below, one
	// per asset, joining assets a person had already linked). sources say where a
	// projection came from; entities and observations are that projection. The raw
	// documents in scans and host_snapshots stay the source of truth and are never
	// rewritten, so entities and observations can be dropped and rebuilt (REQ-MOD-1).
	// audit_log is append-only, enforced by triggers (SR-11).
	`CREATE TABLE systems (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		owner TEXT NOT NULL DEFAULT '',
		environment TEXT NOT NULL DEFAULT '',
		criticality TEXT NOT NULL DEFAULT '',
		exposure TEXT NOT NULL DEFAULT '',
		data_lifetime_years INTEGER,
		fisma_id TEXT NOT NULL DEFAULT '',
		fips199 TEXT NOT NULL DEFAULT '',
		hva_id TEXT NOT NULL DEFAULT '',
		hosting TEXT NOT NULL DEFAULT '',
		hosting_provider TEXT NOT NULL DEFAULT '',
		notes TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	ALTER TABLE assets ADD COLUMN system_id INTEGER REFERENCES systems(id);
	CREATE INDEX assets_system ON assets(system_id);
	-- who a host upload is attributed to: legacy rows start as imported (safe) and the backfill upgrades
	-- those whose recorded producer is this product.
	ALTER TABLE host_snapshots ADD COLUMN source_class TEXT NOT NULL DEFAULT 'imported';
	ALTER TABLE host_snapshots ADD COLUMN submitted_by TEXT NOT NULL DEFAULT '';
	CREATE TABLE sources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		class TEXT NOT NULL CHECK (class IN ('scanner','collector','imported','operator')),
		stream TEXT NOT NULL CHECK (stream IN ('host','network','imported')),
		ref_kind TEXT NOT NULL CHECK (ref_kind IN ('scan','host_snapshot','import')),
		ref_id INTEGER NOT NULL,
		asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
		system_id INTEGER REFERENCES systems(id) ON DELETE CASCADE,
		tool_name TEXT NOT NULL DEFAULT '',
		tool_version TEXT NOT NULL DEFAULT '',
		sha256 TEXT NOT NULL DEFAULT '',
		size INTEGER NOT NULL DEFAULT 0,
		received_at TEXT NOT NULL,
		observed_at TEXT NOT NULL,
		submitted_by TEXT NOT NULL DEFAULT '',
		subject_claim TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','withdrawn')),
		is_current INTEGER NOT NULL DEFAULT 1,
		not_interpreted_json TEXT NOT NULL DEFAULT '{}',
		UNIQUE (ref_kind, ref_id)
	);
	CREATE INDEX sources_asset ON sources(asset_id, is_current);
	CREATE TABLE entities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT NOT NULL,
		key TEXT NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		attrs_json TEXT NOT NULL DEFAULT '{}',
		UNIQUE (kind, key)
	);
	CREATE TABLE observations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
		entity_id INTEGER NOT NULL REFERENCES entities(id),
		relation TEXT NOT NULL,
		via TEXT NOT NULL DEFAULT '',
		rung TEXT NOT NULL,
		class INTEGER NOT NULL,
		method TEXT NOT NULL CHECK (method <> ''),
		quality TEXT NOT NULL,
		observed_at TEXT NOT NULL,
		attrs_json TEXT NOT NULL DEFAULT '{}'
	);
	CREATE INDEX observations_entity ON observations(entity_id);
	CREATE INDEX observations_source ON observations(source_id);
	CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		at TEXT NOT NULL,
		actor TEXT NOT NULL,
		object_kind TEXT NOT NULL,
		object_id INTEGER NOT NULL,
		action TEXT NOT NULL,
		before_json TEXT NOT NULL DEFAULT '{}',
		after_json TEXT NOT NULL DEFAULT '{}',
		reason TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX audit_object ON audit_log(object_kind, object_id, id);
	CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
	CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
	CREATE TABLE projection_state (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		version INTEGER NOT NULL,
		built_at TEXT NOT NULL,
		stale INTEGER NOT NULL DEFAULT 0
	);
	INSERT INTO projection_state (id, version, built_at, stale) VALUES (1, 0, '', 1);`,
	// 5: third-party CBOM imports (PRD-003 REQ-ING). The raw document is kept as uploaded; what it
	// contributed to the graph is a projection of it, rebuilt like the others. The operator's
	// choice of system, the producer the document claims, and who submitted it live on its source.
	`CREATE TABLE imports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sha256 TEXT NOT NULL UNIQUE,
		spec_version TEXT NOT NULL,
		profile TEXT NOT NULL,
		kind TEXT NOT NULL CHECK (kind IN ('static-source','host','generic')),
		cbom_json BLOB NOT NULL,
		created_at TEXT NOT NULL
	);`,
	// 6: correlation links (PRD-003 REQ-COR). A link says an asset belongs to a system, why (the rules
	// that fired and the values that matched), how strongly (a fixed table), and who decided. Manual
	// links of 0.1.0 become confirmed links in the backfill.
	`CREATE TABLE links (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		system_id INTEGER NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
		state TEXT NOT NULL CHECK (state IN ('proposed','confirmed','rejected')),
		strength TEXT NOT NULL CHECK (strength IN ('strong','medium','weak')),
		rules_json TEXT NOT NULL DEFAULT '[]',
		evidence_json TEXT NOT NULL DEFAULT '{}',
		stale INTEGER NOT NULL DEFAULT 0,
		decided_by TEXT NOT NULL DEFAULT '',
		decided_at TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		UNIQUE (asset_id, system_id)
	);
	CREATE INDEX links_state ON links(state);`,
	// 7: private trust anchors per system (PRD-004 REQ-TTRS-2). Certificates only, as PEM;
	// at most MaxAnchorsPerSystem per system, enforced on insert.
	`CREATE TABLE trust_anchors (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		system_id INTEGER NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
		sha256 TEXT NOT NULL,
		subject TEXT NOT NULL,
		not_after TEXT NOT NULL,
		pem TEXT NOT NULL,
		added_at TEXT NOT NULL,
		added_by TEXT NOT NULL,
		UNIQUE (system_id, sha256)
	);`,
	// 8: low and informational finding counts, so a list can say how many findings a result has
	// (not only the critical, high and medium ones). Filled from the stored evaluations.
	`ALTER TABLE scans ADD COLUMN low INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE scans ADD COLUMN info INTEGER NOT NULL DEFAULT 0;`,
	// 9: accounts and sign-in (ADR-0018). A password is stored only as a salted PBKDF2 hash; a
	// session only as the SHA-256 of its token, so a copy of the database signs nobody in.
	`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		display_name TEXT NOT NULL DEFAULT '',
		role TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
		password_hash TEXT NOT NULL,
		disabled INTEGER NOT NULL DEFAULT 0,
		must_change INTEGER NOT NULL DEFAULT 0,
		failed_count INTEGER NOT NULL DEFAULT 0,
		locked_until TEXT,
		created_at TEXT NOT NULL,
		created_by TEXT NOT NULL DEFAULT '',
		password_changed_at TEXT NOT NULL,
		last_login_at TEXT
	);
	CREATE TABLE sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash TEXT NOT NULL UNIQUE,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		created_at TEXT NOT NULL,
		last_seen_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		client TEXT NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX sessions_user ON sessions(user_id);
	CREATE TABLE auth_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		at TEXT NOT NULL,
		kind TEXT NOT NULL,
		username TEXT NOT NULL DEFAULT '',
		actor TEXT NOT NULL DEFAULT '',
		client TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX auth_events_at ON auth_events(at);`,
	// 10: every stored time is rewritten in the fixed-width form ts now writes (nine fractional
	// digits, always). The earlier RFC 3339 "nano" form dropped trailing zeros, so its strings did
	// not sort as the times do ("...05Z" after "...05.3Z") and comparisons in SQL were off within a
	// second. The rewrite is Go (backfillTimestamps); the SQL step only records the version.
	`UPDATE projection_state SET built_at = built_at WHERE id = 1;`,
	// 11: who started a scan (PRD-007 REQ-AC-4): a person's user name, "api-token" or "schedule".
	// Earlier scans keep an empty value, shown as not recorded. audit_log gains an index by time
	// for the Activity list (REQ-AC-3).
	// An endpoint's STARTTLS choice (REQ-SX-3): "auto" (by well-known port), "none" or a protocol.
	`ALTER TABLE scans ADD COLUMN started_by TEXT NOT NULL DEFAULT '';
	CREATE INDEX audit_log_at ON audit_log(at);
	ALTER TABLE assets ADD COLUMN starttls TEXT NOT NULL DEFAULT 'auto';`,
	// 12: server settings a person changes in the interface (UX-REVIEW-008 S3). Sign-in is off by
	// default; a database that already has accounts keeps it on, so an upgrade never opens a server.
	`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
	INSERT INTO settings (key, value) SELECT 'sign_in', 'on' WHERE EXISTS (SELECT 1 FROM users);`,
	// 13: SSH endpoints (PRD-008, ADR-0019). Assets gain no column: an SSH endpoint is kind
	// 'ssh-endpoint'. A scan keeps, for lists, the SSH server's software and default host key type;
	// both stay empty for TLS.
	`ALTER TABLE scans ADD COLUMN service TEXT NOT NULL DEFAULT '';
	ALTER TABLE scans ADD COLUMN host_key TEXT NOT NULL DEFAULT '';`,
	// 14: an SSH server's baseline verdict, for lists (PRD-008 REQ-SHB-5): the baseline id, whether
	// the server meets it (NULL when not judged, and for TLS) and how many changes it needs.
	`ALTER TABLE scans ADD COLUMN baseline TEXT NOT NULL DEFAULT '';
	ALTER TABLE scans ADD COLUMN baseline_meets INTEGER;
	ALTER TABLE scans ADD COLUMN baseline_changes INTEGER NOT NULL DEFAULT 0;`,
	// 15: the TLS hygiene bands are renamed (PRD-011 REQ-UXF-1), so that Strong and Weak belong to suite
	// strength alone. Every stored scan's band is carried over to its new name; the score is unchanged.
	`UPDATE scans SET band = CASE band WHEN 'Strong' THEN 'Excellent' WHEN 'Sound' THEN 'Good'
		WHEN 'Weak' THEN 'Poor' WHEN 'Broken' THEN 'Failing' ELSE band END;`,
}

// postMigrations are steps that need Go rather than SQL. They run inside the same
// transaction as the migration with the same number.
var postMigrations = map[int]func(tx *sql.Tx, now time.Time) error{
	4:  backfillSystems,
	6:  backfillLinks,
	8:  backfillLowInfo,
	10: backfillTimestamps,
}

// Finding triage statuses. "Resolved" is never one of these: it is not a
// decision to persist, it is what a finding_status row becomes, unprompted,
// the moment its finding stops appearing in an asset's latest result — the
// product will not let a user assert "fixed" while it still observes the
// problem.
const (
	FindingAcknowledged = "acknowledged"
	FindingAcceptedRisk = "accepted-risk"
)

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	var have int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&have); err != nil {
		return err
	}
	if have > len(migrations) {
		return fmt.Errorf("store: database schema version %d is newer than this program understands (%d)", have, len(migrations))
	}
	if have > 0 && have < len(migrations) {
		// An existing database is about to change shape: keep a copy first (SR-10). If the
		// copy cannot be made, nothing is changed.
		if err := s.backup(have); err != nil {
			return fmt.Errorf("store: cannot back up %s before migrating from version %d, so it was not changed: %w", s.path, have, err)
		}
	}
	for v := have + 1; v <= len(migrations); v++ {
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
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---- time helpers --------------------------------------------------------------------

// tsLayout is how every time is stored: UTC, always nine fractional digits, so that comparing
// and sorting the strings in SQL agrees with comparing the times.
const tsLayout = "2006-01-02T15:04:05.000000000Z07:00"

func ts(t time.Time) string { return t.UTC().Format(tsLayout) }

// timestampColumns are every column holding a time written by ts (migration 10 rewrites them).
var timestampColumns = map[string][]string{
	"asset_links":       {"created_at"},
	"assets":            {"created_at", "next_scan_at", "updated_at"},
	"audit_log":         {"at"},
	"auth_events":       {"at"},
	"finding_status":    {"set_at"},
	"host_snapshots":    {"at"},
	"imports":           {"created_at"},
	"links":             {"created_at", "decided_at", "updated_at"},
	"observations":      {"observed_at"},
	"projection_state":  {"built_at"},
	"scan_events":       {"at"},
	"scans":             {"cert_not_after", "finished_at", "queued_at", "started_at"},
	"sessions":          {"created_at", "expires_at", "last_seen_at"},
	"sources":           {"observed_at", "received_at"},
	"systems":           {"created_at", "updated_at"},
	"trust_anchors":     {"added_at", "not_after"},
	"users":             {"created_at", "last_login_at", "locked_until", "password_changed_at"},
	"schema_migrations": {"applied_at"},
}

// backfillTimestamps rewrites stored times into tsLayout (migration 10). A value that does not
// parse as RFC 3339 is left as it is. audit_log is append-only by trigger, so its triggers are
// lifted for the rewrite (the same transaction recreates them): the rows keep their meaning,
// only the spelling of the time changes.
func backfillTimestamps(tx *sql.Tx, _ time.Time) error {
	if _, err := tx.Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		return err
	}
	for table, cols := range timestampColumns {
		for _, col := range cols {
			if err := reformatColumnTx(tx, table, col); err != nil {
				return fmt.Errorf("%s.%s: %w", table, col, err)
			}
		}
	}
	_, err := tx.Exec(`CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END`)
	return err
}

func reformatColumnTx(tx *sql.Tx, table, col string) error {
	// table and col come from timestampColumns, a constant list, never from input.
	rows, err := tx.Query(`SELECT rowid, ` + col + ` FROM ` + table + ` WHERE ` + col + ` IS NOT NULL AND ` + col + ` <> ''`) //nolint:gosec // constant identifiers
	if err != nil {
		return err
	}
	type change struct {
		id  int64
		val string
	}
	var changes []change
	for rows.Next() {
		var id int64
		var v string
		if err := rows.Scan(&id, &v); err != nil {
			_ = rows.Close()
			return err
		}
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil && ts(t) != v {
			changes = append(changes, change{id, ts(t)})
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`UPDATE ` + table + ` SET ` + col + ` = ? WHERE rowid = ?`) //nolint:gosec // constant identifiers
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck // closed with the transaction
	for _, c := range changes {
		if _, err := stmt.Exec(c.val, c.id); err != nil {
			return err
		}
	}
	return nil
}

func parseTS(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s.String)
	if err != nil {
		return nil
	}
	return &t
}

func nullTS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

// isConstraint reports whether err is an SQLite constraint violation (unique, foreign key,
// check, ...), by its result code rather than by its message.
func isConstraint(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT
}

// ---- types ---------------------------------------------------------------------------------

// Asset is something to scan.
type Asset struct {
	ID              int64      `json:"id"`
	SystemID        int64      `json:"systemId"`
	Kind            string     `json:"kind"`
	Name            string     `json:"name"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	StartTLS        string     `json:"starttls"` // "auto" (by well-known port), "none" or a protocol
	Tags            []string   `json:"tags"`
	Notes           string     `json:"notes"`
	IntervalSeconds int        `json:"intervalSeconds"`
	NextScanAt      *time.Time `json:"nextScanAt"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`

	// Latest is the most recent scan of any status (what is happening now);
	// LastDone is the most recent completed scan (what is currently known).
	Latest   *ScanSummary `json:"latest"`
	LastDone *ScanSummary `json:"lastDone"`
}

// Address is host:port as the user thinks of it.
func (a Asset) Address() string {
	if a.Port == 0 {
		return a.Host
	}
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

// ScanSummary is a scan without its (large) report and evaluation.
type ScanSummary struct {
	ID             int64      `json:"id"`
	AssetID        int64      `json:"assetId"`
	Status         string     `json:"status"`
	Trigger        string     `json:"trigger"`
	StartedBy      string     `json:"startedBy"` // a user name, "api-token", "schedule", or "" (before 1.0)
	Stage          string     `json:"stage"`
	ProgressPct    int        `json:"progressPct"`
	Connections    int        `json:"connections"`
	QueuedAt       time.Time  `json:"queuedAt"`
	StartedAt      *time.Time `json:"startedAt"`
	FinishedAt     *time.Time `json:"finishedAt"`
	Error          string     `json:"error"`
	Band           string     `json:"band"`  // TLS hygiene band, e.g. Strong; empty until a scan completes
	Score          int        `json:"score"` // TLS hygiene score 0-100; -1 when not rated
	ReadinessLevel *int       `json:"readinessLevel"`
	HNDLExposed    bool       `json:"hndlExposed"`
	Critical       int        `json:"critical"`
	High           int        `json:"high"`
	Medium         int        `json:"medium"`
	Low            int        `json:"low"`
	Info           int        `json:"info"`
	CertNotAfter   *time.Time `json:"certNotAfter"`
	Incomplete     bool       `json:"incomplete"`
	// Service and HostKey describe an SSH endpoint for lists ("OpenSSH_10.0", "Ed25519"); empty for TLS.
	Service string `json:"service"`
	HostKey string `json:"hostKey"`
	// Baseline, BaselineMeets and BaselineChanges are an SSH server's baseline verdict (PRD-008
	// WP-G); BaselineMeets is nil when the server was not judged, and for TLS.
	Baseline        string `json:"baseline,omitempty"`
	BaselineMeets   *bool  `json:"baselineMeets,omitempty"`
	BaselineChanges int    `json:"baselineChanges,omitempty"`
}

// Result is what a finished scan stores.
type Result struct {
	Report         []byte
	Evaluation     []byte
	Band           string
	Score          int
	ReadinessLevel int
	HNDLExposed    bool
	Critical       int
	High           int
	Medium         int
	Low            int
	Info           int
	CertNotAfter   *time.Time
	Incomplete     bool
	Service        string
	HostKey        string
	// The SSH baseline verdict (ScanSummary has the meanings).
	Baseline        string
	BaselineMeets   *bool
	BaselineChanges int
	// FinalEvent, if set, is logged with the result in one transaction.
	FinalEvent string
}

// Event is one line of a scan's progress log.
type Event struct {
	At      time.Time `json:"at"`
	Message string    `json:"message"`
}

func encodeTags(tags []string) string {
	if tags == nil {
		tags = []string{}
	}
	b, _ := json.Marshal(tags)
	return string(b)
}

func decodeTags(s string) []string {
	var t []string
	if err := json.Unmarshal([]byte(s), &t); err != nil || t == nil {
		return []string{}
	}
	return t
}

// ---- assets --------------------------------------------------------------------------------

const assetCols = `id, COALESCE(system_id, 0), kind, name, host, port, tags, notes, interval_seconds, next_scan_at, created_at, updated_at, starttls`

type scanner interface{ Scan(dest ...any) error }

func scanAsset(r scanner) (Asset, error) {
	var a Asset
	var tags, created, updated string
	var next sql.NullString
	if err := r.Scan(&a.ID, &a.SystemID, &a.Kind, &a.Name, &a.Host, &a.Port, &tags, &a.Notes, &a.IntervalSeconds, &next, &created, &updated, &a.StartTLS); err != nil {
		return Asset{}, err
	}
	a.Tags = decodeTags(tags)
	a.NextScanAt = parseTS(next)
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		a.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		a.UpdatedAt = *t
	}
	return a, nil
}

// CreateAsset inserts an asset, and the system it belongs to. It returns
// ErrDuplicate if the same kind, host and port already exist.
func (s *Store) CreateAsset(a Asset) (Asset, error) {
	now := ts(s.now())
	tx, err := s.db.Begin()
	if err != nil {
		return Asset{}, err
	}
	defer func() { _ = tx.Rollback() }()
	sys, err := tx.Exec(`INSERT INTO systems (name, created_at, updated_at) VALUES (?, ?, ?)`, a.Name, now, now)
	if err != nil {
		return Asset{}, err
	}
	sysID, _ := sys.LastInsertId()
	if a.StartTLS == "" {
		a.StartTLS = "auto"
	}
	res, err := tx.Exec(`INSERT INTO assets (kind, name, host, port, tags, notes, interval_seconds, created_at, updated_at, system_id, starttls)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`, a.Kind, a.Name, a.Host, a.Port, encodeTags(a.Tags), a.Notes, now, now, sysID, a.StartTLS)
	if isConstraint(err) {
		return Asset{}, ErrDuplicate
	}
	if err != nil {
		return Asset{}, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	return s.GetAsset(id)
}

// GetAsset returns one asset with its latest scans.
func (s *Store) GetAsset(id int64) (Asset, error) {
	a, err := scanAsset(s.db.QueryRow(`SELECT `+assetCols+` FROM assets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, err
	}
	if err := s.attachLatest([]*Asset{&a}); err != nil {
		return Asset{}, err
	}
	return a, nil
}

// FindAsset looks an asset up by its natural key.
func (s *Store) FindAsset(kind, host string, port int) (Asset, error) {
	a, err := scanAsset(s.db.QueryRow(`SELECT `+assetCols+` FROM assets WHERE kind = ? AND host = ? AND port = ?`, kind, host, port))
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	return a, err
}

// ListAssets returns every asset, newest first, with their latest scans.
func (s *Store) ListAssets(kind string) ([]Asset, error) {
	q := `SELECT ` + assetCols + ` FROM assets`
	var args []any
	switch kind {
	case "":
	case KindEndpoint:
		q += ` WHERE kind IN (?, ?)`
		args = append(args, KindTLS, KindSSH)
	default:
		q += ` WHERE kind = ?`
		args = append(args, kind)
	}
	q += ` ORDER BY id DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	ptrs := make([]*Asset, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	if err := s.attachLatest(ptrs); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Asset{}
	}
	return out, nil
}

// AssetPatch changes editable fields; nil means "leave as is".
type AssetPatch struct {
	Name            *string
	Tags            *[]string
	Notes           *string
	IntervalSeconds *int
	StartTLS        *string
}

// UpdateAsset applies a patch. Setting an interval schedules the next scan.
func (s *Store) UpdateAsset(id int64, p AssetPatch) (Asset, error) {
	// Read and write in one (immediate) transaction, so two concurrent edits of different
	// fields cannot overwrite each other with what each read before the other wrote.
	tx, err := s.db.Begin()
	if err != nil {
		return Asset{}, err
	}
	defer func() { _ = tx.Rollback() }()
	a, err := scanAsset(tx.QueryRow(`SELECT `+assetCols+` FROM assets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, err
	}
	if p.Name != nil {
		a.Name = *p.Name
	}
	if p.Tags != nil {
		a.Tags = *p.Tags
	}
	if p.Notes != nil {
		a.Notes = *p.Notes
	}
	if p.StartTLS != nil {
		a.StartTLS = *p.StartTLS
	}
	var next *time.Time
	if p.IntervalSeconds != nil {
		a.IntervalSeconds = *p.IntervalSeconds
		if a.IntervalSeconds > 0 {
			t := s.now().Add(time.Duration(a.IntervalSeconds) * time.Second)
			next = &t
		}
	} else {
		next = a.NextScanAt
	}
	_, err = tx.Exec(`UPDATE assets SET name = ?, tags = ?, notes = ?, interval_seconds = ?, next_scan_at = ?, updated_at = ?, starttls = ? WHERE id = ?`,
		a.Name, encodeTags(a.Tags), a.Notes, a.IntervalSeconds, nullTS(next), ts(s.now()), a.StartTLS, id)
	if err != nil {
		return Asset{}, err
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, err
	}
	return s.GetAsset(id)
}

// DeleteAsset removes an asset and, by cascade, its scans, events and observations.
// The system it belonged to goes too, unless something else still needs it: another
// asset, an imported source, or anything a person recorded about it.
func (s *Store) DeleteAsset(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var sysID int64
	if err := tx.QueryRow(`SELECT COALESCE(system_id, 0) FROM assets WHERE id = ?`, id).Scan(&sysID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM assets WHERE id = ?`, id); err != nil {
		return err
	}
	if sysID != 0 {
		if err := pruneSystemIfEmpty(tx, sysID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const scanCols = `id, asset_id, status, trigger, started_by, stage, progress_pct, connections, queued_at, started_at, finished_at, error,
	band, score, readiness_level, hndl_exposed, crit, high, medium, low, info, cert_not_after, incomplete, service, host_key,
	baseline, baseline_meets, baseline_changes`

func scanSummary(r scanner) (ScanSummary, error) {
	var v ScanSummary
	var queued string
	var started, finished, certEnd sql.NullString
	var level, meets sql.NullInt64
	var hndl, incomplete int
	if err := r.Scan(&v.ID, &v.AssetID, &v.Status, &v.Trigger, &v.StartedBy, &v.Stage, &v.ProgressPct, &v.Connections, &queued, &started, &finished,
		&v.Error, &v.Band, &v.Score, &level, &hndl, &v.Critical, &v.High, &v.Medium, &v.Low, &v.Info, &certEnd, &incomplete, &v.Service, &v.HostKey,
		&v.Baseline, &meets, &v.BaselineChanges); err != nil {
		return ScanSummary{}, err
	}
	if t := parseTS(sql.NullString{String: queued, Valid: true}); t != nil {
		v.QueuedAt = *t
	}
	v.StartedAt, v.FinishedAt, v.CertNotAfter = parseTS(started), parseTS(finished), parseTS(certEnd)
	if level.Valid {
		l := int(level.Int64)
		v.ReadinessLevel = &l
	}
	v.HNDLExposed, v.Incomplete = hndl != 0, incomplete != 0
	if meets.Valid {
		m := meets.Int64 != 0
		v.BaselineMeets = &m
	}
	return v, nil
}

// attachLatest fills Latest and LastDone for the given assets.
func (s *Store) attachLatest(assets []*Asset) error {
	// SQLite caps the parameters of one statement (32766 by default): ask in chunks.
	const chunk = 5000
	for len(assets) > chunk {
		if err := s.attachLatestChunk(assets[:chunk]); err != nil {
			return err
		}
		assets = assets[chunk:]
	}
	return s.attachLatestChunk(assets)
}

func (s *Store) attachLatestChunk(assets []*Asset) error {
	if len(assets) == 0 {
		return nil
	}
	byID := make(map[int64]*Asset, len(assets))
	ids := make([]any, 0, len(assets))
	ph := make([]string, 0, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
		ids = append(ids, a.ID)
		ph = append(ph, "?")
	}
	in := strings.Join(ph, ",")

	load := func(q string, set func(*Asset, ScanSummary)) error {
		rows, err := s.db.Query(q, ids...)
		if err != nil {
			return err
		}
		defer rows.Close() //nolint:errcheck // read-only
		for rows.Next() {
			v, err := scanSummary(rows)
			if err != nil {
				return err
			}
			if a := byID[v.AssetID]; a != nil {
				set(a, v)
			}
		}
		return rows.Err()
	}
	if err := load(`SELECT `+scanCols+` FROM scans WHERE id IN (SELECT MAX(id) FROM scans WHERE asset_id IN (`+in+`) GROUP BY asset_id)`,
		func(a *Asset, v ScanSummary) { a.Latest = &v }); err != nil {
		return err
	}
	return load(`SELECT `+scanCols+` FROM scans WHERE id IN (SELECT MAX(id) FROM scans WHERE status = 'done' AND asset_id IN (`+in+`) GROUP BY asset_id)`,
		func(a *Asset, v ScanSummary) { a.LastDone = &v })
}
