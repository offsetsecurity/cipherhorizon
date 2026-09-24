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
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
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
	KindHost = "host"
)

// Store is the database handle. It is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at path and applies migrations.
//
// The file holds an organisation's scan results and host inventories, so it is
// created owner-only (0600) and an existing one is tightened. SQLite gives its
// -wal and -shm files the same mode as the database. On Windows the mode bits
// are not enforced and the profile's ACL applies instead.
func Open(path string) (*Store, error) {
	if err := restrictFile(path); err != nil {
		return nil, fmt.Errorf("store: securing %s: %w", path, err)
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
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
	for v := have + 1; v <= len(migrations); v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v-1]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", v, err)
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

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

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

func isConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "constraint failed")
}

// ---- types ---------------------------------------------------------------------------------

// Asset is something to scan.
type Asset struct {
	ID              int64      `json:"id"`
	Kind            string     `json:"kind"`
	Name            string     `json:"name"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
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
	CertNotAfter   *time.Time `json:"certNotAfter"`
	Incomplete     bool       `json:"incomplete"`
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
	CertNotAfter   *time.Time
	Incomplete     bool
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

const assetCols = `id, kind, name, host, port, tags, notes, interval_seconds, next_scan_at, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanAsset(r scanner) (Asset, error) {
	var a Asset
	var tags, created, updated string
	var next sql.NullString
	if err := r.Scan(&a.ID, &a.Kind, &a.Name, &a.Host, &a.Port, &tags, &a.Notes, &a.IntervalSeconds, &next, &created, &updated); err != nil {
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

// CreateAsset inserts an asset. It returns ErrDuplicate if the same kind, host
// and port already exist.
func (s *Store) CreateAsset(a Asset) (Asset, error) {
	now := ts(s.now())
	res, err := s.db.Exec(`INSERT INTO assets (kind, name, host, port, tags, notes, interval_seconds, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`, a.Kind, a.Name, a.Host, a.Port, encodeTags(a.Tags), a.Notes, now, now)
	if isConstraint(err) {
		return Asset{}, ErrDuplicate
	}
	if err != nil {
		return Asset{}, err
	}
	id, _ := res.LastInsertId()
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
	if kind != "" {
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
}

// UpdateAsset applies a patch. Setting an interval schedules the next scan.
func (s *Store) UpdateAsset(id int64, p AssetPatch) (Asset, error) {
	a, err := s.GetAsset(id)
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
	_, err = s.db.Exec(`UPDATE assets SET name = ?, tags = ?, notes = ?, interval_seconds = ?, next_scan_at = ?, updated_at = ? WHERE id = ?`,
		a.Name, encodeTags(a.Tags), a.Notes, a.IntervalSeconds, nullTS(next), ts(s.now()), id)
	if err != nil {
		return Asset{}, err
	}
	return s.GetAsset(id)
}

// DeleteAsset removes an asset and, by cascade, its scans and events.
func (s *Store) DeleteAsset(id int64) error {
	res, err := s.db.Exec(`DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const scanCols = `id, asset_id, status, trigger, stage, progress_pct, connections, queued_at, started_at, finished_at, error,
	band, score, readiness_level, hndl_exposed, crit, high, medium, cert_not_after, incomplete`

func scanSummary(r scanner) (ScanSummary, error) {
	var v ScanSummary
	var queued string
	var started, finished, certEnd sql.NullString
	var level sql.NullInt64
	var hndl, incomplete int
	if err := r.Scan(&v.ID, &v.AssetID, &v.Status, &v.Trigger, &v.Stage, &v.ProgressPct, &v.Connections, &queued, &started, &finished,
		&v.Error, &v.Band, &v.Score, &level, &hndl, &v.Critical, &v.High, &v.Medium, &certEnd, &incomplete); err != nil {
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
	return v, nil
}

// attachLatest fills Latest and LastDone for the given assets.
func (s *Store) attachLatest(assets []*Asset) error {
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
