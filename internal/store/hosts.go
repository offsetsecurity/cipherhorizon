package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/example/cipherhorizon/internal/estate"
)

// HostSnapshot is one uploaded CBOM of a host, with its analysis summary.
type HostSnapshot struct {
	ID      int64     `json:"id"`
	AssetID int64     `json:"assetId"`
	At      time.Time `json:"at"`
	Summary []byte    `json:"-"`
}

// UpsertHostAsset returns the host asset called name, creating it if needed.
func (s *Store) UpsertHostAsset(name string) (a Asset, created bool, err error) {
	a, err = s.FindAsset(KindHost, name, 0)
	if err == nil {
		return a, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Asset{}, false, err
	}
	a, err = s.CreateAsset(Asset{Kind: KindHost, Name: name, Host: name, Port: 0})
	if errors.Is(err, ErrDuplicate) { // lost a race with another ingest
		a, err = s.FindAsset(KindHost, name, 0)
		return a, false, err
	}
	return a, true, err
}

// Retention and quota of uploaded host CBOMs. Each upload can be up to 32 MiB, so a count
// alone does not bound the disk: per host, the oldest uploads go once the host's total passes
// HostSnapshotBytesKept (the newest is always kept); across all hosts, an upload that would
// take the total past HostSnapshotQuota is refused rather than deleting another host's history.
var (
	HostSnapshotsKept           = 50
	HostSnapshotBytesKept int64 = 256 << 20
	HostSnapshotQuota     int64 = 8 << 30
)

// ErrQuota is returned when an upload would take stored host CBOMs past HostSnapshotQuota.
var ErrQuota = errors.New("the server's storage quota for uploaded host inventories is full")

// AddHostSnapshot stores an uploaded CBOM and its analysis as an imported document:
// the safe default, since nothing here proves who made it.
func (s *Store) AddHostSnapshot(assetID int64, cbom, summary []byte) (int64, error) {
	return s.AddHostSnapshotAs(assetID, cbom, summary, estate.ClassImported, "")
}

// AddHostSnapshotAs stores an uploaded CBOM attributed to a source class, and projects
// it into the graph. The caller decides the class from the channel, not from anything
// the document claims about itself (SECARCH-001 T-03).
func (s *Store) AddHostSnapshotAs(assetID int64, cbom, summary []byte, class estate.SourceClass, submittedBy string) (int64, error) {
	if !class.Valid() {
		return 0, errors.New("store: unknown source class")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(length(cbom_json)), 0) FROM host_snapshots`).Scan(&total); err != nil {
		return 0, err
	}
	if total+int64(len(cbom)) > HostSnapshotQuota {
		return 0, ErrQuota
	}
	res, err := tx.Exec(`INSERT INTO host_snapshots (asset_id, at, cbom_json, summary_json, source_class, submitted_by) VALUES (?, ?, ?, ?, ?, ?)`,
		assetID, ts(s.now()), cbom, summary, string(class), submittedBy)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if err := s.retainSnapshotsTx(tx, assetID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.projectQuietly(func(tx *sql.Tx) error { return s.projectSnapshotTx(tx, id) })
	s.correlateQuietly()
	return id, nil
}

// retainSnapshotsTx drops a host's oldest uploads beyond HostSnapshotsKept, and beyond
// HostSnapshotBytesKept in total, never the newest; their projections go with them.
func (s *Store) retainSnapshotsTx(tx *sql.Tx, assetID int64) error {
	rows, err := tx.Query(`SELECT id, length(cbom_json) FROM host_snapshots WHERE asset_id = ? ORDER BY id DESC`, assetID)
	if err != nil {
		return err
	}
	var drop []int64
	var kept int
	var bytes int64
	full := false // once one upload is dropped, every older one goes too
	for rows.Next() {
		var id, n int64
		if err := rows.Scan(&id, &n); err != nil {
			_ = rows.Close()
			return err
		}
		if full || kept > 0 && (kept >= HostSnapshotsKept || bytes+n > HostSnapshotBytesKept) {
			full = true
			drop = append(drop, id)
			continue
		}
		kept++
		bytes += n
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := deleteSourcesTx(tx, "host_snapshot", drop); err != nil {
		return err
	}
	for _, id := range drop {
		if _, err := tx.Exec(`DELETE FROM host_snapshots WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// HostSnapshots lists a host's uploads, newest first.
func (s *Store) HostSnapshots(assetID int64, limit int) ([]HostSnapshot, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, asset_id, at, summary_json FROM host_snapshots WHERE asset_id = ? ORDER BY id DESC LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []HostSnapshot{}
	for rows.Next() {
		var h HostSnapshot
		var at string
		if err := rows.Scan(&h.ID, &h.AssetID, &at, &h.Summary); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			h.At = *t
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostCBOM returns an uploaded CBOM.
func (s *Store) HostCBOM(snapshotID int64) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT cbom_json FROM host_snapshots WHERE id = ?`, snapshotID).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}
