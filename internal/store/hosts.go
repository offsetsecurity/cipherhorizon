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

// HostSnapshotsKept is how many uploads are retained per host.
var HostSnapshotsKept = 50

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
	res, err := s.db.Exec(`INSERT INTO host_snapshots (asset_id, at, cbom_json, summary_json, source_class, submitted_by) VALUES (?, ?, ?, ?, ?, ?)`,
		assetID, ts(s.now()), cbom, summary, string(class), submittedBy)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if _, err = s.db.Exec(`DELETE FROM host_snapshots WHERE asset_id = ? AND id NOT IN
		(SELECT id FROM host_snapshots WHERE asset_id = ? ORDER BY id DESC LIMIT ?)`, assetID, assetID, HostSnapshotsKept); err != nil {
		return id, err
	}
	s.projectQuietly(func(tx *sql.Tx) error { return s.projectSnapshotTx(tx, id) })
	s.pruneOrphans()
	s.correlateQuietly()
	return id, nil
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
