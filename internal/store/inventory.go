package store

import (
	"database/sql"
	"errors"
)

// Reads behind the whole-inventory CBOM (PRD-005 REQ-INV-5).

// ImportDocument returns an active import's stored CBOM.
func (s *Store) ImportDocument(id int64) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT i.cbom_json FROM imports i JOIN sources src ON src.ref_kind = 'import' AND src.ref_id = i.id
		WHERE i.id = ? AND src.status = 'active' LIMIT 1`, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// LatestHostSnapshots returns, for every machine, its most recent snapshot (without the summary).
func (s *Store) LatestHostSnapshots() (map[int64]HostSnapshot, error) {
	rows, err := s.db.Query(`SELECT id, asset_id, at FROM host_snapshots WHERE id IN (SELECT MAX(id) FROM host_snapshots GROUP BY asset_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[int64]HostSnapshot{}
	for rows.Next() {
		var h HostSnapshot
		var at string
		if err := rows.Scan(&h.ID, &h.AssetID, &at); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			h.At = *t
		}
		out[h.AssetID] = h
	}
	return out, rows.Err()
}
