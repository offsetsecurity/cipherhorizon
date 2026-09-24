package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// FindingStatus is a persisted triage decision on one finding of one asset.
// finding_key is a rule ID (e.g. "CIPHER.RC4") for a TLS finding, or
// "pqc:<algorithm name>" for a host algorithm verdict — the two finding
// systems have no shared identity otherwise (see internal/eval vs internal/pqc).
type FindingStatus struct {
	AssetID    int64     `json:"assetId"`
	FindingKey string    `json:"findingKey"`
	Status     string    `json:"status"`
	Note       string    `json:"note,omitempty"`
	SetAt      time.Time `json:"setAt"`
}

// SetFindingStatus records or replaces a triage decision.
func (s *Store) SetFindingStatus(assetID int64, key, status, note string) error {
	if status != FindingAcknowledged && status != FindingAcceptedRisk {
		return fmt.Errorf("store: invalid finding status %q", status)
	}
	_, err := s.db.Exec(`INSERT INTO finding_status (asset_id, finding_key, status, note, set_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (asset_id, finding_key) DO UPDATE SET status = excluded.status, note = excluded.note, set_at = excluded.set_at`,
		assetID, key, status, note, ts(s.now()))
	return err
}

// ClearFindingStatus removes a triage decision, returning the finding to "new".
func (s *Store) ClearFindingStatus(assetID int64, key string) error {
	_, err := s.db.Exec(`DELETE FROM finding_status WHERE asset_id = ? AND finding_key = ?`, assetID, key)
	return err
}

// FindingStatuses returns one asset's triage decisions, keyed by finding_key.
func (s *Store) FindingStatuses(assetID int64) (map[string]FindingStatus, error) {
	rows, err := s.db.Query(`SELECT asset_id, finding_key, status, note, set_at FROM finding_status WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[string]FindingStatus{}
	for rows.Next() {
		var fs FindingStatus
		var at string
		if err := rows.Scan(&fs.AssetID, &fs.FindingKey, &fs.Status, &fs.Note, &at); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			fs.SetAt = *t
		}
		out[fs.FindingKey] = fs
	}
	return out, rows.Err()
}

// AllFindingStatuses returns every triage decision across every asset, keyed
// by asset ID then finding_key, for the fleet-wide findings view.
func (s *Store) AllFindingStatuses() (map[int64]map[string]FindingStatus, error) {
	rows, err := s.db.Query(`SELECT asset_id, finding_key, status, note, set_at FROM finding_status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[int64]map[string]FindingStatus{}
	for rows.Next() {
		var fs FindingStatus
		var at string
		if err := rows.Scan(&fs.AssetID, &fs.FindingKey, &fs.Status, &fs.Note, &at); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			fs.SetAt = *t
		}
		if out[fs.AssetID] == nil {
			out[fs.AssetID] = map[string]FindingStatus{}
		}
		out[fs.AssetID][fs.FindingKey] = fs
	}
	return out, rows.Err()
}

// LinkAssets records that two assets (typically a TLS endpoint and a host)
// are known, by a person, to be the same machine. Never inferred by the
// product itself. Order does not matter; the link is symmetric.
func (s *Store) LinkAssets(a, b int64) error {
	if a == b {
		return errors.New("store: cannot link an asset to itself")
	}
	if _, err := s.GetAsset(a); err != nil {
		return err
	}
	if _, err := s.GetAsset(b); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO asset_links (asset_id, linked_asset_id, created_at) VALUES (?, ?, ?)`, a, b, ts(s.now()))
	return err
}

// UnlinkAssets removes a link in either direction.
func (s *Store) UnlinkAssets(a, b int64) error {
	_, err := s.db.Exec(`DELETE FROM asset_links WHERE (asset_id = ? AND linked_asset_id = ?) OR (asset_id = ? AND linked_asset_id = ?)`, a, b, b, a)
	return err
}

// AllLinks returns every asset's linked-asset IDs in one query, symmetric
// (each link appears under both asset IDs), for batch list rendering.
func (s *Store) AllLinks() (map[int64][]int64, error) {
	rows, err := s.db.Query(`SELECT asset_id, linked_asset_id FROM asset_links`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[int64][]int64{}
	for rows.Next() {
		var a, b int64
		if err := rows.Scan(&a, &b); err != nil {
			return nil, err
		}
		out[a] = append(out[a], b)
		out[b] = append(out[b], a)
	}
	return out, rows.Err()
}

// LinkedAssetIDs returns the IDs of every asset linked to assetID.
func (s *Store) LinkedAssetIDs(assetID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT linked_asset_id FROM asset_links WHERE asset_id = ?
		UNION SELECT asset_id FROM asset_links WHERE linked_asset_id = ?`, assetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
