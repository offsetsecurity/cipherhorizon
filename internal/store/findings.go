package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
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
//
// The two assets also become one system (their systems are merged, keeping the
// host's), so the metadata a person records is about the machine, not one of its
// faces. If the two systems hold different operator-set values the link is refused
// with a ConflictError naming the fields, and nothing changes.
func (s *Store) LinkAssets(a, b int64) error { return s.LinkAssetsAs(a, b, "operator") }

// LinkAssetsAs is LinkAssets recording who made the link.
func (s *Store) LinkAssetsAs(a, b int64, actor string) error {
	if a == b {
		return errors.New("store: cannot link an asset to itself")
	}
	aa, err := s.GetAsset(a)
	if err != nil {
		return err
	}
	bb, err := s.GetAsset(b)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if aa.SystemID != bb.SystemID && aa.SystemID != 0 && bb.SystemID != 0 {
		from, to := bb.SystemID, aa.SystemID
		if bb.Kind == KindHost && aa.Kind != KindHost {
			from, to = aa.SystemID, bb.SystemID
		}
		if err := s.mergeSystemsTx(tx, from, to, actor, fmt.Sprintf("assets %d and %d linked", a, b)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO asset_links (asset_id, linked_asset_id, created_at) VALUES (?, ?, ?)`, a, b, ts(s.now())); err != nil {
		return err
	}
	// The same fact, as a reviewable link a person made: confirmed, source operator.
	linkAsset := a
	if aa.Kind == KindHost && bb.Kind != KindHost {
		linkAsset = b
	}
	var sysID int64
	if err := tx.QueryRow(`SELECT COALESCE(system_id, 0) FROM assets WHERE id = ?`, linkAsset).Scan(&sysID); err != nil {
		return err
	}
	if sysID != 0 {
		if err := recordManualLinkTx(tx, ts(s.now()), actor, linkAsset, sysID, LinkConfirmed); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.correlateQuietly()
	return nil
}

// UnlinkAssets removes a link in either direction. If that leaves the two assets
// unconnected by any other link, the second asset (and whatever is still linked to it)
// moves to a system of its own; the metadata stays with the original system.
func (s *Store) UnlinkAssets(a, b int64) error { return s.UnlinkAssetsAs(a, b, "operator") }

// UnlinkAssetsAs is UnlinkAssets recording who removed the link.
func (s *Store) UnlinkAssetsAs(a, b int64, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM asset_links WHERE (asset_id = ? AND linked_asset_id = ?) OR (asset_id = ? AND linked_asset_id = ?)`, a, b, b, a); err != nil {
		return err
	}
	var sysA, sysB sql.NullInt64
	for _, q := range []struct {
		id  int64
		dst *sql.NullInt64
	}{{a, &sysA}, {b, &sysB}} {
		// A missing asset leaves its system unknown (NULL): nothing to split. Any other error is real.
		if err := tx.QueryRow(`SELECT system_id FROM assets WHERE id = ?`, q.id).Scan(q.dst); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if sysA.Valid && sysB.Valid && sysA.Int64 == sysB.Int64 {
		comp, err := componentTx(tx, a)
		if err != nil {
			return err
		}
		if !comp[b] {
			bComp, err := componentTx(tx, b)
			if err != nil {
				return err
			}
			var moved []int64
			for id := range bComp {
				moved = append(moved, id)
			}
			sort.Slice(moved, func(i, j int) bool { return moved[i] < moved[j] })
			var name string
			if err := tx.QueryRow(`SELECT name FROM assets WHERE id = ?`, b).Scan(&name); err != nil {
				return err
			}
			if err := s.splitAssetTx(tx, moved, name, actor, fmt.Sprintf("assets %d and %d unlinked", a, b), sysA.Int64); err != nil {
				return err
			}
			// A person said these are not the same system: remember it, so correlation does not
			// propose the pair again.
			if err := recordManualLinkTx(tx, ts(s.now()), actor, b, sysA.Int64, LinkRejected); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.correlateQuietly()
	return nil
}

// componentTx returns the assets connected to id through asset_links.
func componentTx(tx *sql.Tx, id int64) (map[int64]bool, error) {
	seen := map[int64]bool{id: true}
	queue := []int64{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		rows, err := tx.Query(`SELECT linked_asset_id FROM asset_links WHERE asset_id = ? UNION SELECT asset_id FROM asset_links WHERE linked_asset_id = ?`, cur, cur)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var n int64
			if err := rows.Scan(&n); err != nil {
				_ = rows.Close()
				return nil, err
			}
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
		_ = rows.Close()
	}
	return seen, nil
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
