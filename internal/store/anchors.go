package store

import (
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Private trust anchors (PRD-004 REQ-TTRS-2): CA certificates an operator adds to a
// system so that chains to a private CA are judged "trusted by your CA bundle". Only
// certificates are stored; the server refuses key blocks before anything reaches here.

// MaxAnchorsPerSystem bounds the per-system bundle.
const MaxAnchorsPerSystem = 50

// AnchorCert is a certificate being added.
type AnchorCert struct {
	SHA256   string
	Subject  string
	NotAfter time.Time
	DER      []byte
}

// TrustAnchor is one stored anchor.
type TrustAnchor struct {
	SHA256   string    `json:"fingerprint"`
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"notAfter"`
	AddedAt  time.Time `json:"addedAt"`
	AddedBy  string    `json:"addedBy"`
}

// ErrTooManyAnchors is returned when an upload would exceed MaxAnchorsPerSystem.
var ErrTooManyAnchors = fmt.Errorf("a system holds at most %d trust anchors", MaxAnchorsPerSystem)

// AddTrustAnchors stores the certificates on a system, skipping ones already
// there, and audits each addition. It returns the anchors added.
func (s *Store) AddTrustAnchors(systemID int64, certs []AnchorCert, actor string) ([]TrustAnchor, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM systems WHERE id = ?`, systemID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrNotFound
	}
	var have int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM trust_anchors WHERE system_id = ?`, systemID).Scan(&have); err != nil {
		return nil, err
	}
	at := s.now().UTC()
	now := ts(at)
	if actor == "" {
		actor = "unknown"
	}
	var added []TrustAnchor
	for _, c := range certs {
		var dup int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM trust_anchors WHERE system_id = ? AND sha256 = ?`, systemID, c.SHA256).Scan(&dup); err != nil {
			return nil, err
		}
		if dup > 0 {
			continue
		}
		if have+len(added) >= MaxAnchorsPerSystem {
			return nil, ErrTooManyAnchors
		}
		p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
		if _, err := tx.Exec(`INSERT INTO trust_anchors (system_id, sha256, subject, not_after, pem, added_at, added_by) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			systemID, c.SHA256, c.Subject, ts(c.NotAfter), string(p), now, actor); err != nil {
			return nil, err
		}
		if err := audit(tx, now, actor, systemID, "anchor-add", map[string]any{},
			map[string]any{"fingerprint": c.SHA256, "subject": c.Subject}, ""); err != nil {
			return nil, err
		}
		added = append(added, TrustAnchor{SHA256: c.SHA256, Subject: c.Subject, NotAfter: c.NotAfter.UTC(), AddedAt: at, AddedBy: actor})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return added, nil
}

// TrustAnchors lists a system's anchors, oldest first.
func (s *Store) TrustAnchors(systemID int64) ([]TrustAnchor, error) {
	rows, err := s.db.Query(`SELECT sha256, subject, not_after, added_at, added_by FROM trust_anchors WHERE system_id = ? ORDER BY id`, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []TrustAnchor{}
	for rows.Next() {
		var a TrustAnchor
		var na, at string
		if err := rows.Scan(&a.SHA256, &a.Subject, &na, &at, &a.AddedBy); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: na, Valid: true}); t != nil {
			a.NotAfter = *t
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			a.AddedAt = *t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TrustAnchorDER returns the certificates of a system's anchors.
func (s *Store) TrustAnchorDER(systemID int64) ([][]byte, error) {
	rows, err := s.db.Query(`SELECT pem FROM trust_anchors WHERE system_id = ? ORDER BY id`, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out [][]byte
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if b, _ := pem.Decode([]byte(p)); b != nil && b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
	return out, rows.Err()
}

// RemoveTrustAnchor deletes one anchor from a system and audits it.
func (s *Store) RemoveTrustAnchor(systemID int64, sha, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var subject string
	err = tx.QueryRow(`SELECT subject FROM trust_anchors WHERE system_id = ? AND sha256 = ?`, systemID, sha).Scan(&subject)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM trust_anchors WHERE system_id = ? AND sha256 = ?`, systemID, sha); err != nil {
		return err
	}
	if err := audit(tx, ts(s.now()), actor, systemID, "anchor-remove",
		map[string]any{"fingerprint": sha, "subject": subject}, map[string]any{}, ""); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceEvaluation stores a re-evaluation of a completed scan's report (REQ-TNFR-4).
// The report itself is never rewritten. The event records the old and new versions.
func (s *Store) ReplaceEvaluation(scanID int64, r Result, event string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE scans SET eval_json = ?, band = ?, score = ?, readiness_level = ?, hndl_exposed = ?, crit = ?, high = ?, medium = ?
		WHERE id = ? AND status = 'done'`,
		r.Evaluation, r.Band, r.Score, r.ReadinessLevel, b2i(r.HNDLExposed), r.Critical, r.High, r.Medium, scanID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if event != "" {
		if _, err := tx.Exec(`INSERT INTO scan_events (scan_id, at, message) VALUES (?, ?, ?)`, scanID, ts(s.now()), event); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LatestDoneScans returns, for every asset, the ID of its most recent completed scan.
// systemID > 0 limits it to that system's assets.
func (s *Store) LatestDoneScans(systemID int64) (map[int64]int64, error) {
	q := `SELECT a.id, (SELECT sc.id FROM scans sc WHERE sc.asset_id = a.id AND sc.status = 'done' ORDER BY sc.id DESC LIMIT 1)
		FROM assets a`
	var args []any
	if systemID > 0 {
		q += ` WHERE a.system_id = ?`
		args = append(args, systemID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[int64]int64{}
	for rows.Next() {
		var asset int64
		var scan sql.NullInt64
		if err := rows.Scan(&asset, &scan); err != nil {
			return nil, err
		}
		if scan.Valid {
			out[asset] = scan.Int64
		}
	}
	return out, rows.Err()
}
