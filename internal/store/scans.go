package store

import (
	"database/sql"
	"errors"
	"time"
)

// EnqueueScan queues a scan of an asset. If the asset already has an active
// (queued or running) scan, that one is returned with existing=true and nothing
// is added: the schema allows only one (AC-02.6).
func (s *Store) EnqueueScan(assetID int64, trigger string) (v ScanSummary, existing bool, err error) {
	now := s.now()
	res, err := s.db.Exec(`INSERT INTO scans (asset_id, status, trigger, queued_at) VALUES (?, 'queued', ?, ?)`, assetID, trigger, ts(now))
	if isConstraint(err) {
		// Either the asset does not exist (foreign key) or a scan is already active.
		if _, gerr := s.GetAsset(assetID); errors.Is(gerr, ErrNotFound) {
			return ScanSummary{}, false, ErrNotFound
		}
		active, aerr := s.activeScan(assetID)
		return active, true, aerr
	}
	if err != nil {
		return ScanSummary{}, false, err
	}
	id, _ := res.LastInsertId()
	v, err = s.GetScan(id)
	return v, false, err
}

func (s *Store) activeScan(assetID int64) (ScanSummary, error) {
	v, err := scanSummary(s.db.QueryRow(`SELECT `+scanCols+` FROM scans WHERE asset_id = ? AND status IN ('queued','running')`, assetID))
	if errors.Is(err, sql.ErrNoRows) {
		return ScanSummary{}, ErrNotFound
	}
	return v, err
}

// ClaimNext atomically takes the oldest queued scan and marks it running.
// It returns ErrNotFound when the queue is empty.
func (s *Store) ClaimNext() (ScanSummary, error) {
	row := s.db.QueryRow(`UPDATE scans SET status = 'running', started_at = ?, stage = 'starting', progress_pct = 0
		WHERE id = (SELECT id FROM scans WHERE status = 'queued' ORDER BY id LIMIT 1)
		RETURNING `+scanCols, ts(s.now()))
	v, err := scanSummary(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanSummary{}, ErrNotFound
	}
	return v, err
}

// GetScan returns a scan without its report.
func (s *Store) GetScan(id int64) (ScanSummary, error) {
	v, err := scanSummary(s.db.QueryRow(`SELECT `+scanCols+` FROM scans WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ScanSummary{}, ErrNotFound
	}
	return v, err
}

// ScanFilter narrows ListScans.
type ScanFilter struct {
	AssetID int64
	Status  string
	Limit   int
}

// ScanWithAsset is a scan row plus the asset it belongs to, for lists.
type ScanWithAsset struct {
	ScanSummary
	AssetName    string `json:"assetName"`
	AssetAddress string `json:"assetAddress"`
}

// ListScans returns scans, newest first.
func (s *Store) ListScans(f ScanFilter) ([]ScanWithAsset, error) {
	q := `SELECT ` + prefixed("s", scanCols) + `, a.name, a.host, a.port FROM scans s JOIN assets a ON a.id = s.asset_id WHERE 1=1` //nolint:gosec // scanCols is a constant column list, not input
	var args []any
	if f.AssetID != 0 {
		q += ` AND s.asset_id = ?`
		args = append(args, f.AssetID)
	}
	if f.Status != "" {
		q += ` AND s.status = ?`
		args = append(args, f.Status)
	}
	q += ` ORDER BY s.id DESC LIMIT ?`
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	args = append(args, f.Limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []ScanWithAsset{}
	for rows.Next() {
		var w ScanWithAsset
		var name, host string
		var port int
		var queued string
		var started, finished, certEnd sql.NullString
		var level sql.NullInt64
		var hndl, incomplete int
		v := &w.ScanSummary
		if err := rows.Scan(&v.ID, &v.AssetID, &v.Status, &v.Trigger, &v.Stage, &v.ProgressPct, &v.Connections, &queued, &started, &finished,
			&v.Error, &v.Band, &v.Score, &level, &hndl, &v.Critical, &v.High, &v.Medium, &certEnd, &incomplete, &name, &host, &port); err != nil {
			return nil, err
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
		w.AssetName = name
		w.AssetAddress = Asset{Host: host, Port: port}.Address()
		out = append(out, w)
	}
	return out, rows.Err()
}

// prefixed puts a table alias in front of every column in a comma list.
func prefixed(alias, cols string) string {
	var out []byte
	first := true
	start := 0
	flush := func(end int) {
		c := trim(cols[start:end])
		if c == "" {
			return
		}
		if !first {
			out = append(out, ',', ' ')
		}
		out = append(out, alias...)
		out = append(out, '.')
		out = append(out, c...)
		first = false
	}
	for i := 0; i < len(cols); i++ {
		if cols[i] == ',' {
			flush(i)
			start = i + 1
		}
	}
	flush(len(cols))
	return string(out)
}

func trim(s string) string {
	a, b := 0, len(s)
	for a < b && (s[a] == ' ' || s[a] == '\n' || s[a] == '\t' || s[a] == '\r') {
		a++
	}
	for b > a && (s[b-1] == ' ' || s[b-1] == '\n' || s[b-1] == '\t' || s[b-1] == '\r') {
		b--
	}
	return s[a:b]
}

// UpdateProgress records the running scan's stage, percentage and connection count.
func (s *Store) UpdateProgress(id int64, stage string, pct, connections int) error {
	_, err := s.db.Exec(`UPDATE scans SET stage = ?, progress_pct = ?, connections = ? WHERE id = ? AND status = 'running'`,
		stage, pct, connections, id)
	return err
}

// AddEvent appends a line to the scan's log.
func (s *Store) AddEvent(scanID int64, message string) error {
	_, err := s.db.Exec(`INSERT INTO scan_events (scan_id, at, message) VALUES (?, ?, ?)`, scanID, ts(s.now()), message)
	return err
}

// Events returns the scan's log, oldest first.
func (s *Store) Events(scanID int64) ([]Event, error) {
	rows, err := s.db.Query(`SELECT at, message FROM scan_events WHERE scan_id = ? ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []Event{}
	for rows.Next() {
		var at, msg string
		if err := rows.Scan(&at, &msg); err != nil {
			return nil, err
		}
		e := Event{Message: msg}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			e.At = *t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// FinishScan stores a completed scan's result.
func (s *Store) FinishScan(id int64, r Result) error {
	res, err := s.db.Exec(`UPDATE scans SET status = 'done', finished_at = ?, stage = 'done', progress_pct = 100, error = '',
		report_json = ?, eval_json = ?, band = ?, score = ?, readiness_level = ?, hndl_exposed = ?, crit = ?, high = ?, medium = ?,
		cert_not_after = ?, incomplete = ? WHERE id = ? AND status = 'running'`,
		ts(s.now()), r.Report, r.Evaluation, r.Band, r.Score, r.ReadinessLevel, b2i(r.HNDLExposed), r.Critical, r.High, r.Medium,
		nullTS(r.CertNotAfter), b2i(r.Incomplete), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.afterFinish(id)
}

// FailScan marks a running scan failed with a reason, optionally keeping a
// partial report.
func (s *Store) FailScan(id int64, reason string, partialReport []byte) error {
	_, err := s.db.Exec(`UPDATE scans SET status = 'failed', finished_at = ?, stage = 'failed', error = ?, report_json = ? WHERE id = ? AND status IN ('running','queued')`,
		ts(s.now()), reason, partialReport, id)
	if err != nil {
		return err
	}
	return s.afterFinish(id)
}

// CancelScan marks a queued or running scan canceled.
func (s *Store) CancelScan(id int64) error {
	res, err := s.db.Exec(`UPDATE scans SET status = 'canceled', finished_at = ?, stage = 'canceled', error = 'canceled by user' WHERE id = ? AND status IN ('queued','running')`,
		ts(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, gerr := s.GetScan(id); errors.Is(gerr, ErrNotFound) {
			return ErrNotFound
		}
		return errors.New("scan is not active")
	}
	return s.afterFinish(id)
}

// afterFinish reschedules the asset and applies retention.
func (s *Store) afterFinish(scanID int64) error {
	var assetID int64
	var interval int
	if err := s.db.QueryRow(`SELECT s.asset_id, a.interval_seconds FROM scans s JOIN assets a ON a.id = s.asset_id WHERE s.id = ?`, scanID).Scan(&assetID, &interval); err != nil {
		return err
	}
	if interval > 0 {
		next := s.now().Add(time.Duration(interval) * time.Second)
		if _, err := s.db.Exec(`UPDATE assets SET next_scan_at = ? WHERE id = ?`, ts(next), assetID); err != nil {
			return err
		}
	}
	return s.retain(assetID, s.keep())
}

// Retention is how many finished scans are kept per asset.
var Retention = 200

func (s *Store) keep() int { return Retention }

func (s *Store) retain(assetID int64, keep int) error {
	if keep <= 0 {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM scans WHERE asset_id = ? AND status NOT IN ('queued','running')
		AND id NOT IN (SELECT id FROM scans WHERE asset_id = ? ORDER BY id DESC LIMIT ?)`, assetID, assetID, keep)
	return err
}

// FailInterrupted marks scans left running or queued by a previous process as
// failed, so none stays "running" forever after a restart (AC-12.2).
func (s *Store) FailInterrupted() (int, error) {
	res, err := s.db.Exec(`UPDATE scans SET status = 'failed', finished_at = ?, stage = 'failed', error = 'interrupted by a restart of the server'
		WHERE status IN ('running','queued')`, ts(s.now()))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// DueAssets returns assets whose scheduled scan is due and that have no active scan.
func (s *Store) DueAssets(now time.Time) ([]Asset, error) {
	rows, err := s.db.Query(`SELECT `+assetCols+` FROM assets a WHERE kind = 'tls-endpoint' AND interval_seconds > 0 AND next_scan_at IS NOT NULL AND next_scan_at <= ?
		AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.asset_id = a.id AND s.status IN ('queued','running')) ORDER BY next_scan_at`, ts(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Report returns a scan's stored report JSON.
func (s *Store) Report(id int64) ([]byte, error) { return s.blob(`report_json`, id) }

// Evaluation returns a scan's stored evaluation JSON.
func (s *Store) Evaluation(id int64) ([]byte, error) { return s.blob(`eval_json`, id) }

func (s *Store) blob(col string, id int64) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT `+col+` FROM scans WHERE id = ?`, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, ErrNotFound
	}
	return b, nil
}

// HistoryPoint is one completed scan on an asset's timeline.
type HistoryPoint struct {
	ScanID         int64     `json:"scanId"`
	At             time.Time `json:"at"`
	Status         string    `json:"status"`
	Band           string    `json:"band"`
	Score          int       `json:"score"`
	ReadinessLevel *int      `json:"readinessLevel"`
	HNDLExposed    bool      `json:"hndlExposed"`
	Critical       int       `json:"critical"`
	High           int       `json:"high"`
	Medium         int       `json:"medium"`
	Error          string    `json:"error"`
	Incomplete     bool      `json:"incomplete"`
}

// History returns an asset's finished scans, oldest first (for charts).
func (s *Store) History(assetID int64, limit int) ([]HistoryPoint, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, COALESCE(finished_at, queued_at), status, band, score, readiness_level, hndl_exposed, crit, high, medium, error, incomplete
		FROM scans WHERE asset_id = ? AND status IN ('done','failed','canceled') ORDER BY id DESC LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []HistoryPoint{}
	for rows.Next() {
		var p HistoryPoint
		var at string
		var level sql.NullInt64
		var hndl, inc int
		if err := rows.Scan(&p.ScanID, &at, &p.Status, &p.Band, &p.Score, &level, &hndl, &p.Critical, &p.High, &p.Medium, &p.Error, &inc); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			p.At = *t
		}
		if level.Valid {
			l := int(level.Int64)
			p.ReadinessLevel = &l
		}
		p.HNDLExposed, p.Incomplete = hndl != 0, inc != 0
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Oldest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
