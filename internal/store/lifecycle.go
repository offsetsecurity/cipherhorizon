package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Certificate lifecycle (PRD-023 M2): what a person says about a certificate, and the notifications
// the lifecycle monitor sends.

// RenewalMethods are the ways a person can record that a certificate is renewed.
var RenewalMethods = []string{"acme", "ca-portal", "cert-manager", "cloud-managed", "internal-ca", "manual", "vendor"}

// CertLifecycle is what a person recorded about one certificate.
type CertLifecycle struct {
	Fingerprint string    `json:"fingerprint"`
	Owner       string    `json:"owner"`
	Renewal     string    `json:"renewal"`
	Notes       string    `json:"notes"`
	UpdatedBy   string    `json:"updatedBy,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// CertificateLifecycle returns what was recorded about a certificate; found is false when nothing was.
func (s *Store) CertificateLifecycle(fingerprint string) (CertLifecycle, bool, error) {
	var c CertLifecycle
	var at string
	err := s.db.QueryRow(`SELECT fingerprint, owner, renewal, notes, updated_by, updated_at FROM certificate_lifecycle WHERE fingerprint = ?`,
		strings.ToLower(fingerprint)).Scan(&c.Fingerprint, &c.Owner, &c.Renewal, &c.Notes, &c.UpdatedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return CertLifecycle{Fingerprint: strings.ToLower(fingerprint)}, false, nil
	}
	if err != nil {
		return c, false, err
	}
	if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
		c.UpdatedAt = *t
	}
	return c, true, nil
}

// CertificateLifecycles returns every record, keyed by fingerprint.
func (s *Store) CertificateLifecycles() (map[string]CertLifecycle, error) {
	rows, err := s.db.Query(`SELECT fingerprint, owner, renewal, notes, updated_by, updated_at FROM certificate_lifecycle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[string]CertLifecycle{}
	for rows.Next() {
		var c CertLifecycle
		var at string
		if err := rows.Scan(&c.Fingerprint, &c.Owner, &c.Renewal, &c.Notes, &c.UpdatedBy, &at); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			c.UpdatedAt = *t
		}
		out[c.Fingerprint] = c
	}
	return out, rows.Err()
}

// SetCertificateLifecycle records owner, renewal method and notes for a certificate, with the change
// in the audit log (object kind "certificate", keyed by the record's rowid-free fingerprint in the row).
func (s *Store) SetCertificateLifecycle(c CertLifecycle, actor, reason string) (CertLifecycle, error) {
	now := s.now()
	c.Fingerprint = strings.ToLower(c.Fingerprint)
	old, _, err := s.CertificateLifecycle(c.Fingerprint)
	if err != nil {
		return CertLifecycle{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return CertLifecycle{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	if _, err := tx.Exec(`INSERT INTO certificate_lifecycle (fingerprint, owner, renewal, notes, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (fingerprint) DO UPDATE SET owner = excluded.owner, renewal = excluded.renewal, notes = excluded.notes,
		updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		c.Fingerprint, c.Owner, c.Renewal, c.Notes, actor, ts(now)); err != nil {
		return CertLifecycle{}, err
	}
	before := map[string]any{"fingerprint": c.Fingerprint, "owner": old.Owner, "renewal": old.Renewal, "notes": old.Notes}
	after := map[string]any{"fingerprint": c.Fingerprint, "owner": c.Owner, "renewal": c.Renewal, "notes": c.Notes}
	if err := auditWorkTx(tx, now, actor, "certificate", 0, "lifecycle edited", before, after, reason); err != nil {
		return CertLifecycle{}, err
	}
	if err := tx.Commit(); err != nil {
		return CertLifecycle{}, err
	}
	out, _, err := s.CertificateLifecycle(c.Fingerprint)
	return out, err
}

// LeafChange is an endpoint whose two latest complete scans presented different leaf certificates.
type LeafChange struct {
	AssetID  int64
	Name     string
	FromScan int64
	ToScan   int64
	From     []string // fingerprints
	To       []string
	At       time.Time // when the later scan finished
}

// RecentLeafChanges lists, for every TLS endpoint, a change of leaf certificate between its two latest
// complete scans, when the later one finished at or after since.
func (s *Store) RecentLeafChanges(since time.Time) ([]LeafChange, error) {
	rows, err := s.db.Query(`SELECT a.id, a.name FROM assets a WHERE a.kind = ? ORDER BY a.id`, KindTLS)
	if err != nil {
		return nil, err
	}
	type ep struct {
		id   int64
		name string
	}
	var eps []ep
	for rows.Next() {
		var e ep
		if err := rows.Scan(&e.id, &e.name); err != nil {
			_ = rows.Close()
			return nil, err
		}
		eps = append(eps, e)
	}
	_ = rows.Close()
	var out []LeafChange
	for _, e := range eps {
		sr, err := s.db.Query(`SELECT id, finished_at FROM scans WHERE asset_id = ? AND status = 'done' AND incomplete = 0 ORDER BY finished_at DESC, id DESC LIMIT 2`, e.id)
		if err != nil {
			return nil, err
		}
		var ids []int64
		var at []string
		for sr.Next() {
			var id int64
			var f sql.NullString
			if err := sr.Scan(&id, &f); err != nil {
				_ = sr.Close()
				return nil, err
			}
			ids = append(ids, id)
			at = append(at, f.String)
		}
		_ = sr.Close()
		if len(ids) < 2 {
			continue
		}
		finished := parseTS(sql.NullString{String: at[0], Valid: true})
		if finished == nil || finished.Before(since) {
			continue
		}
		newer, err := s.ScanLeafCertificates(ids[0])
		if err != nil {
			return nil, err
		}
		older, err := s.ScanLeafCertificates(ids[1])
		if err != nil {
			return nil, err
		}
		if len(newer) == 0 || len(older) == 0 || sameFingerprints(newer, older) {
			continue
		}
		c := LeafChange{AssetID: e.id, Name: e.name, FromScan: ids[1], ToScan: ids[0], At: *finished}
		for _, l := range older {
			c.From = append(c.From, l.Fingerprint)
		}
		for _, l := range newer {
			c.To = append(c.To, l.Fingerprint)
		}
		out = append(out, c)
	}
	return out, nil
}

func sameFingerprints(a, b []LeafCertificate) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, l := range a {
		set[l.Fingerprint] = true
	}
	for _, l := range b {
		if !set[l.Fingerprint] {
			return false
		}
	}
	return true
}

// WorkCertificates is the set of certificate fingerprints any piece of work names (any stage).
func (s *Store) WorkCertificates() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT certificate, MAX(id) FROM work_items WHERE certificate <> '' GROUP BY certificate`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := map[string]int64{}
	for rows.Next() {
		var fp string
		var id int64
		if err := rows.Scan(&fp, &id); err != nil {
			return nil, err
		}
		out[fp] = id
	}
	return out, rows.Err()
}

// ---- notifications --------------------------------------------------------------------------

// Notification statuses.
const (
	NotifyPending = "pending"  // waiting to be delivered
	NotifySent    = "sent"     // delivered
	NotifyFailed  = "failed"   // gave up after the last attempt
	NotifyNotSent = "not-sent" // no destination is configured, or the event kind is not chosen
)

// Notification is one lifecycle event and its delivery.
type Notification struct {
	Key       string     `json:"key"`
	Kind      string     `json:"kind"`
	Severity  string     `json:"severity"`
	Title     string     `json:"title"`
	Detail    string     `json:"detail"`
	Link      string     `json:"link"`
	FirstSeen time.Time  `json:"firstSeen"`
	LastSeen  time.Time  `json:"lastSeen"`
	Status    string     `json:"status"`
	Attempts  int        `json:"attempts"`
	SentAt    *time.Time `json:"sentAt"`
	LastError string     `json:"lastError,omitempty"`
}

// SeeNotification records that an event was found now. A new event is stored with status; one already
// known only has last_seen moved. It reports whether the event is new.
func (s *Store) SeeNotification(n Notification, status string) (bool, error) {
	now := ts(s.now())
	res, err := s.db.Exec(`INSERT INTO notifications (event_key, kind, severity, title, detail, link, first_seen, last_seen, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (event_key) DO NOTHING`,
		n.Key, n.Kind, n.Severity, n.Title, n.Detail, n.Link, now, now, status)
	if err != nil {
		return false, err
	}
	if k, _ := res.RowsAffected(); k == 1 {
		return true, nil
	}
	_, err = s.db.Exec(`UPDATE notifications SET last_seen = ?, title = ?, detail = ? WHERE event_key = ?`, now, n.Title, n.Detail, n.Key)
	return false, err
}

// PendingNotifications lists events waiting for delivery, oldest first.
func (s *Store) PendingNotifications(limit int) ([]Notification, error) {
	return s.notifications(`WHERE status = 'pending' ORDER BY first_seen, event_key LIMIT ?`, limit)
}

// Notifications lists the most recently seen events.
func (s *Store) Notifications(limit int) ([]Notification, error) {
	return s.notifications(`ORDER BY last_seen DESC, event_key LIMIT ?`, limit)
}

func (s *Store) notifications(tail string, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	//nolint:gosec // tail is one of two constant clauses written in this file, never input
	rows, err := s.db.Query(`SELECT event_key, kind, severity, title, detail, link, first_seen, last_seen, status, attempts, sent_at, last_error
		FROM notifications `+tail, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []Notification{}
	for rows.Next() {
		var n Notification
		var first, last string
		var sent sql.NullString
		if err := rows.Scan(&n.Key, &n.Kind, &n.Severity, &n.Title, &n.Detail, &n.Link, &first, &last, &n.Status, &n.Attempts, &sent, &n.LastError); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: first, Valid: true}); t != nil {
			n.FirstSeen = *t
		}
		if t := parseTS(sql.NullString{String: last, Valid: true}); t != nil {
			n.LastSeen = *t
		}
		n.SentAt = parseTS(sent)
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkNotification records the outcome of one delivery attempt.
func (s *Store) MarkNotification(key, status, lastError string) error {
	var sent any
	if status == NotifySent {
		sent = ts(s.now())
	}
	_, err := s.db.Exec(`UPDATE notifications SET status = ?, attempts = attempts + 1, sent_at = COALESCE(?, sent_at), last_error = ? WHERE event_key = ?`,
		status, sent, lastError, key)
	return err
}
