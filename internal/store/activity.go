package store

import (
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// RecordAction appends one change made through the API to the audit log (PRD-007 REQ-AC-2): who,
// what kind of object, which one, what was done, and a short detail. The detail names objects
// (ids, finding keys, an endpoint's address), never a secret or a request body.
//
// client is the address the request came from; it matters most while sign-in is off, when the
// actor is the anonymous "local" operator (UX-REVIEW-008 D4).
func (s *Store) RecordAction(actor, client, kind string, id int64, action, detail, reason string) error {
	if actor == "" {
		actor = "unknown"
	}
	rec := map[string]string{"detail": detail}
	if client != "" {
		rec["client"] = client
	}
	after, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO audit_log (at, actor, object_kind, object_id, action, before_json, after_json, reason) VALUES (?, ?, ?, ?, ?, '{}', ?, ?)`,
		ts(s.now()), actor, kind, id, action, string(after), reason)
	return err
}

// ActivityEntry is one line of the Activity list: a change (from the audit log) or a sign-in
// event (from the sign-in log), in one shape.
type ActivityEntry struct {
	At         time.Time `json:"at"`
	Source     string    `json:"source"` // "change" or "sign-in"
	Actor      string    `json:"actor"`  // who did it ("" for a failed sign-in by nobody known)
	Action     string    `json:"action"`
	ObjectKind string    `json:"objectKind,omitempty"`
	ObjectID   int64     `json:"objectId,omitempty"`
	Username   string    `json:"username,omitempty"` // the account a sign-in event is about
	Client     string    `json:"client,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

// ActivityFilter narrows the Activity list. Empty fields match everything.
type ActivityFilter struct {
	Person string // the actor, or the account a sign-in event is about
	Source string // "change" or "sign-in"
	Limit  int    // at most 5000; default 500
}

// Activity lists changes and sign-in events together, newest first.
func (s *Store) Activity(f ActivityFilter) ([]ActivityEntry, error) {
	if f.Limit <= 0 {
		f.Limit = 500
	}
	if f.Limit > 5000 {
		f.Limit = 5000
	}
	var parts []string
	var args []any
	if f.Source == "" || f.Source == "change" {
		q := `SELECT at, 'change', actor, action, object_kind, object_id, '', '', after_json, reason FROM audit_log`
		if f.Person != "" {
			q += ` WHERE actor = ?`
			args = append(args, f.Person)
		}
		parts = append(parts, q)
	}
	if f.Source == "" || f.Source == "sign-in" {
		q := `SELECT at, 'sign-in', actor, kind, '', 0, username, client, detail, '' FROM auth_events`
		if f.Person != "" {
			q += ` WHERE actor = ? OR username = ?`
			args = append(args, f.Person, f.Person)
		}
		parts = append(parts, q)
	}
	if len(parts) == 0 {
		return []ActivityEntry{}, nil
	}
	args = append(args, f.Limit)
	// The query is built from fixed fragments; every value is a parameter.
	rows, err := s.db.Query(strings.Join(parts, " UNION ALL ")+` ORDER BY 1 DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []ActivityEntry{}
	for rows.Next() {
		var e ActivityEntry
		var at, detail string
		if err := rows.Scan(&at, &e.Source, &e.Actor, &e.Action, &e.ObjectKind, &e.ObjectID, &e.Username, &e.Client, &detail, &e.Reason); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			e.At = *t
		}
		e.Detail = detail
		if e.Source == "change" {
			e.Detail, e.Client = changeDetail(detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// changeDetail turns an audit row's after_json into one readable line: the "detail" an API
// action recorded, or, for the system changes recorded with before and after values, the fields
// that changed.
func changeDetail(after string) (detail, client string) {
	var m map[string]any
	if json.Unmarshal([]byte(after), &m) != nil {
		return "", ""
	}
	client, _ = m["client"].(string)
	if d, ok := m["detail"].(string); ok && (len(m) == 1 || len(m) == 2 && client != "") {
		return d, client
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", "), client
}
