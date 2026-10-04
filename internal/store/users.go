package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Accounts, sessions and the sign-in audit trail (ADR-0018). This file stores what the
// server decides; the decisions (password policy, hashing, lockout, timeouts) live in
// internal/auth and internal/server.

// Roles, from most to least able.
const (
	RoleAdmin   = "admin"   // everything, including accounts
	RoleAnalyst = "analyst" // scan, upload, triage, edit systems
	RoleViewer  = "viewer"  // read and download only
)

// Roles lists the valid roles.
var Roles = []string{RoleAdmin, RoleAnalyst, RoleViewer}

// ErrUsernameTaken is returned when an account with the name exists.
var ErrUsernameTaken = errors.New("an account with that username already exists")

// ErrLastAdmin is returned by a change that would leave no enabled administrator.
var ErrLastAdmin = errors.New("this is the only enabled administrator; add another before removing this one")

// User is an account. PasswordHash never leaves the server.
type User struct {
	ID                int64      `json:"id"`
	Username          string     `json:"username"`
	DisplayName       string     `json:"displayName"`
	Role              string     `json:"role"`
	PasswordHash      string     `json:"-"`
	Disabled          bool       `json:"disabled"`
	MustChange        bool       `json:"mustChangePassword"`
	FailedCount       int        `json:"-"`
	LockedUntil       *time.Time `json:"lockedUntil,omitempty"`
	CreatedAt         time.Time  `json:"createdAt"`
	CreatedBy         string     `json:"createdBy"`
	PasswordChangedAt time.Time  `json:"passwordChangedAt"`
	LastLoginAt       *time.Time `json:"lastLoginAt,omitempty"`
}

const userCols = `id, username, display_name, role, password_hash, disabled, must_change, failed_count, locked_until,
	created_at, created_by, password_changed_at, last_login_at`

func scanUser(r scanner) (User, error) {
	var u User
	var disabled, must int
	var locked, last sql.NullString
	var created, changed string
	if err := r.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &disabled, &must, &u.FailedCount, &locked,
		&created, &u.CreatedBy, &changed, &last); err != nil {
		return User{}, err
	}
	u.Disabled, u.MustChange = disabled != 0, must != 0
	u.LockedUntil, u.LastLoginAt = parseTS(locked), parseTS(last)
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		u.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: changed, Valid: true}); t != nil {
		u.PasswordChangedAt = *t
	}
	return u, nil
}

// CountUsers returns how many accounts exist (zero means the server still needs its first administrator).
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser adds an account.
func (s *Store) CreateUser(username, displayName, role, passwordHash string, mustChange bool, createdBy string) (User, error) {
	now := ts(s.now())
	res, err := s.db.Exec(`INSERT INTO users (username, display_name, role, password_hash, must_change, created_at, created_by, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, username, displayName, role, passwordHash, b2i(mustChange), now, createdBy, now)
	if isConstraint(err) {
		return User{}, ErrUsernameTaken
	}
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetUser(id)
}

// CreateFirstAdmin adds the first administrator, but only while there are no accounts:
// two people racing through first-run setup cannot both become administrators.
func (s *Store) CreateFirstAdmin(username, displayName, passwordHash string) (User, error) {
	now := ts(s.now())
	res, err := s.db.Exec(`INSERT INTO users (username, display_name, role, password_hash, created_at, created_by, password_changed_at)
		SELECT ?, ?, 'admin', ?, ?, 'setup', ? WHERE NOT EXISTS (SELECT 1 FROM users)`, username, displayName, passwordHash, now, now)
	if err != nil {
		return User{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return User{}, ErrConflict
	}
	id, _ := res.LastInsertId()
	return s.GetUser(id)
}

// GetUser returns an account by id.
func (s *Store) GetUser(id int64) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// UserByName returns an account by username (case-insensitive).
func (s *Store) UserByName(username string) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, strings.TrimSpace(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// ListUsers returns every account, by username.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// enabledAdminsExcept counts enabled administrators other than id.
func enabledAdminsExcept(tx *sql.Tx, id int64) (int, error) {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, id).Scan(&n)
	return n, err
}

// UpdateUser changes an account's display name, role and enabled state. Demoting or
// disabling the last enabled administrator is refused. Disabling ends the account's sessions.
func (s *Store) UpdateUser(id int64, displayName, role string, disabled bool) (User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	u, err := scanUser(tx.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if u.Role == RoleAdmin && !u.Disabled && (role != RoleAdmin || disabled) {
		if n, err := enabledAdminsExcept(tx, id); err != nil {
			return User{}, err
		} else if n == 0 {
			return User{}, ErrLastAdmin
		}
	}
	if _, err := tx.Exec(`UPDATE users SET display_name = ?, role = ?, disabled = ? WHERE id = ?`, displayName, role, b2i(disabled), id); err != nil {
		return User{}, err
	}
	if disabled || role != u.Role {
		// A change of role or a disabled account takes effect now, not at the next sign-in.
		if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUser(id)
}

// DeleteUser removes an account and its sessions; the last enabled administrator stays.
func (s *Store) DeleteUser(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	u, err := scanUser(tx.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin && !u.Disabled {
		if n, err := enabledAdminsExcept(tx, id); err != nil {
			return err
		} else if n == 0 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetPassword replaces an account's password hash, clears any lockout and ends every
// session of the account except keepSession (the one making the change, or 0 for none).
func (s *Store) SetPassword(id int64, hash string, mustChange bool, keepSession int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE users SET password_hash = ?, must_change = ?, failed_count = 0, locked_until = NULL, password_changed_at = ? WHERE id = ?`,
		hash, b2i(mustChange), ts(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ? AND id != ?`, id, keepSession); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordLoginFailure counts a failed password for an account and locks it for lockFor once
// the count reaches threshold. It returns the new count and the lock, if one was set.
func (s *Store) RecordLoginFailure(id int64, threshold int, lockFor time.Duration) (int, *time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`UPDATE users SET failed_count = failed_count + 1 WHERE id = ? RETURNING failed_count`, id).Scan(&n); err != nil {
		return 0, nil, err
	}
	var until *time.Time
	if n >= threshold {
		t := s.now().Add(lockFor).UTC()
		until = &t
		if _, err := tx.Exec(`UPDATE users SET locked_until = ?, failed_count = 0 WHERE id = ?`, ts(t), id); err != nil {
			return 0, nil, err
		}
	}
	return n, until, tx.Commit()
}

// RecordLoginSuccess clears the failure count and stamps the sign-in time.
func (s *Store) RecordLoginSuccess(id int64) error {
	_, err := s.db.Exec(`UPDATE users SET failed_count = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`, ts(s.now()), id)
	return err
}

// UnlockUser clears a lockout (an administrator's action).
func (s *Store) UnlockUser(id int64) error {
	res, err := s.db.Exec(`UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- sessions ----------------------------------------------------------------------------

// Session is a signed-in browser. The token itself is never stored.
type Session struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"-"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Client     string    `json:"client"`
	UserAgent  string    `json:"userAgent"`
}

func scanSession(r scanner) (Session, error) {
	var v Session
	var c, l, e string
	if err := r.Scan(&v.ID, &v.UserID, &c, &l, &e, &v.Client, &v.UserAgent); err != nil {
		return Session{}, err
	}
	for _, p := range []struct {
		s string
		t *time.Time
	}{{c, &v.CreatedAt}, {l, &v.LastSeenAt}, {e, &v.ExpiresAt}} {
		if t := parseTS(sql.NullString{String: p.s, Valid: true}); t != nil {
			*p.t = *t
		}
	}
	return v, nil
}

const sessionCols = `id, user_id, created_at, last_seen_at, expires_at, client, user_agent`

// CreateSession stores a new session under the hash of its token.
func (s *Store) CreateSession(tokenHash string, userID int64, expires time.Time, client, userAgent string) (Session, error) {
	now := ts(s.now())
	if len(userAgent) > 200 {
		userAgent = userAgent[:200]
	}
	res, err := s.db.Exec(`INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, client, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tokenHash, userID, now, now, ts(expires), client, userAgent)
	if err != nil {
		return Session{}, err
	}
	id, _ := res.LastInsertId()
	return scanSession(s.db.QueryRow(`SELECT `+sessionCols+` FROM sessions WHERE id = ?`, id))
}

// SessionByHash returns a session and its account.
func (s *Store) SessionByHash(tokenHash string) (Session, User, error) {
	v, err := scanSession(s.db.QueryRow(`SELECT `+sessionCols+` FROM sessions WHERE token_hash = ?`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, err
	}
	u, err := s.GetUser(v.UserID)
	return v, u, err
}

// TouchSession records activity on a session.
func (s *Store) TouchSession(id int64) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, ts(s.now()), id)
	return err
}

// DeleteSession ends one session; userID, when not 0, must own it.
func (s *Store) DeleteSession(id, userID int64) error {
	q, args := `DELETE FROM sessions WHERE id = ?`, []any{id}
	if userID != 0 {
		q, args = q+` AND user_id = ?`, append(args, userID)
	}
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UserSessions lists an account's sessions, newest first.
func (s *Store) UserSessions(userID int64) ([]Session, error) {
	rows, err := s.db.Query(`SELECT `+sessionCols+` FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []Session
	for rows.Next() {
		v, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// PruneSessions deletes sessions past their absolute expiry or idle longer than idle.
func (s *Store) PruneSessions(idle time.Duration) error {
	now := s.now()
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ?`, ts(now), ts(now.Add(-idle)))
	return err
}

// ---- audit -------------------------------------------------------------------------------

// AuthEvent is one line of the sign-in audit trail.
type AuthEvent struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Username string    `json:"username"`
	Actor    string    `json:"actor"`
	Client   string    `json:"client"`
	Detail   string    `json:"detail"`
}

// maxAuthEvents bounds the audit trail; the oldest lines go first.
const maxAuthEvents = 5000

// AddAuthEvent appends to the audit trail. Never pass a password or a token.
func (s *Store) AddAuthEvent(e AuthEvent) error {
	if len(e.Username) > 100 {
		e.Username = e.Username[:100]
	}
	if _, err := s.db.Exec(`INSERT INTO auth_events (at, kind, username, actor, client, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		ts(s.now()), e.Kind, e.Username, e.Actor, e.Client, e.Detail); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM auth_events WHERE id <= (SELECT MAX(id) FROM auth_events) - ?`, maxAuthEvents)
	return err
}

// AuthEvents returns the newest events first.
func (s *Store) AuthEvents(limit int) ([]AuthEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT at, kind, username, actor, client, detail FROM auth_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []AuthEvent
	for rows.Next() {
		var e AuthEvent
		var at string
		if err := rows.Scan(&at, &e.Kind, &e.Username, &e.Actor, &e.Client, &e.Detail); err != nil {
			return nil, err
		}
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			e.At = *t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
