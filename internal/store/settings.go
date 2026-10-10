package store

import (
	"database/sql"
	"errors"
)

// Setting keys.
const (
	// SettingSignIn is "on" when every request needs a signed-in account (ADR-0018), anything
	// else when the server runs without sign-in. Absent means off.
	SettingSignIn = "sign_in"
)

// Setting returns a server setting, or "" when it was never set.
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a server setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
