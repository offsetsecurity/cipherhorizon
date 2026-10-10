package store_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// UX-REVIEW-008 S3: sign-in is off by default, but an upgrade never opens a server that had
// accounts: migration 12 turns the setting on wherever an account exists.
func TestExistingAccountsKeepSignInOn(t *testing.T) {
	for name, withUser := range map[string]bool{"with an account": true, "without": false} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v11.db")
			if err := store.BuildLegacyDB(path, 11); err != nil {
				t.Fatal(err)
			}
			if withUser {
				db, err := sql.Open("sqlite", "file:"+path)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO users (username, display_name, role, password_hash, must_change, created_at, created_by, password_changed_at)
					VALUES ('admin', '', 'admin', 'x', 0, '2026-10-01T00:00:00.000000000Z', 'setup', '2026-10-01T00:00:00.000000000Z')`)
				_ = db.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close() //nolint:errcheck // test
			v, err := s.Setting(store.SettingSignIn)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if withUser {
				want = "on"
			}
			if v != want {
				t.Fatalf("sign_in = %q, want %q", v, want)
			}
			if err := s.SetSetting(store.SettingSignIn, "off"); err != nil {
				t.Fatal(err)
			}
			if v, _ := s.Setting(store.SettingSignIn); v != "off" {
				t.Fatalf("after SetSetting: %q", v)
			}
		})
	}
}
