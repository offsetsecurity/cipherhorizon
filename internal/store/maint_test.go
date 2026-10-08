package store_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/store"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sslv2Report(spki string, sslv2 bool) []byte {
	rep := tlsprobe.Report{
		SchemaVersion: tlsprobe.SchemaVersion,
		Protocols:     []tlsprobe.ProtocolResult{{Version: "SSLv2", Supported: sslv2}, {Version: "TLSv1.2", Supported: true}},
		Certificates: []tlsprobe.CertResult{{Source: "tls-default", Chain: []tlsprobe.CertInfo{
			{Subject: "CN=leaf", Issuer: "CN=CA", SHA256: strings.Repeat(spki[:1], 64), SPKISHA256: spki,
				NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
			{Subject: "CN=CA", Issuer: "CN=CA", SHA256: strings.Repeat("f", 64), SPKISHA256: strings.Repeat("e", 64)},
		}}},
	}
	b, _ := json.Marshal(rep)
	return b
}

// The DROWN index lists the leaf keys of endpoints whose latest scan accepted SSLv2, and only those.
func TestSSLv2LeafKeysFollowTheLatestScan(t *testing.T) {
	s := openStore(t)
	old, _ := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "old", Host: "old.test", Port: 443})
	cur, _ := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "cur", Host: "cur.test", Port: 443})
	keyA, keyB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	finishWith(t, s, old, sslv2Report(keyA, true))
	finishWith(t, s, cur, sslv2Report(keyB, false))
	keys, err := s.SSLv2LeafKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].AssetID != old.ID || keys[0].SPKI != keyA || keys[0].Address != "old.test:443" {
		t.Fatalf("keys = %+v, want only old.test's leaf key (not its CA's, not cur.test's)", keys)
	}
	// Once the latest scan no longer accepts SSLv2, the endpoint leaves the index.
	finishWith(t, s, old, sslv2Report(keyA, false))
	if keys, _ := s.SSLv2LeafKeys(); len(keys) != 0 {
		t.Fatalf("after SSLv2 was turned off: %+v", keys)
	}
}

// Retention removes the projections of the scans it deletes as it goes, not by sweeping the graph.
func TestRetentionRemovesItsOwnProjections(t *testing.T) {
	defer func(old int) { store.Retention = old }(store.Retention)
	store.Retention = 2
	s := openStore(t)
	a, _ := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "a", Host: "a.test", Port: 443})
	for i := 0; i < 4; i++ {
		finishWith(t, s, a, report(fp(byte('a'+i)), 2048))
	}
	ents, err := s.Entities("certificate", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("certificates after retention kept 2 scans: %d, want 2 (the two deleted scans' certificates go with them)", len(ents))
	}
}

// Host uploads are bounded by bytes, per host and in total, not only by count.
func TestHostSnapshotsAreBoundedByBytes(t *testing.T) {
	defer func(k int64, q int64) { store.HostSnapshotBytesKept, store.HostSnapshotQuota = k, q }(store.HostSnapshotBytesKept, store.HostSnapshotQuota)
	s := openStore(t)
	h, _, err := s.UpsertHostAsset("web-01")
	if err != nil {
		t.Fatal(err)
	}
	doc := hostCBOM("web-01", "cipherhorizon-collector")
	store.HostSnapshotBytesKept = int64(len(doc))*2 + 10 // room for two uploads per host
	for i := 0; i < 4; i++ {
		if _, err := s.AddHostSnapshot(h.ID, doc, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	snaps, _ := s.HostSnapshots(h.ID, 50)
	if len(snaps) != 2 {
		t.Fatalf("kept %d uploads, want 2 (the byte budget)", len(snaps))
	}
	store.HostSnapshotQuota = int64(len(doc)) * 2 // full
	if _, err := s.AddHostSnapshot(h.ID, doc, []byte(`{}`)); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("an upload past the server-wide quota: %v, want ErrQuota", err)
	}
}

// Concurrent evidence changes share correlation runs and every caller still returns only after a
// run that saw its change.
func TestConcurrentUploadsAreCorrelated(t *testing.T) {
	s := openStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("host-%d", i)
			h, _, err := s.UpsertHostAsset(name)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := s.AddHostSnapshot(h.ID, hostCBOM(name, "cipherhorizon-collector"), []byte(`{}`)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := s.Maintain(); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Stale {
		t.Fatal("the graph is stale after concurrent uploads")
	}
}

// Stored times sort as the times do: migration 10 rewrites the older variable-width form, and
// everything written since has nine fractional digits.
func TestTimestampsAreFixedWidthAndSortAsTimes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	if err := store.BuildLegacyDB(path, 9); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []string{"2026-10-06T10:00:05Z", "2026-10-06T10:00:05.3Z"} {
		if _, err := db.Exec(`INSERT INTO auth_events (at, kind) VALUES (?, 'login')`, at); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO audit_log (at, actor, object_kind, object_id, action) VALUES (?, 'x', 'system', 1, 'edit')`, at); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	for _, table := range []string{"auth_events", "audit_log"} {
		n, err := s.QueryIntForTest(`SELECT COUNT(*) FROM ` + table + ` WHERE at IN ('2026-10-06T10:00:05.000000000Z', '2026-10-06T10:00:05.300000000Z')`)
		if err != nil || n != 2 {
			t.Fatalf("%s: %d rewritten (%v), want 2", table, n, err)
		}
	}
	// The audit log is append-only again after the rewrite.
	if err := s.ExecForTest(`UPDATE audit_log SET actor = 'y'`); err == nil {
		t.Fatal("audit_log accepted an update after migration 10")
	}
	n, _ := s.QueryIntForTest(`SELECT COUNT(*) FROM auth_events a JOIN auth_events b ON a.at < b.at WHERE a.at LIKE '%05.000%'`)
	if n != 1 {
		t.Fatalf("the whole second does not sort before the later fraction")
	}
}
