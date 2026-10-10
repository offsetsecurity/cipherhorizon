package store_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// REQ-NFR-1: performance design targets are measured and reported, not promised. Run it with
//
//	CIPHERHORIZON_SCALE=1 go test ./internal/store -run TestListViewsAtScale -v
//
// It builds 5,000 systems holding 50,000 certificates, then times the queries behind the list views
// (estate ranking, certificates, systems, links, entities) and the correlation pass. The target is
// under one second at the 95th percentile for each list view on a developer laptop; this test fails at
// five times that so a regression cannot pass unnoticed, and logs the real figures for the QA report.
func TestListViewsAtScale(t *testing.T) {
	if os.Getenv("CIPHERHORIZON_SCALE") == "" {
		t.Skip("set CIPHERHORIZON_SCALE=1 to run the scale measurement")
	}
	path := filepath.Join(t.TempDir(), "scale.db")
	if keep := os.Getenv("CIPHERHORIZON_SCALE_DB"); keep != "" {
		path = keep // keep the database, to time the HTTP views against a real server
	}
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close() //nolint:errcheck // test
	const systems, certsPer = 5000, 10
	t0 := time.Now()
	for i := 0; i < systems; i++ {
		if _, err := st.CreateAsset(store.Asset{Kind: store.KindTLS, Name: fmt.Sprintf("svc-%05d", i), Host: fmt.Sprintf("svc-%05d.example.test", i), Port: 443}); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(30000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ent, _ := tx.Prepare(`INSERT INTO entities (kind, key, name, attrs_json) VALUES ('certificate', ?, ?, ?)`)
	src, _ := tx.Prepare(`INSERT INTO sources (class, stream, ref_kind, ref_id, asset_id, received_at, observed_at) VALUES ('scanner', 'network', 'scan', ?, ?, ?, ?)`)
	obs, _ := tx.Prepare(`INSERT INTO observations (source_id, entity_id, relation, rung, class, method, quality, observed_at) VALUES (?, ?, 'presents', 'exercised', 3, 'tls-handshake', 'authoritative', ?)`)
	notAfter := time.Now().Add(40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	for i := 0; i < systems; i++ {
		r, err := src.Exec(1000000+i, i+1, now, now)
		if err != nil {
			t.Fatal(err)
		}
		sid, _ := r.LastInsertId()
		for c := 0; c < certsPer; c++ {
			key := fmt.Sprintf("cert:%064x", i*certsPer+c)
			attrs := fmt.Sprintf(`{"subject":"CN=svc-%d-%d","issuer":"CN=Test CA","keyAlg":"RSA","keyBits":"2048","sigAlg":"SHA256withRSA","notAfter":%q,"isCA":"false"}`, i, c, notAfter)
			er, err := ent.Exec(key, fmt.Sprintf("svc-%d-%d", i, c), attrs)
			if err != nil {
				t.Fatal(err)
			}
			eid, _ := er.LastInsertId()
			if _, err := obs.Exec(sid, eid, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Logf("built %d systems and %d certificates in %s", systems, systems*certsPer, time.Since(t0).Round(time.Millisecond))

	measure := func(name string, limit time.Duration, fn func() error) {
		t.Helper()
		var worst time.Duration
		var all []time.Duration
		for i := 0; i < 5; i++ {
			s := time.Now()
			if err := fn(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			d := time.Since(s)
			all = append(all, d)
			if d > worst {
				worst = d
			}
		}
		t.Logf("%-28s worst of 5: %s (all: %v)", name, worst.Round(time.Millisecond), all)
		if worst > limit {
			t.Errorf("%s took %s, over %s (five times the 1 s design target)", name, worst, limit)
		}
	}
	const limit = 5 * time.Second
	measure("ListSystems", limit, func() error { _, err := st.ListSystems(); return err })
	measure("Certificates", limit, func() error { _, err := st.Certificates(); return err })
	measure("PriorityInputs+Prioritise", limit, func() error {
		in, err := st.PriorityInputs()
		if err != nil {
			return err
		}
		if r := eval.Prioritise(in, time.Now()); len(r) != systems {
			return fmt.Errorf("ranked %d of %d", len(r), systems)
		}
		return nil
	})
	measure("Links(all)", limit, func() error { _, err := st.Links(""); return err })
	measure("Entities(certificate)", limit, func() error { _, err := st.Entities("certificate", 5000); return err })
	measure("Correlate", limit, func() error { return st.Correlate() })
}
