package store_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/estate"
	"github.com/example/cipherhorizon/internal/store"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// The first three migrations are what 0.1.0 shipped. Editing one would make the
// legacy-database tests meaningless and would change what an existing install runs.
func TestFrozenMigrationsAreUnchanged(t *testing.T) {
	want := map[int]string{
		1: "322ac65ad005a250ae183424c9cd2cbc554a298b64ef9fc3bcfaf239e93a7c1a",
		2: "e508e5434edde4d2fbb59c8d0b6903ddf105258b8958d793dfd84c1006790fb0",
		3: "890f9fbeee7148eaab374f896d7aa1238d8499fb630994ca99cf2b813e88074e",
	}
	for v, h := range want {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(store.FrozenMigration(v)))); got != h {
			t.Errorf("migration %d changed (hash %s); released migrations are never edited, add a new one", v, got)
		}
	}
}

// ---- fixtures -------------------------------------------------------------------------------

func report(fp string, bits int) []byte {
	rep := tlsprobe.Report{
		SchemaVersion: tlsprobe.SchemaVersion,
		Protocols:     []tlsprobe.ProtocolResult{{Version: "TLSv1.3", Supported: true}},
		Suites:        []tlsprobe.SuiteResult{{Version: "TLSv1.3", ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", AEAD: true}},
		Certificates: []tlsprobe.CertResult{{Source: "tls-default", Chain: []tlsprobe.CertInfo{{
			Subject: "CN=" + fp[:6] + ".test", Issuer: "CN=CA", SHA256: fp, PublicKey: tlsprobe.KeyInfo{Algorithm: "RSA", Bits: bits},
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}}}},
	}
	b, _ := json.Marshal(rep)
	return b
}

func fp(c byte) string { return strings.Repeat(string(c), 64) }

func hostCBOM(name string, producer string) []byte {
	comps := []cdx.Component{
		{BOMRef: "sw1", Type: cdx.ComponentTypeLibrary, Name: "libcrypto", Version: "3.5.7", Properties: &[]cdx.Property{
			{Name: "cipherhorizon:claim", Value: "present"}, {Name: "cipherhorizon:method", Value: "pe.version-info@1"}, {Name: "cipherhorizon:method-quality", Value: "parsed"}}},
		{BOMRef: "algo:aes-256-gcm", Type: cdx.ComponentTypeCryptographicAsset, Name: "AES-256-GCM",
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm}},
	}
	deps := []cdx.Dependency{{Ref: "sw1", Provides: &[]string{"algo:aes-256-gcm"}}}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeDevice, Name: name},
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: producer, Version: "1"}}}}
	bom.Components, bom.Dependencies = &comps, &deps
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// legacy builds a database as 0.1.0 left it and fills it through raw SQL, exactly the
// shape of rows an existing install holds.
func legacy(t *testing.T) (path string, raw map[string][]byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "old.db")
	if err := store.BuildLegacyDB(path, 3); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	now := "2026-05-01T10:00:00Z"
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO assets (id, kind, name, host, port, created_at, updated_at) VALUES
		(1, 'tls-endpoint', 'shop.example.test:443', 'shop.example.test', 443, ?, ?),
		(2, 'tls-endpoint', 'api.example.test:443', 'api.example.test', 443, ?, ?),
		(3, 'host', 'web-01', 'web-01', 0, ?, ?)`, now, now, now, now, now, now)
	raw = map[string][]byte{"scan1": report(fp('a'), 2048), "scan2": report(fp('a'), 2048), "scan3": report(fp('b'), 3072), "snap1": hostCBOM("web-01", "cipherhorizon-collector"), "snap2": hostCBOM("web-01", "some-other-tool")}
	mustExec(`INSERT INTO scans (id, asset_id, status, trigger, queued_at, finished_at, band, score, report_json, eval_json) VALUES
		(1, 1, 'done', 'manual', ?, ?, 'Strong', 90, ?, x'7b7d'),
		(2, 1, 'done', 'manual', ?, ?, 'Strong', 90, ?, x'7b7d'),
		(3, 2, 'done', 'manual', ?, ?, 'Fair', 70, ?, x'7b7d'),
		(4, 2, 'failed', 'manual', ?, ?, '', -1, NULL, NULL)`,
		now, "2026-05-01T10:01:00Z", raw["scan1"], now, "2026-05-02T10:01:00Z", raw["scan2"], now, "2026-05-02T10:02:00Z", raw["scan3"], now, "2026-05-03T10:00:00Z")
	mustExec(`INSERT INTO host_snapshots (id, asset_id, at, cbom_json, summary_json) VALUES
		(1, 3, '2026-05-01T11:00:00Z', ?, ?), (2, 3, '2026-05-02T11:00:00Z', ?, ?)`,
		raw["snap1"], []byte(`{"producer":"cipherhorizon-collector 1"}`), raw["snap2"], []byte(`{"producer":"some-other-tool 1"}`))
	mustExec(`INSERT INTO asset_links (asset_id, linked_asset_id, created_at) VALUES (1, 3, ?)`, now)
	mustExec(`INSERT INTO finding_status (asset_id, finding_key, status, note, set_at) VALUES (1, 'CERT.EXPIRED', 'acknowledged', 'n', ?)`, now)
	return path, raw
}

func count(t *testing.T, s *store.Store, q string, args ...any) int {
	t.Helper()
	n, err := s.QueryIntForTest(q, args...)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// ---- migration ------------------------------------------------------------------------------

// AC-MOD-2 (REQ-MOD-5): a 0.1.0 database migrates forward after a backup; every raw
// row is untouched; assets a person had linked become one system; the graph is built.
func TestLegacyDatabaseMigratesWithoutLosingAnything(t *testing.T) {
	path, raw := legacy(t)
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if v := count(t, s, `SELECT MAX(version) FROM schema_migrations`); v < 4 {
		t.Errorf("schema version %d, want at least 4", v)
	}
	// Raw rows unchanged.
	if n := count(t, s, `SELECT COUNT(*) FROM scans`); n != 4 {
		t.Errorf("%d scans, want 4", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM host_snapshots`); n != 2 {
		t.Errorf("%d snapshots, want 2", n)
	}
	got, err := s.Report(1)
	if err != nil || !bytes.Equal(got, raw["scan1"]) {
		t.Errorf("scan 1 report changed: %v", err)
	}
	if b, err := s.HostCBOM(1); err != nil || !bytes.Equal(b, raw["snap1"]) {
		t.Errorf("snapshot 1 changed: %v", err)
	}
	if fs, err := s.FindingStatuses(1); err != nil || fs["CERT.EXPIRED"].Status != "acknowledged" {
		t.Errorf("finding status lost: %v %v", fs, err)
	}

	// Systems: the linked endpoint and host share one (the host's name); the other endpoint has its own.
	systems, err := s.ListSystems()
	if err != nil {
		t.Fatal(err)
	}
	if len(systems) != 2 {
		t.Fatalf("%d systems, want 2: %+v", len(systems), systems)
	}
	names := []string{systems[0].Name, systems[1].Name}
	sort.Strings(names)
	if names[0] != "api.example.test:443" || names[1] != "web-01" {
		t.Errorf("system names = %v", names)
	}
	for _, sys := range systems {
		if sys.Name == "web-01" && len(sys.Assets) != 2 {
			t.Errorf("web-01 has %d assets, want the host and its linked endpoint", len(sys.Assets))
		}
		if len(sys.Provided()) != 0 {
			t.Errorf("a migrated system claims metadata nobody provided: %v", sys.Provided())
		}
	}

	// The manual link of 0.1.0 became a confirmed link with source operator (REQ-COR-7).
	links, err := s.Links("confirmed")
	if err != nil || len(links) != 1 || len(links[0].Rules) != 1 || links[0].Rules[0].ID != "manual" || links[0].AssetID != 1 {
		t.Errorf("links after migration = %+v, %v", links, err)
	}

	// A backup was made, owner-only, and it opens as the old database.
	backups, _ := filepath.Glob(path + ".bak-v3-*")
	if len(backups) != 1 {
		t.Fatalf("backups = %v, want exactly one", backups)
	}
	old, err := sql.Open("sqlite", "file:"+backups[0])
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close() //nolint:errcheck // test
	var scans int
	if err := old.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&scans); err != nil || scans != 4 {
		t.Errorf("backup scans = %d, %v", scans, err)
	}
	var hasSystems int
	_ = old.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'systems'`).Scan(&hasSystems)
	if hasSystems != 0 {
		t.Error("the backup was taken after the migration")
	}

	// The graph was built from the stored documents.
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Stale || st.Version != store.ProjectionVersion {
		t.Errorf("projection state = %+v", st)
	}
	if st.Entities["certificate"] != 2 || st.Entities["software"] != 1 || st.Entities["algorithm"] != 1 {
		t.Errorf("entities = %v", st.Entities)
	}
	// Two failed/no-report scans project nothing; the three done scans and two snapshots do.
	if st.Sources != 5 {
		t.Errorf("sources = %d, want 5", st.Sources)
	}
}

// A legacy snapshot is attributed to this product's collector only when its recorded
// producer says so; anything else stays imported (SR-03).
func TestLegacySnapshotsKeepOnlyTheClassTheyCanProve(t *testing.T) {
	path, _ := legacy(t)
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if n := count(t, s, `SELECT COUNT(*) FROM sources WHERE ref_kind = 'host_snapshot' AND ref_id = 1 AND class = 'collector'`); n != 1 {
		t.Error("the collector's own snapshot lost its class")
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sources WHERE ref_kind = 'host_snapshot' AND ref_id = 2 AND class = 'imported'`); n != 1 {
		t.Error("another tool's snapshot was attributed to the collector")
	}
}

// AC-MOD-4 (SR-10): a migration that fails part-way leaves the database as it was.
func TestFailedMigrationLeavesTheDatabaseIntact(t *testing.T) {
	path, _ := legacy(t)
	restore := store.SetPostMigration(4, func(*sql.Tx, time.Time) error { return errors.New("injected failure") })
	defer restore()
	if _, err := store.Open(path); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("Open = %v, want the injected failure", err)
	}
	restore()

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	var v, systems, cols int
	_ = db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	_ = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'systems'`).Scan(&systems)
	_ = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('assets') WHERE name = 'system_id'`).Scan(&cols)
	if v != 3 || systems != 0 || cols != 0 {
		t.Errorf("after a failed migration: version %d, systems table %d, assets.system_id %d; want 3, 0, 0", v, systems, cols)
	}
	// And a retry succeeds.
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	_ = s.Close()
}

// ---- projection -----------------------------------------------------------------------------

func finishWith(t *testing.T, s *store.Store, a store.Asset, rep []byte) int64 {
	t.Helper()
	sc, _, err := s.EnqueueScan(a.ID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimNext(); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(sc.ID, store.Result{Report: rep, Evaluation: []byte(`{}`), Band: "Strong", Score: 90}); err != nil {
		t.Fatal(err)
	}
	return sc.ID
}

// dump lists the graph without ids so two builds can be compared.
func dump(t *testing.T, s *store.Store) []string {
	t.Helper()
	var out []string
	ents, err := s.Entities("", 5000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		ks := make([]string, 0, len(e.Attrs))
		for k := range e.Attrs {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var attrs []string
		for _, k := range ks {
			attrs = append(attrs, k+"="+e.Attrs[k])
		}
		out = append(out, fmt.Sprintf("E %s %s %q %s seen=%d current=%v", e.Kind, e.Key, e.Name, strings.Join(attrs, ";"), e.Seen, e.Current))
	}
	systems, err := s.ListSystems()
	if err != nil {
		t.Fatal(err)
	}
	for _, sys := range systems {
		obs, err := s.SystemObservations(sys.ID, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			out = append(out, fmt.Sprintf("O %s %s %s %s %s via=%s %s/%s %s cur=%v", sys.Name, o.SourceKind, o.Class, o.Entity.Key, o.Relation, o.Via, o.Rung, o.Quality, o.Method, o.Current))
		}
	}
	sort.Strings(out)
	return out
}

// AC-MOD-1 (REQ-MOD-1): dropping the projection and rebuilding it from the stored
// documents gives exactly the graph incremental projection built.
func TestRebuildEqualsIncrementalProjection(t *testing.T) {
	s, _ := open(t)
	ep := asset(t, s, "shop.example.test", 443)
	host, _, err := s.UpsertHostAsset("web-01")
	if err != nil {
		t.Fatal(err)
	}
	finishWith(t, s, ep, report(fp('a'), 2048))
	finishWith(t, s, ep, report(fp('a'), 2048))
	finishWith(t, s, ep, report(fp('c'), 4096))
	if _, err := s.AddHostSnapshotAs(host.ID, hostCBOM("web-01", "cipherhorizon-collector"), []byte(`{}`), estate.ClassCollector, "tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddHostSnapshot(host.ID, hostCBOM("web-01", "cipherhorizon-collector"), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	before := dump(t, s)
	if len(before) == 0 {
		t.Fatal("empty graph")
	}
	counts, err := s.RebuildGraph()
	if err != nil {
		t.Fatal(err)
	}
	if counts.Entities == 0 || counts.Observations == 0 {
		t.Errorf("rebuild produced %+v", counts)
	}
	after := dump(t, s)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("rebuild differs from incremental projection\nbefore:\n%s\nafter:\n%s", strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	// Rebuilding twice is the same as once.
	if _, err := s.RebuildGraph(); err != nil {
		t.Fatal(err)
	}
	if again := dump(t, s); strings.Join(again, "\n") != strings.Join(after, "\n") {
		t.Error("a second rebuild changed the graph")
	}
}

// REQ-MOD-3, REQ-CERT-6: the same certificate seen by two scans (and later by a host)
// is one entity; the entity knows when it was first and last seen.
func TestTheSameCertificateIsOneEntity(t *testing.T) {
	s, c := open(t)
	a := asset(t, s, "one.test", 443)
	b := asset(t, s, "two.test", 443)
	finishWith(t, s, a, report(fp('a'), 2048))
	c.advance(48 * time.Hour)
	finishWith(t, s, b, report(fp('a'), 2048))
	certs, err := s.Entities("certificate", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Key != "cert:"+fp('a') || certs[0].Seen != 2 {
		t.Fatalf("certificates = %+v", certs)
	}
	if certs[0].LastSeen.Sub(certs[0].FirstSeen) < 47*time.Hour {
		t.Errorf("first %v, last %v", certs[0].FirstSeen, certs[0].LastSeen)
	}
	if certs[0].Attrs["keyBits"] != "2048" {
		t.Errorf("attrs = %v", certs[0].Attrs)
	}
}

// REQ-MOD-7: an entity a newer scan no longer shows is "no longer observed", not deleted.
func TestAnEntityNoLongerObservedIsFlaggedNotDeleted(t *testing.T) {
	s, c := open(t)
	a := asset(t, s, "one.test", 443)
	finishWith(t, s, a, report(fp('a'), 2048))
	c.advance(time.Hour)
	finishWith(t, s, a, report(fp('b'), 2048)) // the certificate was replaced
	certs, err := s.Entities("certificate", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("%d certificates, want the old one kept too", len(certs))
	}
	for _, e := range certs {
		want := e.Key == "cert:"+fp('b')
		if e.Current != want {
			t.Errorf("%s current = %v, want %v", e.Key, e.Current, want)
		}
	}
}

// REQ-MOD-6, ADR-0006: the streams stay separate. A scan is network evidence from the
// scanner; a host upload is host evidence, and never at the exercised rung.
func TestStreamsAndSourceClassesStaySeparate(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	host, _, _ := s.UpsertHostAsset("web-01")
	finishWith(t, s, a, report(fp('a'), 2048))
	if _, err := s.AddHostSnapshotAs(host.ID, hostCBOM("web-01", "cipherhorizon-collector"), []byte(`{}`), estate.ClassCollector, ""); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sources WHERE ref_kind = 'scan' AND (class <> 'scanner' OR stream <> 'network')`); n != 0 {
		t.Errorf("%d scan sources are not scanner/network", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sources WHERE ref_kind = 'host_snapshot' AND stream <> 'host'`); n != 0 {
		t.Errorf("%d snapshot sources are not on the host stream", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM observations o JOIN sources s ON s.id = o.source_id WHERE s.stream = 'host' AND o.rung = 'exercised'`); n != 0 {
		t.Errorf("%d host observations at the exercised rung", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM observations WHERE method = '' OR quality = '' OR rung = ''`); n != 0 {
		t.Errorf("%d observations without method, quality or rung", n)
	}
}

// AC-MOD-3: the schema itself refuses an observation without a method.
func TestSchemaRefusesAnObservationWithoutAMethod(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	finishWith(t, s, a, report(fp('a'), 2048))
	err := s.ExecForTest(`INSERT INTO observations (source_id, entity_id, relation, rung, class, method, quality, observed_at)
		SELECT id, (SELECT id FROM entities LIMIT 1), 'offers', 'present', 0, '', 'parsed', 'x' FROM sources LIMIT 1`)
	if err == nil {
		t.Error("an observation with an empty method was accepted")
	}
	if err := s.ExecForTest(`INSERT INTO sources (class, stream, ref_kind, ref_id, received_at, observed_at) VALUES ('trusted', 'host', 'scan', 999, 'x', 'x')`); err == nil {
		t.Error("an unknown source class was accepted")
	}
}

// SR-03: a host upload is imported unless the channel says otherwise.
func TestAHostUploadIsImportedUnlessTheChannelSaysOtherwise(t *testing.T) {
	s, _ := open(t)
	host, _, _ := s.UpsertHostAsset("web-01")
	id, err := s.AddHostSnapshot(host.ID, hostCBOM("web-01", "cipherhorizon-collector"), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sources WHERE ref_kind = 'host_snapshot' AND ref_id = ? AND class = 'imported'`, id); n != 1 {
		t.Error("the default class is not imported")
	}
	if _, err := s.AddHostSnapshotAs(host.ID, hostCBOM("web-01", "x"), []byte(`{}`), estate.SourceClass("root"), ""); err == nil {
		t.Error("an unknown source class was accepted")
	}
}

// Retention deletes old scans; their projections go with them, and entities nothing
// observes any more are removed.
func TestRetentionRemovesOrphanedProjections(t *testing.T) {
	old := store.Retention
	store.Retention = 2
	defer func() { store.Retention = old }()
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	for _, c := range []byte("abcd") {
		finishWith(t, s, a, report(fp(c), 2048))
	}
	if n := count(t, s, `SELECT COUNT(*) FROM sources WHERE ref_kind = 'scan'`); n != 2 {
		t.Errorf("%d scan sources, want 2 (retention)", n)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM entities WHERE kind = 'certificate'`); n != 2 {
		t.Errorf("%d certificate entities, want the 2 still observed", n)
	}
}

// Deleting an asset removes what only it observed.
func TestDeletingAnAssetRemovesItsObservations(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	finishWith(t, s, a, report(fp('a'), 2048))
	if err := s.DeleteAsset(a.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT (SELECT COUNT(*) FROM observations) + (SELECT COUNT(*) FROM sources) + (SELECT COUNT(*) FROM systems)`); n != 0 {
		t.Errorf("%d rows left behind", n)
	}
}

// ---- systems and audit ----------------------------------------------------------------------

func TestSystemMetadataIsOptionalAndValidated(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	sys, err := s.GetSystem(a.SystemID)
	if err != nil {
		t.Fatal(err)
	}
	if sys.Name != "one.test" || len(sys.Provided()) != 0 || sys.DataLifetimeYears != nil {
		t.Fatalf("a new system claims metadata: %+v", sys)
	}
	got, err := s.UpdateSystem(sys.ID, store.SystemPatch{
		"owner": "payments team", "environment": "production", "criticality": "high", "exposure": "internet",
		"dataLifetimeYears": float64(25), "fismaId": "F-123", "fips199": "moderate", "hvaId": "HVA-9",
		"hosting": "commercial-cloud", "hostingProvider": "ExampleCloud", "notes": "line one\nline two",
	}, "tester", "initial")
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != "payments team" || got.DataLifetimeYears == nil || *got.DataLifetimeYears != 25 || len(got.Provided()) != 11 {
		t.Errorf("after update: %+v", got)
	}
	// A null clears; an absent key leaves alone.
	got, err = s.UpdateSystem(sys.ID, store.SystemPatch{"owner": nil, "dataLifetimeYears": nil}, "tester", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != "" || got.DataLifetimeYears != nil || got.Environment != "production" {
		t.Errorf("after clear: %+v", got)
	}

	bad := map[string]store.SystemPatch{
		"unknown field":          {"password": "x"},
		"bad environment":        {"environment": "prod"},
		"bad criticality":        {"criticality": "critical"},
		"bad exposure":           {"exposure": "public"},
		"bad fips":               {"fips199": "severe"},
		"bad hosting":            {"hosting": "moon"},
		"negative lifetime":      {"dataLifetimeYears": float64(-1)},
		"fractional lifetime":    {"dataLifetimeYears": 1.5},
		"huge lifetime":          {"dataLifetimeYears": float64(1000)},
		"lifetime as text":       {"dataLifetimeYears": "ten"},
		"empty name":             {"name": ""},
		"owner control char":     {"owner": "a\x00b"},
		"owner newline":          {"owner": "a\nb"},
		"owner too long":         {"owner": strings.Repeat("x", 201)},
		"notes too long":         {"notes": strings.Repeat("x", 4001)},
		"invalid utf-8":          {"owner": "a\xffb"},
		"number where text":      {"owner": float64(3)},
		"sql in a value is data": nil,
	}
	delete(bad, "sql in a value is data")
	for name, p := range bad {
		if _, err := s.UpdateSystem(sys.ID, p, "tester", ""); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// Hostile text is data, never interpreted.
	if _, err := s.UpdateSystem(sys.ID, store.SystemPatch{"owner": "x'); DROP TABLE systems;--"}, "tester", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSystem(sys.ID); err != nil {
		t.Errorf("the systems table did not survive: %v", err)
	}
}

// SR-11: every change is audited in the same transaction, and a no-op writes nothing.
func TestSystemChangesAreAudited(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	if _, err := s.UpdateSystem(a.SystemID, store.SystemPatch{"owner": "team-a"}, "token-1", "onboarding"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSystem(a.SystemID, store.SystemPatch{"owner": "team-a"}, "token-1", "same again"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSystem(a.SystemID, store.SystemPatch{"owner": "team-b", "environment": "staging"}, "token-2", "moved"); err != nil {
		t.Fatal(err)
	}
	log, err := s.Audit("system", a.SystemID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 2 {
		t.Fatalf("%d audit rows, want 2 (the no-op writes none)", len(log))
	}
	newest := log[0]
	if newest.Actor != "token-2" || newest.Reason != "moved" || newest.Action != "update" ||
		!strings.Contains(string(newest.Before), `"owner":"team-a"`) || !strings.Contains(string(newest.After), `"owner":"team-b"`) {
		t.Errorf("newest audit row = %+v (before %s, after %s)", newest, newest.Before, newest.After)
	}
}

// A failed patch writes neither the change nor an audit row.
func TestARejectedPatchWritesNothing(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	if _, err := s.UpdateSystem(a.SystemID, store.SystemPatch{"owner": "ok", "environment": "nonsense"}, "t", ""); err == nil {
		t.Fatal("accepted")
	}
	sys, _ := s.GetSystem(a.SystemID)
	log, _ := s.Audit("system", a.SystemID, 10)
	if sys.Owner != "" || len(log) != 0 {
		t.Errorf("owner %q, %d audit rows after a rejected patch", sys.Owner, len(log))
	}
}

func TestBulkUpdateIsAllOrNothing(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	b := asset(t, s, "two.test", 443)
	err := s.UpdateSystems([]store.SystemPatchByID{
		{ID: a.SystemID, Patch: store.SystemPatch{"owner": "x"}},
		{ID: b.SystemID, Patch: store.SystemPatch{"environment": "nonsense"}},
	}, "t", "")
	if err == nil {
		t.Fatal("accepted")
	}
	if sys, _ := s.GetSystem(a.SystemID); sys.Owner != "" {
		t.Error("the first patch was applied although the second failed")
	}
}

// SR-11: the audit log cannot be edited or emptied, even by SQL.
func TestAuditLogIsAppendOnly(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	if _, err := s.UpdateSystem(a.SystemID, store.SystemPatch{"owner": "x"}, "t", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.ExecForTest(`UPDATE audit_log SET actor = 'someone else'`); err == nil {
		t.Error("an audit row was rewritten")
	}
	if err := s.ExecForTest(`DELETE FROM audit_log`); err == nil {
		t.Error("the audit log was emptied")
	}
	// Removing the asset does not remove the record of what was done to its system.
	if err := s.DeleteAsset(a.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM audit_log`); n != 1 {
		t.Errorf("%d audit rows after deleting the asset, want 1", n)
	}
}

// A system a person described is not deleted just because its last asset was.
func TestASystemWithOperatorInputOutlivesItsAssets(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	if _, err := s.UpdateSystem(a.SystemID, store.SystemPatch{"owner": "team"}, "t", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(a.ID); err != nil {
		t.Fatal(err)
	}
	sys, err := s.GetSystem(a.SystemID)
	if err != nil || sys.Owner != "team" || len(sys.Assets) != 0 {
		t.Errorf("system = %+v, %v", sys, err)
	}
}

// ---- merging ---------------------------------------------------------------------------------

func TestLinkingAssetsMergesTheirSystems(t *testing.T) {
	s, _ := open(t)
	ep := asset(t, s, "shop.test", 443)
	host, _, _ := s.UpsertHostAsset("web-01")
	if _, err := s.UpdateSystem(host.SystemID, store.SystemPatch{"owner": "web team"}, "t", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateSystem(ep.SystemID, store.SystemPatch{"exposure": "internet"}, "t", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAssetsAs(ep.ID, host.ID, "tok"); err != nil {
		t.Fatal(err)
	}
	systems, _ := s.ListSystems()
	if len(systems) != 1 {
		t.Fatalf("%d systems after linking, want 1", len(systems))
	}
	sys := systems[0]
	if sys.Name != "web-01" || sys.Owner != "web team" || sys.Exposure != "internet" || len(sys.Assets) != 2 {
		t.Errorf("merged system = %+v (the host's name wins, empty fields are filled, nothing is lost)", sys)
	}
	log, _ := s.Audit("system", sys.ID, 10)
	found := false
	for _, e := range log {
		found = found || e.Action == "merge"
	}
	if !found {
		t.Error("the merge was not audited")
	}

	// Unlinking splits them again; the metadata stays with the original system.
	if err := s.UnlinkAssetsAs(ep.ID, host.ID, "tok"); err != nil {
		t.Fatal(err)
	}
	systems, _ = s.ListSystems()
	if len(systems) != 2 {
		t.Fatalf("%d systems after unlinking, want 2", len(systems))
	}
}

func TestLinkingIsRefusedWhenOperatorValuesDisagree(t *testing.T) {
	s, _ := open(t)
	ep := asset(t, s, "shop.test", 443)
	host, _, _ := s.UpsertHostAsset("web-01")
	_, _ = s.UpdateSystem(host.SystemID, store.SystemPatch{"owner": "web team", "criticality": "high"}, "t", "")
	_, _ = s.UpdateSystem(ep.SystemID, store.SystemPatch{"owner": "shop team", "criticality": "high"}, "t", "")
	err := s.LinkAssets(ep.ID, host.ID)
	var ce *store.ConflictError
	if !errors.As(err, &ce) || !errors.Is(err, store.ErrConflict) || len(ce.Fields) != 1 || ce.Fields[0] != "owner" {
		t.Fatalf("err = %v, want a conflict on owner only", err)
	}
	if systems, _ := s.ListSystems(); len(systems) != 2 {
		t.Error("a refused link still changed the systems")
	}
	if links, _ := s.AllLinks(); len(links) != 0 {
		t.Error("a refused link was still recorded")
	}
}

// A link that survives through another asset does not split the system.
func TestUnlinkingOneOfTwoPathsKeepsTheSystemTogether(t *testing.T) {
	s, _ := open(t)
	e1 := asset(t, s, "a.test", 443)
	e2 := asset(t, s, "b.test", 443)
	host, _, _ := s.UpsertHostAsset("web-01")
	for _, e := range []store.Asset{e1, e2} {
		if err := s.LinkAssets(e.ID, host.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.LinkAssets(e1.ID, e2.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.UnlinkAssets(e1.ID, host.ID); err != nil {
		t.Fatal(err)
	}
	if systems, _ := s.ListSystems(); len(systems) != 1 {
		t.Errorf("%d systems, want 1: e1 is still connected to the host through e2", len(systems))
	}
}

func TestBackupIsOwnerOnlyOnUnix(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("file mode bits are not enforced on Windows")
	}
	path, _ := legacy(t)
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	backups, _ := filepath.Glob(path + ".bak-v3-*")
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	if fi, err := os.Stat(backups[0]); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %v, %v", fi.Mode(), err)
	}
}

// SECARCH-001 SR-01: a document that would add millions of observations is bounded, and
// the projection says how much it left out instead of silently dropping it.
func TestAnEnormousDocumentIsBoundedAndCounted(t *testing.T) {
	old := store.ObservationCap
	store.ObservationCap = 5
	defer func() { store.ObservationCap = old }()
	s, _ := open(t)
	host, _, _ := s.UpsertHostAsset("web-01")
	bom := cdx.NewBOM()
	var comps []cdx.Component
	for i := 0; i < 20; i++ {
		comps = append(comps, cdx.Component{BOMRef: fmt.Sprint("c", i), Type: cdx.ComponentTypeLibrary, Name: fmt.Sprint("lib", i), Version: "1"})
	}
	bom.Components = &comps
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddHostSnapshot(host.ID, buf.Bytes(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM observations`); n != 5 {
		t.Errorf("%d observations, want the cap of 5", n)
	}
	var ni string
	if err := s.QueryStringForTest(`SELECT not_interpreted_json FROM sources LIMIT 1`, &ni); err != nil || !strings.Contains(ni, `"over the per-document limit":15`) {
		t.Errorf("not_interpreted = %q, %v", ni, err)
	}
}

// ---- imports ----------------------------------------------------------------------------------

func importInput(t *testing.T, doc string, systemID int64, newName string) store.ImportInput {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", doc))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return store.ImportInput{Raw: raw, SHA256: fmt.Sprintf("%x", sum), SpecVersion: "1.7", Profile: "cbom-lens", Kind: estate.ImportHost,
		ToolName: "CBOM-Lens", SubmittedBy: "tester", SystemID: systemID, NewSystemName: newName}
}

// REQ-MOD-1 for imports: the graph an import built is the graph a rebuild builds, and a rebuild
// keeps withdrawn imports out. First-party evidence wins whichever is projected first.
func TestRebuildKeepsImportsAndTheirPrecedence(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "one.test", 443)
	// A scan of the same certificate the import describes, with a different key size.
	fpr := strings.Repeat("ab", 32)
	finishWith(t, s, a, report(fpr, 2048)) // 2048-bit RSA observed by the scanner
	rec, dup, err := s.AddImport(importInput(t, "cbomlens-like-1.7.json", 0, "imported-system"))
	if err != nil || dup {
		t.Fatalf("AddImport: %v dup=%v", err, dup)
	}
	before := dump(t, s)
	if _, err := s.RebuildGraph(); err != nil {
		t.Fatal(err)
	}
	if after := dump(t, s); strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("a rebuild differs from the incremental graph\nbefore:\n%s\nafter:\n%s", strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	if got, _ := s.GetImport(rec.ID); got.Observations == 0 || got.Status != "active" {
		t.Errorf("import after rebuild = %+v", got)
	}
	// Withdrawn imports stay out of a rebuild.
	if err := s.WithdrawImport(rec.ID, "tester", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RebuildGraph(); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM observations o JOIN sources src ON src.id = o.source_id WHERE src.class = 'imported'`); n != 0 {
		t.Errorf("%d imported observations after withdrawing and rebuilding", n)
	}
	got, err := s.GetImport(rec.ID)
	if err != nil || got.Status != "withdrawn" || got.SHA256 == "" {
		t.Errorf("the record of a withdrawn import must remain: %+v %v", got, err)
	}
	// The raw document is still there.
	if n := count(t, s, `SELECT COUNT(*) FROM imports WHERE id = ? AND length(cbom_json) > 100`, rec.ID); n != 1 {
		t.Error("the raw document was not kept")
	}
}

func TestAnImportNeedsASystemAndValidatesItsName(t *testing.T) {
	s, _ := open(t)
	if _, _, err := s.AddImport(importInput(t, "cbomlens-like-1.7.json", 0, "")); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("no system: %v", err)
	}
	if _, _, err := s.AddImport(importInput(t, "cbomlens-like-1.7.json", 0, "bad\x00name")); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("hostile system name: %v", err)
	}
	if _, _, err := s.AddImport(importInput(t, "cbomlens-like-1.7.json", 999, "")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown system: %v", err)
	}
	if n := count(t, s, `SELECT (SELECT COUNT(*) FROM imports) + (SELECT COUNT(*) FROM systems)`); n != 0 {
		t.Errorf("%d rows left by refused imports", n)
	}
}
