package store_test

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func open(t *testing.T) (*store.Store, *clock) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	c := &clock{t: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	s.SetClock(c.now)
	return s, c
}

func asset(t *testing.T, s *store.Store, host string, port int) store.Asset {
	t.Helper()
	a, err := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: host, Host: host, Port: port, Tags: []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func finish(t *testing.T, s *store.Store, scanID int64, level int, band string, crit int) {
	t.Helper()
	na := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.FinishScan(scanID, store.Result{Report: []byte(`{"r":1}`), Evaluation: []byte(`{"e":1}`), Band: band, Score: 80,
		ReadinessLevel: level, HNDLExposed: level < 3, Critical: crit, CertNotAfter: &na}); err != nil {
		t.Fatal(err)
	}
}

func runOne(t *testing.T, s *store.Store, a store.Asset, level int, band string, crit int) store.ScanSummary {
	t.Helper()
	sc, _, err := s.EnqueueScan(a.ID, "manual", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimNext(); err != nil {
		t.Fatal(err)
	}
	finish(t, s, sc.ID, level, band, crit)
	got, _ := s.GetScan(sc.ID)
	return got
}

func TestAssetLifecycle(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	if a.ID == 0 || a.Kind != store.KindTLS || a.Address() != "a.example:443" || len(a.Tags) != 1 || a.Latest != nil {
		t.Fatalf("asset = %+v", a)
	}

	// AC-01.3: no duplicates.
	if _, err := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "again", Host: "a.example", Port: 443}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate: err = %v", err)
	}
	// The same host on another port is a different asset.
	asset(t, s, "a.example", 8443)

	// AC-01.5: edit.
	name, notes, tags := "Renamed", "n", []string{"a", "b"}
	up, err := s.UpdateAsset(a.ID, store.AssetPatch{Name: &name, Notes: &notes, Tags: &tags})
	if err != nil || up.Name != "Renamed" || up.Notes != "n" || len(up.Tags) != 2 || up.Host != "a.example" {
		t.Fatalf("update = %+v, %v", up, err)
	}

	list, err := s.ListAssets("")
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
	if empty, _ := open2(t).ListAssets(""); empty == nil || len(empty) != 0 {
		t.Errorf("an empty list must be [], not null: %v", empty)
	}

	if _, err := s.GetAsset(999); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing asset: %v", err)
	}
	if err := s.DeleteAsset(999); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete missing: %v", err)
	}
}

func open2(t *testing.T) *store.Store { s, _ := open(t); return s }

func TestDeletingAnAssetDeletesItsHistory(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	sc := runOne(t, s, a, 1, "Sound", 0)
	if err := s.AddEvent(sc.ID, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetScan(sc.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("scan survived its asset: %v", err)
	}
	if ev, _ := s.Events(sc.ID); len(ev) != 0 {
		t.Errorf("events survived: %v", ev)
	}
	if _, err := s.Report(sc.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("report survived: %v", err)
	}
}

// AC-02.6: enforced by the schema, so it holds under concurrency too.
func TestOnlyOneActiveScanPerAsset(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)

	first, existing, err := s.EnqueueScan(a.ID, "manual", "test")
	if err != nil || existing {
		t.Fatalf("first: %+v existing=%v err=%v", first, existing, err)
	}
	second, existing, err := s.EnqueueScan(a.ID, "manual", "test")
	if err != nil || !existing || second.ID != first.ID {
		t.Fatalf("second request must return the active scan: %+v existing=%v err=%v", second, existing, err)
	}

	// Once claimed (running) it is still the active one.
	if _, err := s.ClaimNext(); err != nil {
		t.Fatal(err)
	}
	if third, existing, _ := s.EnqueueScan(a.ID, "manual", "test"); !existing || third.ID != first.ID || third.Status != store.StatusRunning {
		t.Errorf("while running: %+v existing=%v", third, existing)
	}

	// Concurrent requests for a fresh asset yield exactly one scan.
	b := asset(t, s, "b.example", 443)
	var wg sync.WaitGroup
	ids := make(chan int64, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc, _, err := s.EnqueueScan(b.ID, "manual", "test")
			if err == nil {
				ids <- sc.ID
			}
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[int64]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Errorf("20 concurrent requests created %d scans, want 1", len(seen))
	}

	// A finished scan frees the slot.
	finish(t, s, first.ID, 1, "Sound", 0)
	if next, existing, err := s.EnqueueScan(a.ID, "manual", "test"); err != nil || existing || next.ID == first.ID {
		t.Errorf("after finish: %+v existing=%v err=%v", next, existing, err)
	}

	if _, _, err := s.EnqueueScan(12345, "manual", "test"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("scan of a missing asset: %v", err)
	}
}

// Two workers must never run the same scan.
func TestClaimNextIsAtomic(t *testing.T) {
	s, _ := open(t)
	const n = 12
	for i := 0; i < n; i++ {
		a := asset(t, s, "h"+string(rune('a'+i))+".example", 443)
		if _, _, err := s.EnqueueScan(a.ID, "bulk", "test"); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	claimed := make(chan int64, 4*n)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				sc, err := s.ClaimNext()
				if errors.Is(err, store.ErrNotFound) {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				claimed <- sc.ID
			}
		}()
	}
	wg.Wait()
	close(claimed)
	seen := map[int64]int{}
	for id := range claimed {
		seen[id]++
	}
	if len(seen) != n {
		t.Fatalf("claimed %d distinct scans, want %d", len(seen), n)
	}
	for id, c := range seen {
		if c != 1 {
			t.Errorf("scan %d claimed %d times", id, c)
		}
	}
	if _, err := s.ClaimNext(); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("empty queue: %v", err)
	}
}

func TestScanProgressAndResult(t *testing.T) {
	s, c := open(t)
	a := asset(t, s, "a.example", 443)
	sc, _, _ := s.EnqueueScan(a.ID, "manual", "test")
	if sc.Status != store.StatusQueued || sc.Trigger != "manual" {
		t.Fatalf("queued = %+v", sc)
	}

	c.advance(time.Second)
	run, err := s.ClaimNext()
	if err != nil || run.Status != store.StatusRunning || run.StartedAt == nil {
		t.Fatalf("running = %+v, %v", run, err)
	}
	if err := s.UpdateProgress(run.ID, "enumerating cipher suites", 40, 57); err != nil {
		t.Fatal(err)
	}
	_ = s.AddEvent(run.ID, "testing protocol versions")
	_ = s.AddEvent(run.ID, "enumerating cipher suites")
	got, _ := s.GetScan(run.ID)
	if got.Stage != "enumerating cipher suites" || got.ProgressPct != 40 || got.Connections != 57 {
		t.Errorf("progress = %+v", got)
	}
	ev, _ := s.Events(run.ID)
	if len(ev) != 2 || ev[0].Message != "testing protocol versions" || ev[1].Message != "enumerating cipher suites" {
		t.Errorf("events = %+v", ev)
	}

	// While running, the asset shows the running scan as Latest and no LastDone yet.
	if as, _ := s.GetAsset(a.ID); as.Latest == nil || as.Latest.Status != store.StatusRunning || as.LastDone != nil {
		t.Errorf("asset while running: latest=%+v lastDone=%+v", as.Latest, as.LastDone)
	}

	finish(t, s, run.ID, 3, "Strong", 0)
	done, _ := s.GetScan(run.ID)
	if done.Status != store.StatusDone || done.ProgressPct != 100 || done.Band != "Strong" || done.ReadinessLevel == nil ||
		*done.ReadinessLevel != 3 || done.HNDLExposed || done.FinishedAt == nil || done.CertNotAfter == nil {
		t.Errorf("done = %+v", done)
	}
	if b, err := s.Report(run.ID); err != nil || string(b) != `{"r":1}` {
		t.Errorf("report = %q, %v", b, err)
	}
	if b, err := s.Evaluation(run.ID); err != nil || string(b) != `{"e":1}` {
		t.Errorf("evaluation = %q, %v", b, err)
	}
	if as, _ := s.GetAsset(a.ID); as.LastDone == nil || as.LastDone.Band != "Strong" {
		t.Errorf("asset after done: %+v", as.LastDone)
	}
	// Finishing twice must not overwrite.
	if err := s.FinishScan(run.ID, store.Result{Band: "Broken"}); err == nil {
		t.Error("a finished scan was finished again")
	}
}

func TestFailedAndCanceledScansKeepHistoryAndFreeTheSlot(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)

	sc, _, _ := s.EnqueueScan(a.ID, "manual", "test")
	_, _ = s.ClaimNext()
	if err := s.FailScan(sc.ID, "no response from target: connection refused", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetScan(sc.ID); got.Status != store.StatusFailed || got.Error == "" || got.FinishedAt == nil {
		t.Errorf("failed = %+v", got)
	}

	sc2, existing, err := s.EnqueueScan(a.ID, "manual", "test")
	if err != nil || existing {
		t.Fatalf("slot not freed: %v %v", existing, err)
	}
	if err := s.CancelScan(sc2.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetScan(sc2.ID); got.Status != store.StatusCanceled {
		t.Errorf("canceled = %+v", got)
	}
	if err := s.CancelScan(sc2.ID); err == nil {
		t.Error("canceling a finished scan succeeded")
	}
	if err := s.CancelScan(999); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("cancel missing: %v", err)
	}

	h, _ := s.History(a.ID, 0)
	if len(h) != 2 || h[0].Status != store.StatusFailed || h[1].Status != store.StatusCanceled {
		t.Errorf("history = %+v", h)
	}
}

// AC-12.2
func TestInterruptedScansAreFailedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "a", Host: "a.example", Port: 443})
	b, _ := s.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "b", Host: "b.example", Port: 443})
	running, _, _ := s.EnqueueScan(a.ID, "manual", "test")
	_, _ = s.ClaimNext()
	queued, _, _ := s.EnqueueScan(b.ID, "manual", "test")
	_ = s.Close()

	s2, err := store.Open(path) // the "restart": the schema must also survive being reopened
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck // test
	n, err := s2.FailInterrupted()
	if err != nil || n != 1 {
		t.Fatalf("FailInterrupted = %d, %v", n, err)
	}
	if got, _ := s2.GetScan(running.ID); got.Status != store.StatusFailed || got.Error == "" {
		t.Errorf("the interrupted scan = %+v, want failed", got)
	}
	// A queued scan was never started, so a restart does not lose it: it is the next one claimed.
	next, err := s2.ClaimNext()
	if err != nil || next.ID != queued.ID {
		t.Errorf("after a restart the queued scan should be claimable: %+v, %v", next, err)
	}
	if _, err := s2.ClaimNext(); !errors.Is(err, store.ErrNotFound) {
		t.Error("the interrupted scan is still claimable")
	}
}

// AC-07.1, AC-07.5
func TestHistoryAndRetention(t *testing.T) {
	old := store.Retention
	store.Retention = 5
	defer func() { store.Retention = old }()

	s, c := open(t)
	a := asset(t, s, "a.example", 443)
	other := asset(t, s, "b.example", 443)
	for i := 0; i < 8; i++ {
		c.advance(time.Hour)
		runOne(t, s, a, i%4, "Sound", 0)
	}
	runOne(t, s, other, 1, "C", 0)

	h, err := s.History(a.ID, 0)
	if err != nil || len(h) != 5 {
		t.Fatalf("history = %d entries, %v (retention 5)", len(h), err)
	}
	for i := 1; i < len(h); i++ {
		if h[i].At.Before(h[i-1].At) {
			t.Fatal("history must be oldest first")
		}
	}
	// The newest five survived: levels of scans 3..7.
	if *h[4].ReadinessLevel != 7%4 {
		t.Errorf("newest = level %d", *h[4].ReadinessLevel)
	}
	if h2, _ := s.History(other.ID, 0); len(h2) != 1 {
		t.Errorf("retention on one asset touched another: %d", len(h2))
	}
}

func TestSchedulingAndDueAssets(t *testing.T) {
	s, c := open(t)
	a := asset(t, s, "a.example", 443)
	b := asset(t, s, "b.example", 443)

	day := 86400
	up, err := s.UpdateAsset(a.ID, store.AssetPatch{IntervalSeconds: &day})
	if err != nil || up.IntervalSeconds != day || up.NextScanAt == nil || !up.NextScanAt.Equal(c.t.Add(24*time.Hour)) {
		t.Fatalf("schedule = %+v, %v", up, err)
	}
	if due, _ := s.DueAssets(c.t); len(due) != 0 {
		t.Errorf("due before the interval elapsed: %v", due)
	}
	c.advance(25 * time.Hour)
	due, _ := s.DueAssets(c.t)
	if len(due) != 1 || due[0].ID != a.ID {
		t.Fatalf("due = %+v (only the scheduled asset)", due)
	}
	_ = b

	// An active scan makes it not due; finishing reschedules from then.
	sc, _, _ := s.EnqueueScan(a.ID, "scheduled", "test")
	if due, _ := s.DueAssets(c.t); len(due) != 0 {
		t.Error("an asset with an active scan is due again")
	}
	_, _ = s.ClaimNext()
	finish(t, s, sc.ID, 1, "Sound", 0)
	got, _ := s.GetAsset(a.ID)
	if got.NextScanAt == nil || !got.NextScanAt.Equal(c.t.Add(24*time.Hour)) {
		t.Errorf("next scan after finishing = %v", got.NextScanAt)
	}

	zero := 0
	off, _ := s.UpdateAsset(a.ID, store.AssetPatch{IntervalSeconds: &zero})
	c.advance(48 * time.Hour)
	if due, _ := s.DueAssets(c.t); len(due) != 0 || off.IntervalSeconds != 0 {
		t.Errorf("a schedule turned off still fires: %v", due)
	}
}

func TestListScansFilters(t *testing.T) {
	s, _ := open(t)
	a, b := asset(t, s, "a.example", 443), asset(t, s, "b.example", 443)
	runOne(t, s, a, 1, "Sound", 0)
	runOne(t, s, b, 3, "Strong", 0)
	sc, _, _ := s.EnqueueScan(a.ID, "manual", "test")

	all, _ := s.ListScans(store.ScanFilter{})
	if len(all) != 3 || all[0].ID != sc.ID || all[0].AssetName != "a.example" || all[0].AssetAddress != "a.example:443" {
		t.Errorf("all = %+v", all)
	}
	if q, _ := s.ListScans(store.ScanFilter{Status: store.StatusQueued}); len(q) != 1 {
		t.Errorf("queued = %d", len(q))
	}
	if forA, _ := s.ListScans(store.ScanFilter{AssetID: a.ID}); len(forA) != 2 {
		t.Errorf("for a = %d", len(forA))
	}
	if lim, _ := s.ListScans(store.ScanFilter{Limit: 1}); len(lim) != 1 {
		t.Errorf("limit = %d", len(lim))
	}
}

// AC-06.x: the dashboard's numbers come from each asset's latest completed scan.
func TestFleetSummary(t *testing.T) {
	s, c := open(t)
	a := asset(t, s, "hybrid.example", 443)
	b := asset(t, s, "classical.example", 443)
	d := asset(t, s, "legacy.example", 443)
	asset(t, s, "never-scanned.example", 443)

	runOne(t, s, a, 1, "Sound", 0) // day 1: exposed
	c.advance(24 * time.Hour)
	runOne(t, s, a, 3, "Strong", 0) // day 2: fixed
	runOne(t, s, b, 1, "Sound", 0)
	runOne(t, s, d, 0, "Broken", 2)

	f, err := s.FleetSummary(3)
	if err != nil {
		t.Fatal(err)
	}
	if f.Assets != 4 || f.Scanned != 3 {
		t.Errorf("assets=%d scanned=%d", f.Assets, f.Scanned)
	}
	if f.HNDLExposed != 2 { // classical + legacy; the hybrid one was fixed
		t.Errorf("hndl exposed = %d, want 2", f.HNDLExposed)
	}
	if f.Readiness[3] != 1 || f.Readiness[1] != 1 || f.Readiness[0] != 1 {
		t.Errorf("readiness = %v (latest scan per asset, not history)", f.Readiness)
	}
	if f.Bands["Strong"] != 1 || f.Bands["Sound"] != 1 || f.Bands["Broken"] != 1 || f.Critical != 2 {
		t.Errorf("bands = %v critical = %d", f.Bands, f.Critical)
	}
	if f.CertsExpiring != 0 { // certs expire 2027, well past 30 days
		t.Errorf("certs expiring = %d", f.CertsExpiring)
	}
	if len(f.NeedsAttention) == 0 || f.NeedsAttention[0].Name != "legacy.example" || f.NeedsAttention[0].Why != "critical findings" {
		t.Errorf("needs attention (worst first) = %+v", f.NeedsAttention)
	}
	if len(f.Recent) != 4 {
		t.Errorf("recent = %d", len(f.Recent))
	}

	// The trend shows the fleet moving: day 1 only "a" (exposed); day 2 all three.
	if len(f.Trend) != 3 {
		t.Fatalf("trend has %d points, want 3", len(f.Trend))
	}
	day1, day2 := f.Trend[1], f.Trend[2]
	if day1.Levels[1] != 1 || len(day1.Levels) != 1 {
		t.Errorf("day 1 = %v", day1.Levels)
	}
	if day2.Levels[3] != 1 || day2.Levels[1] != 1 || day2.Levels[0] != 1 {
		t.Errorf("day 2 = %v", day2.Levels)
	}
	if len(f.Trend[0].Levels) != 0 {
		t.Errorf("before any scan = %v", f.Trend[0].Levels)
	}
}

func TestCertExpirySurfacesInAttention(t *testing.T) {
	s, c := open(t)
	a := asset(t, s, "a.example", 443)
	sc, _, _ := s.EnqueueScan(a.ID, "manual", "test")
	_, _ = s.ClaimNext()
	soon := c.t.AddDate(0, 0, 10)
	_ = s.FinishScan(sc.ID, store.Result{Report: []byte("{}"), Evaluation: []byte("{}"), Band: "Strong", ReadinessLevel: 3, CertNotAfter: &soon})
	f, _ := s.FleetSummary(1)
	if f.CertsExpiring != 1 || len(f.NeedsAttention) != 1 || f.NeedsAttention[0].Why != "certificate expires within 30 days" {
		t.Errorf("%+v", f)
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// Simulate a database written by a newer program.
	if err := store.ForceSchemaVersion(path, 999); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(path); err == nil {
		t.Error("opened a database from a newer version")
	}
}
