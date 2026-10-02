package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/example/cipherhorizon/internal/store"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

// RunnerOptions configures the scan runner.
type RunnerOptions struct {
	// Workers is how many scans may run at once (default 2).
	Workers int
	// Scan holds the per-scan limits (timeout, connection concurrency and budget).
	Scan tlsprobe.Options
	// SchedulerInterval is how often due scheduled scans are looked for (default 10s).
	SchedulerInterval time.Duration
	// ScanTimeout bounds one whole scan (default 10 minutes).
	ScanTimeout time.Duration
	Now         func() time.Time
	// CABundle is the server-wide private CA bundle (--ca-bundle), applied to
	// every evaluation as "your CA bundle" (REQ-TTRS-2).
	CABundle []AnchorCert
}

// Runner executes queued scans and triggers scheduled ones.
type Runner struct {
	st    *store.Store
	guard Guard
	opts  RunnerOptions

	wake chan struct{}
	mu   sync.Mutex
	// cancels holds the cancel function of each running scan.
	cancels map[int64]context.CancelFunc
	wg      sync.WaitGroup
}

// NewRunner creates a runner. Call Start to begin work.
func NewRunner(st *store.Store, guard Guard, opts RunnerOptions) *Runner {
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.SchedulerInterval <= 0 {
		opts.SchedulerInterval = 10 * time.Second
	}
	if opts.ScanTimeout <= 0 {
		opts.ScanTimeout = 10 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Runner{st: st, guard: guard, opts: opts, wake: make(chan struct{}, opts.Workers), cancels: map[int64]context.CancelFunc{}}
}

// Start launches the workers and the scheduler. They stop when ctx is done.
func (r *Runner) Start(ctx context.Context) {
	for i := 0; i < r.opts.Workers; i++ {
		r.wg.Add(1)
		go r.worker(ctx)
	}
	r.wg.Add(1)
	go r.scheduler(ctx)
}

// Wait blocks until every worker has stopped.
func (r *Runner) Wait() { r.wg.Wait() }

// HTTPChecks reports whether this runner's scans send the opt-in HTTP-layer
// check (HSTS), so the API can tell callers about a server-wide setting.
func (r *Runner) HTTPChecks() bool { return r.opts.Scan.HTTPChecks }

// CABundle returns the server-wide private CA bundle.
func (r *Runner) CABundle() []AnchorCert { return r.opts.CABundle }

// Notify tells idle workers there is queued work.
func (r *Runner) Notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Cancel stops a running scan. (A queued scan is simply marked canceled in the store.)
func (r *Runner) Cancel(scanID int64) {
	r.mu.Lock()
	cancel := r.cancels[scanID]
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *Runner) worker(ctx context.Context) {
	defer r.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		for ctx.Err() == nil {
			sc, err := r.st.ClaimNext()
			if err != nil {
				break
			}
			r.execute(ctx, sc)
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-tick.C:
		}
	}
}

func (r *Runner) scheduler(ctx context.Context) {
	defer r.wg.Done()
	tick := time.NewTicker(r.opts.SchedulerInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.enqueueDue()
		}
	}
}

// enqueueDue queues a scheduled scan for every asset that is due.
func (r *Runner) enqueueDue() {
	due, err := r.st.DueAssets(r.opts.Now())
	if err != nil {
		return
	}
	queued := false
	for _, a := range due {
		if _, existing, err := r.st.EnqueueScan(a.ID, "scheduled"); err == nil && !existing {
			queued = true
		}
	}
	if queued {
		r.Notify()
	}
}

// The stages a scan moves through, in the order tlsprobe reports them.
var stages = []struct {
	key, message string
	floor        int
}{
	{"protocols", "testing protocol versions", 5},
	{"suites", "enumerating cipher suites", 15},
	{"keyexchange", "probing key exchange", 70},
	{"certificates", "fetching certificates", 85},
}

const (
	stageEvaluating = "evaluating"
	floorEvaluating = 95
)

// progress turns the prober's callbacks into database updates, throttled so a
// scan making hundreds of connections does not write hundreds of rows.
type progress struct {
	r   *Runner
	ctx context.Context // once it is done (canceled, timed out) the scan says no more
	id  int64

	mu       sync.Mutex
	stage    string
	floor    int
	next     int // the floor of the next stage: the percentage may creep toward it
	conns    int
	lastSent time.Time
}

func (p *progress) message(msg string) {
	if p.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	for i, s := range stages {
		if s.message == msg {
			p.stage, p.floor = s.key, s.floor
			p.next = floorEvaluating
			if i+1 < len(stages) {
				p.next = stages[i+1].floor
			}
		}
	}
	stage, pct, conns := p.stage, p.pctLocked(), p.conns
	p.lastSent = time.Now()
	p.mu.Unlock()
	_ = p.r.st.AddEvent(p.id, msg)
	_ = p.r.st.UpdateProgress(p.id, stage, pct, conns)
}

func (p *progress) tick(n int) {
	if p.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	p.conns = n
	if time.Since(p.lastSent) < 250*time.Millisecond {
		p.mu.Unlock()
		return
	}
	p.lastSent = time.Now()
	stage, pct := p.stage, p.pctLocked()
	p.mu.Unlock()
	_ = p.r.st.UpdateProgress(p.id, stage, pct, n)
}

// pctLocked is the stage's floor plus a creep toward the next floor as
// connections accumulate, so the bar keeps moving inside a long stage without
// ever overtaking it.
func (p *progress) pctLocked() int {
	creep := p.conns / 8
	if room := p.next - p.floor - 1; creep > room {
		creep = room
	}
	if creep < 0 {
		creep = 0
	}
	return p.floor + creep
}

func (r *Runner) execute(parent context.Context, sc store.ScanSummary) {
	asset, err := r.st.GetAsset(sc.AssetID)
	if err != nil {
		_ = r.st.FailScan(sc.ID, "the asset no longer exists", nil)
		return
	}
	target, err := tlsprobe.ParseTarget(asset.Address())
	if err != nil {
		_ = r.st.FailScan(sc.ID, "invalid target: "+err.Error(), nil)
		return
	}

	ctx, cancel := context.WithTimeout(parent, r.opts.ScanTimeout)
	defer cancel()
	r.mu.Lock()
	r.cancels[sc.ID] = cancel
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.cancels, sc.ID)
		r.mu.Unlock()
	}()

	prog := &progress{r: r, ctx: ctx, id: sc.ID, floor: 0, next: stages[0].floor}
	o := r.opts.Scan
	o.Dial = r.guard.Dial
	o.LookupIP = r.guard.LookupIP
	o.Now = r.opts.Now
	o.Progress = prog.message
	o.Tick = prog.tick

	_ = r.st.AddEvent(sc.ID, "scan started: "+asset.Address())
	rep, err := tlsprobe.Scan(ctx, target, o)
	if err != nil {
		if ctx.Err() != nil && parent.Err() == nil && r.canceledByUser(sc.ID) {
			return // the API already marked it canceled
		}
		reason := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			reason = "the scan exceeded its time limit"
		}
		var partial []byte
		if rep != nil && len(rep.Protocols) > 0 {
			partial, _ = json.Marshal(rep)
		}
		_ = r.st.AddEvent(sc.ID, "scan failed: "+reason)
		_ = r.st.FailScan(sc.ID, reason, partial)
		return
	}

	if ctx.Err() != nil && r.canceledByUser(sc.ID) {
		return // the scan returned a partial report; the user canceled, so do not evaluate it
	}
	_ = r.st.UpdateProgress(sc.ID, stageEvaluating, floorEvaluating, rep.Connections)
	_ = r.st.AddEvent(sc.ID, "evaluating results")
	ev := r.Evaluate(rep, sc.AssetID)

	res, err := resultOf(rep, ev)
	if err != nil {
		_ = r.st.FailScan(sc.ID, err.Error(), nil)
		return
	}
	res.FinalEvent = fmt.Sprintf("done: TLS hygiene %s (%d), PQC readiness L%d (%s), %d connections",
		ev.Hygiene.Band, ev.Hygiene.Score, ev.Readiness.Level, ev.Readiness.Label, rep.Connections)
	if na := leafNotAfter(rep); na != nil {
		res.CertNotAfter = na
	}
	_ = r.st.FinishScan(sc.ID, res) // an error means it was canceled while evaluating: nothing to add
}

func (r *Runner) canceledByUser(id int64) bool {
	sc, err := r.st.GetScan(id)
	return err == nil && sc.Status == store.StatusCanceled
}

// leafNotAfter is the earliest expiry among the leaf certificates presented.
func leafNotAfter(rep *tlsprobe.Report) *time.Time {
	var earliest *time.Time
	for _, cr := range rep.Certificates {
		if len(cr.Chain) == 0 {
			continue
		}
		t := cr.Chain[0].NotAfter
		if earliest == nil || t.Before(*earliest) {
			earliest = &t
		}
	}
	return earliest
}
