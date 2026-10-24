package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
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
	// MaintenanceInterval is how often derived data is repaired (store.Maintain): a graph
	// left stale by a failed projection is rebuilt and orphans are swept (default 5 minutes).
	MaintenanceInterval time.Duration
	Now                 func() time.Time
	// CABundle is the server-wide private CA bundle (--ca-bundle), applied to
	// every evaluation as "your CA bundle" (REQ-TTRS-2).
	CABundle []AnchorCert
	// Log receives what the runner could not do: a store write that failed, a scan that
	// panicked. Default: discarded.
	Log *slog.Logger
}

// Runner executes queued scans and triggers scheduled ones.
type Runner struct {
	st    *store.Store
	guard Guard
	opts  RunnerOptions
	log   *slog.Logger

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
	if opts.MaintenanceInterval <= 0 {
		opts.MaintenanceInterval = 5 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &Runner{st: st, guard: guard, opts: opts, log: opts.Log, wake: make(chan struct{}, opts.Workers), cancels: map[int64]context.CancelFunc{}}
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

// CRLLookups reports whether this runner's scans fetch the CRLs certificates name (--revocation).
func (r *Runner) CRLLookups() bool { return r.opts.Scan.CRL != nil }

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
				if !errors.Is(err, store.ErrNotFound) {
					r.log.Error("claiming the next queued scan failed; retrying shortly", "err", err)
				}
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
	maint := time.NewTicker(r.opts.MaintenanceInterval)
	defer maint.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.enqueueDue()
		case <-maint.C:
			if err := r.st.Maintain(); err != nil {
				r.log.Error("maintaining derived data failed", "err", err)
			}
		}
	}
}

// enqueueDue queues a scheduled scan for every asset that is due.
func (r *Runner) enqueueDue() {
	due, err := r.st.DueAssets(r.opts.Now())
	if err != nil {
		r.log.Error("finding scheduled scans failed", "err", err)
		return
	}
	queued := false
	for _, a := range due {
		_, existing, err := r.st.EnqueueScan(a.ID, "scheduled", "schedule")
		switch {
		case err != nil:
			r.log.Error("queueing a scheduled scan failed", "asset", a.ID, "err", err)
		case !existing:
			queued = true
		}
	}
	if queued {
		r.Notify()
	}
}

// stageDef is one step of a scan's progress: the prober's message, and where the bar starts.
type stageDef struct {
	key, message string
	floor        int
}

// The stages a TLS scan moves through, in the order tlsprobe reports them.
var stages = []stageDef{
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
	// table is the scan type's stages (TLS or SSH).
	table []stageDef

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
	for i, s := range p.table {
		if s.message == msg {
			p.stage, p.floor = s.key, s.floor
			p.next = floorEvaluating
			if i+1 < len(p.table) {
				p.next = p.table[i+1].floor
			}
		}
	}
	stage, pct, conns := p.stage, p.pctLocked(), p.conns
	p.lastSent = time.Now()
	p.r.note(p.id, p.r.st.AddEvent(p.id, msg))
	// Written under the lock that computed it, so two progress writes never land out of order.
	p.r.note(p.id, p.r.st.UpdateProgress(p.id, stage, pct, conns))
	p.mu.Unlock()
}

func (p *progress) tick(n int) {
	if p.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Probe goroutines report counts they read at different moments; a count read earlier can
	// arrive later. The counter only moves forward.
	p.conns = max(p.conns, n)
	if time.Since(p.lastSent) < 250*time.Millisecond {
		return
	}
	p.lastSent = time.Now()
	p.r.note(p.id, p.r.st.UpdateProgress(p.id, p.stage, p.pctLocked(), p.conns))
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

// note logs a progress write the runner could not make. Progress lines are best effort, but a
// failure must be visible: a database that has stopped taking writes is otherwise silent.
func (r *Runner) note(scanID int64, err error) {
	if err != nil {
		r.log.Warn("recording scan progress failed", "scan", scanID, "err", err)
	}
}

// fail marks a scan failed, and logs when even that cannot be recorded.
func (r *Runner) fail(scanID int64, reason string, partial []byte) {
	if err := r.st.FailScan(scanID, reason, partial); err != nil {
		r.log.Error("recording a failed scan failed; it shows as running until the next restart", "scan", scanID, "reason", reason, "err", err)
	}
}

// internalFailure is what a scan that hit a bug says; the details are in the server log only.
const internalFailure = "internal error while scanning; the server log has the details"

func (r *Runner) execute(parent context.Context, sc store.ScanSummary) {
	// A bug anywhere below (the prober, the evaluation, the result encoding) fails this scan and
	// is logged with its stack; it never ends the process and every other scan with it.
	defer func() {
		if v := recover(); v != nil {
			r.log.Error("scan panicked", "scan", sc.ID, "asset", sc.AssetID, "panic", v, "stack", string(debug.Stack()))
			r.fail(sc.ID, internalFailure, nil)
		}
	}()
	asset, err := r.st.GetAsset(sc.AssetID)
	if err != nil {
		reason := "the asset no longer exists"
		if !errors.Is(err, store.ErrNotFound) {
			r.log.Error("reading the asset of a scan failed", "scan", sc.ID, "asset", sc.AssetID, "err", err)
			reason = "the asset could not be read; the server log has the details"
		}
		r.fail(sc.ID, reason, nil)
		return
	}
	if asset.Kind == store.KindSSH {
		r.executeSSH(parent, sc, asset)
		return
	}
	target, err := tlsprobe.ParseTargetStartTLS(asset.Address(), asset.StartTLS)
	if err != nil {
		r.fail(sc.ID, "invalid target: "+err.Error(), nil)
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

	prog := &progress{r: r, ctx: ctx, id: sc.ID, table: stages, floor: 0, next: stages[0].floor}
	o := r.opts.Scan
	g := r.guard.ForTarget(target.Host) // the scan scope applies to every connection (REQ-AC-1)
	o.Dial = g.Dial
	o.LookupIP = g.LookupIP
	o.Now = r.opts.Now
	o.Progress = prog.message
	o.Tick = prog.tick
	if o.CRL != nil {
		// A CRL issued by a root is checked against the bundled roots and this asset's private anchors.
		o.CRLIssuers = refdata.RootCertificates()
		if a := r.anchorsFor(asset.ID); a != nil {
			o.CRLIssuers = append(o.CRLIssuers, a.Certificates()...)
		}
	}

	r.note(sc.ID, r.st.AddEvent(sc.ID, "scan started: "+asset.Address()))
	rep, err := tlsprobe.Scan(ctx, target, o)
	if err != nil {
		if ctx.Err() != nil && parent.Err() == nil && r.canceledByUser(sc.ID) {
			return // the API already marked it canceled
		}
		reason := err.Error()
		var pe *tlsprobe.PanicError
		switch {
		case errors.As(err, &pe):
			r.log.Error("the prober panicked", "scan", sc.ID, "target", asset.Address(), "panic", pe.Value, "stack", string(pe.Stack))
			reason = internalFailure
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			reason = "the scan exceeded its time limit"
		}
		var partial []byte
		if rep != nil && len(rep.Protocols) > 0 && pe == nil {
			if partial, err = json.Marshal(rep); err != nil {
				r.log.Warn("encoding a partial report failed", "scan", sc.ID, "err", err)
				partial = nil
			}
		}
		r.note(sc.ID, r.st.AddEvent(sc.ID, "scan failed: "+reason))
		r.fail(sc.ID, reason, partial)
		return
	}

	if ctx.Err() != nil && r.canceledByUser(sc.ID) {
		return // the scan returned a partial report; the user canceled, so do not evaluate it
	}
	r.note(sc.ID, r.st.UpdateProgress(sc.ID, stageEvaluating, floorEvaluating, rep.Connections))
	r.note(sc.ID, r.st.AddEvent(sc.ID, "evaluating results"))
	ev := r.Evaluate(rep, sc.AssetID)

	res, err := resultOf(rep, ev)
	if err != nil {
		r.fail(sc.ID, err.Error(), nil)
		return
	}
	res.FinalEvent = fmt.Sprintf("done: TLS hygiene %s (%d), PQC readiness L%d (%s), %d connections",
		ev.Hygiene.Band, ev.Hygiene.Score, ev.Readiness.Level, ev.Readiness.Label, rep.Connections)
	switch err := r.st.FinishScan(sc.ID, res); {
	case errors.Is(err, store.ErrNotFound):
		// canceled while evaluating: nothing to add
	case err != nil:
		r.log.Error("storing a finished scan failed", "scan", sc.ID, "err", err)
		r.fail(sc.ID, "the result could not be stored; the server log has the details", nil)
	}
}

func (r *Runner) canceledByUser(id int64) bool {
	sc, err := r.st.GetScan(id)
	return err == nil && sc.Status == store.StatusCanceled
}

// leafNotAfter is the earliest expiry among the leaf certificates presented.
func leafNotAfter(rep *tlsprobe.Report) *time.Time {
	var earliest *time.Time
	for _, cr := range rep.Certificates {
		// The no-SNI chain is what clients that send no server name get, often a placeholder
		// (badssl.com's expired 2018 fallback): it is not the endpoint's certificate.
		if len(cr.Chain) == 0 || cr.NoSNI {
			continue
		}
		t := cr.Chain[0].NotAfter
		if earliest == nil || t.Before(*earliest) {
			earliest = &t
		}
	}
	return earliest
}
