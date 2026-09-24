package sense

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/example/cipherhorizon/internal/evidence"
)

// Status is the outcome of one sensor in one run.
type Status string

// The possible statuses.
const (
	StatusOK      Status = "ok"      // collected completely
	StatusSkipped Status = "skipped" // this kind of thing is not on the host (normal)
	StatusPartial Status = "partial" // collection failed part-way; findings so far are kept
	StatusFailed  Status = "failed"  // nothing could be collected
)

// Run records what happened to one sensor.
type Run struct {
	Name         string
	Info         Info // zero if the sensor could not be constructed
	Status       Status
	Err          error
	Observations int
	Duration     time.Duration
}

// Result is the outcome of a run.
type Result struct {
	Runs    []Run
	Batches []evidence.Batch
}

// Incomplete reports whether the result is known to be incomplete: a sensor
// failed or was cut short, or a budget was hit. A skipped sensor is not
// incomplete (absence of an ecosystem is a fact, not a fault), and neither is a
// scope that merely had unreadable locations: that is reported as a privilege
// warning, not as an error (ADR-0009).
func (r Result) Incomplete() bool {
	for _, run := range r.Runs {
		if run.Status == StatusPartial || run.Status == StatusFailed {
			return true
		}
	}
	for _, b := range r.Batches {
		for _, c := range b.Coverage {
			if c.Status == evidence.CoverageFailed || c.Reason == evidence.UnknownBudget {
				return true
			}
		}
	}
	return false
}

// Denied is the total number of locations sensors could not read for lack of permission.
func (r Result) Denied() int {
	n := 0
	for _, b := range r.Batches {
		for _, c := range b.Coverage {
			n += c.Denied
		}
	}
	return n
}

// Options configures a run.
type Options struct {
	Env      Env
	Enabled  []string      // run only these sensors; empty means all registered
	Disabled []string      // never run these
	Timeout  time.Duration // per-sensor budget for Detect plus Collect; 0 means none
}

// Sensors executes the selected sensors one after another, in name order.
//
// A sensor that fails, times out or panics is recorded and the rest still run:
// one broken sensor must not blank the inventory. It returns an error only for a
// request that cannot be honoured, such as naming a sensor that does not exist,
// which is nearly always a typo in configuration.
func Sensors(ctx context.Context, reg *Registry, opts Options) (Result, error) {
	names, err := selectSensors(reg.Names(), opts.Enabled, opts.Disabled)
	if err != nil {
		return Result{}, err
	}
	var res Result
	for _, name := range names {
		run, batch := runOne(ctx, reg, name, opts)
		res.Runs = append(res.Runs, run)
		res.Batches = append(res.Batches, batch)
	}
	return res, nil
}

func selectSensors(registered, enabled, disabled []string) ([]string, error) {
	for _, n := range slices.Concat(enabled, disabled) {
		if !slices.Contains(registered, n) {
			return nil, fmt.Errorf("sense: unknown sensor %q (available: %v)", n, registered)
		}
	}
	var out []string
	for _, n := range registered {
		if (len(enabled) == 0 || slices.Contains(enabled, n)) && !slices.Contains(disabled, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

func runOne(ctx context.Context, reg *Registry, name string, opts Options) (run Run, batch evidence.Batch) {
	run.Name = name
	start := time.Now()
	defer func() {
		run.Duration = time.Since(start)
		run.Observations = len(batch.Observations)
		// A sensor bug must not take down the process (or a daemon): contain it.
		if p := recover(); p != nil {
			run.Status, run.Err = StatusFailed, fmt.Errorf("sensor panicked: %v", p)
			batch, run.Observations = evidence.Batch{}, 0
			batch.Coverage = []evidence.Coverage{{Sensor: name, Scope: "the sensor", Status: evidence.CoverageFailed, Reason: evidence.UnknownError}}
		}
	}()

	s, err := reg.New(name, opts.Env)
	if err != nil {
		run.Status, run.Err = StatusFailed, err
		return run, failedCoverage(name, err)
	}
	run.Info = s.Info()

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	present, err := s.Detect(ctx)
	switch {
	case err != nil:
		run.Status, run.Err = StatusFailed, fmt.Errorf("detect: %w", err)
		return run, failedCoverage(name, run.Err)
	case !present:
		run.Status = StatusSkipped
		return run, evidence.Batch{}
	}

	batch, err = s.Collect(ctx)
	switch {
	case err == nil:
		run.Status = StatusOK
	case len(batch.Observations) > 0:
		run.Status, run.Err = StatusPartial, describe(err)
	default:
		run.Status, run.Err = StatusFailed, describe(err)
		batch.Coverage = append(batch.Coverage, failedCoverage(name, err).Coverage...)
	}
	return run, batch
}

func failedCoverage(sensor string, err error) evidence.Batch {
	return evidence.Batch{Coverage: []evidence.Coverage{{
		Sensor: sensor, Scope: "the sensor", Status: evidence.CoverageFailed, Reason: evidence.UnknownError,
		Limits: map[string]string{"error": truncate(err.Error(), 200)},
	}}}
}

func describe(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timed out: %w", err)
	}
	return err
}

// truncate bounds a host-derived string carried in coverage.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
