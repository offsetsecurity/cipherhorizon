// Package scan runs collectors against a host. It is the single code path both
// one-shot CLI mode and (later) daemon/timer mode go through: only the trigger
// differs.
package scan

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/example/cipherhorizon/internal/collector"
)

// Status is the outcome of one plugin in one scan.
type Status string

// The possible statuses.
const (
	StatusOK      Status = "ok"      // collected completely
	StatusSkipped Status = "skipped" // ecosystem not present on this host (normal)
	StatusPartial Status = "partial" // collection failed part-way; findings so far are kept
	StatusFailed  Status = "failed"  // nothing could be collected
)

// PluginRun records what happened to one plugin.
type PluginRun struct {
	Name     string
	Info     collector.PluginInfo // zero if the plugin could not be constructed
	Status   Status
	Err      error
	Assets   int
	Duration time.Duration
}

// Result is the outcome of a scan.
type Result struct {
	Runs   []PluginRun
	Assets []collector.CryptoAsset
}

// Incomplete reports whether any plugin failed or was cut short. A skipped
// plugin is not incomplete: absence of an ecosystem is a fact, not a fault.
func (r Result) Incomplete() bool {
	for _, run := range r.Runs {
		if run.Status == StatusPartial || run.Status == StatusFailed {
			return true
		}
	}
	return false
}

// Options configures a scan.
type Options struct {
	Host     collector.Host
	Enabled  []string      // run only these plugins; empty means all registered
	Disabled []string      // never run these
	Timeout  time.Duration // per-plugin budget for Detect plus Collect; 0 means none
}

// Run executes the selected plugins one after another, in name order.
//
// A plugin that fails, times out or panics is recorded and the rest still run:
// one broken collector must not blank the inventory. Run itself returns an
// error only for a request that cannot be honoured, such as naming a plugin that
// does not exist, which is nearly always a typo in configuration.
func Run(ctx context.Context, reg *collector.Registry, opts Options) (Result, error) {
	names, err := selectPlugins(reg.Names(), opts.Enabled, opts.Disabled)
	if err != nil {
		return Result{}, err
	}

	var res Result
	for _, name := range names {
		run, assets := runOne(ctx, reg, name, opts)
		res.Runs = append(res.Runs, run)
		res.Assets = append(res.Assets, assets...)
	}
	return res, nil
}

func selectPlugins(registered, enabled, disabled []string) ([]string, error) {
	for _, n := range slices.Concat(enabled, disabled) {
		if !slices.Contains(registered, n) {
			return nil, fmt.Errorf("scan: unknown plugin %q (available: %v)", n, registered)
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

func runOne(ctx context.Context, reg *collector.Registry, name string, opts Options) (run PluginRun, assets []collector.CryptoAsset) {
	run.Name = name
	start := time.Now()
	defer func() {
		run.Duration = time.Since(start)
		run.Assets = len(assets)
		// A plugin bug must not take down the process (or a daemon): contain it.
		if p := recover(); p != nil {
			run.Status, run.Err = StatusFailed, fmt.Errorf("plugin panicked: %v", p)
			assets, run.Assets = nil, 0
		}
	}()

	c, err := reg.New(name, opts.Host)
	if err != nil {
		run.Status, run.Err = StatusFailed, err
		return run, nil
	}
	run.Info = c.Metadata()

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	present, err := c.Detect(ctx)
	switch {
	case err != nil:
		run.Status, run.Err = StatusFailed, fmt.Errorf("detect: %w", err)
		return run, nil
	case !present:
		run.Status = StatusSkipped
		return run, nil
	}

	assets, err = c.Collect(ctx)
	switch {
	case err == nil:
		run.Status = StatusOK
	case len(assets) > 0:
		run.Status, run.Err = StatusPartial, describe(err)
	default:
		run.Status, run.Err = StatusFailed, describe(err)
	}
	return run, assets
}

func describe(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timed out: %w", err)
	}
	return err
}
