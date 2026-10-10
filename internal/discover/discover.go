// Package discover runs the host discovery pipeline end to end:
//
//	sensors -> evidence graph -> derived capability
//
// and returns the graph. Turning the graph into a CBOM is the cbom package's job;
// this package never touches CycloneDX, and never touches the operating system
// itself: sensors do, through sense.Env.
package discover

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/derive"
	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/hostinfo"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
)

// Options configures a discovery run.
type Options struct {
	FS       fs.FS  // the host's root filesystem
	OS       string // the host's OS family: "linux" or "windows"
	Tier     string // the privilege tier of this run: "user" or "admin"
	HostName string // the host name to record
	// Live says FS is this machine's own root, so sensors that ask the operating
	// system may run. It must be false for any other root.
	Live bool

	// RedactHost replaces the host name with a stable label derived from the
	// platform machine id (ADR-0009). The run fails if no machine id is available,
	// rather than emit an unstable label.
	RedactHost bool

	Enabled  []string
	Disabled []string
	Timeout  time.Duration
}

// Result is the outcome of a discovery run.
type Result struct {
	Graph *evidence.Graph
	Run   sense.Result
	// PrivilegeNote is the warning to show when the run had less than the highest
	// privilege tier; empty at admin.
	PrivilegeNote string
}

// Run drives the sensors, normalises their evidence into a graph and derives
// capability. It returns an error only for a request that cannot be honoured or a
// sensor that broke the evidence contract (a bug, not a partial result).
func Run(ctx context.Context, reg *sense.Registry, o Options) (*Result, error) {
	if o.Tier == "" {
		o.Tier = hostinfo.TierUser
	}
	host := hostinfo.Describe(o.FS, o.OS, o.HostName, o.Tier)
	if o.RedactHost {
		if host.ID == "" {
			return nil, errors.New("cannot redact the host name: this platform offers no machine id to derive a stable label from")
		}
		host.Name = host.ID
	} else {
		// A persistent device identifier is emitted only when the operator asked for
		// the redacted label; by default the host name is the subject and nothing more
		// identifying leaves the machine.
		host.ID = ""
	}

	res, err := sense.Sensors(ctx, reg, sense.Options{
		Env:      sense.Env{FS: o.FS, OS: o.OS, Tier: o.Tier, Live: o.Live},
		Enabled:  o.Enabled,
		Disabled: o.Disabled,
		Timeout:  o.Timeout,
	})
	if err != nil {
		return nil, err
	}

	g := evidence.NewGraph(host)
	for _, b := range res.Batches {
		if err := g.AddBatch(b); err != nil {
			return nil, fmt.Errorf("a sensor broke the evidence contract: %w", err)
		}
	}
	if err := derive.Capabilities(g); err != nil {
		return nil, err
	}
	return &Result{Graph: g, Run: res, PrivilegeNote: PrivilegeNote(o.Tier, res.Denied())}, nil
}

// PrivilegeNote is the warning for a run below the highest privilege tier: full
// results may need Administrator (Windows) or root (Linux). It is empty at admin.
// When the run counted locations it could not read, it says how many.
func PrivilegeNote(tier string, denied int) string {
	if tier == hostinfo.TierAdmin {
		return ""
	}
	if denied > 0 {
		return fmt.Sprintf("%d location(s) could not be read for lack of permission, so results may be incomplete. "+
			"Running as Administrator (Windows) or root (Linux) may reveal more.", denied)
	}
	return "Running without elevated privileges: some evidence may be unavailable, so results may be incomplete. " +
		"Running as Administrator (Windows) or root (Linux) may reveal more."
}
