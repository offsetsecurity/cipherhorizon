package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/sshcbom"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// SSH endpoints in the server (PRD-008 WP-D; ENG-HANDOFF-005 §3). Every reader of a stored
// report goes through decodeReport, which dispatches on the report's declared schema.

// sshStages are the steps of an SSH scan's progress bar, in sshprobe's order.
var sshStages = []stageDef{
	{"identification", "reading the server's identification", 5},
	{"negotiation", "negotiating as a current client", 30},
	{"host-keys", "fetching host keys", 50},
}

// decodedReport is a stored report of either protocol.
type decodedReport struct {
	tls *tlsprobe.Report
	ssh *sshprobe.Report
}

// decodeReport reads a stored report by its schemaVersion: "ssh-report/..." is SSH, anything
// else (including the unversioned tls-report/1) is TLS.
func decodeReport(raw []byte) (decodedReport, error) {
	var head struct {
		SchemaVersion string `json:"schemaVersion"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return decodedReport{}, err
	}
	if strings.HasPrefix(head.SchemaVersion, "ssh-report/") {
		var r sshprobe.Report
		if err := json.Unmarshal(raw, &r); err != nil {
			return decodedReport{}, err
		}
		return decodedReport{ssh: &r}, nil
	}
	var r tlsprobe.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return decodedReport{}, err
	}
	return decodedReport{tls: &r}, nil
}

// EvaluateSSH judges an SSH report with the server's clock.
func (r *Runner) EvaluateSSH(rep *sshprobe.Report) eval.Evaluation {
	return eval.EvaluateSSH(rep, eval.Input{Now: r.opts.Now()})
}

// resultOfSSH is resultOf for an SSH scan: the same counts, plus the software and the default
// host key type the Endpoints list shows.
func resultOfSSH(rep *sshprobe.Report, ev eval.Evaluation) (store.Result, error) {
	repJSON, err1 := json.Marshal(rep)
	evJSON, err2 := json.Marshal(ev)
	if err1 != nil || err2 != nil {
		return store.Result{}, errors.New("could not encode the result")
	}
	res := store.Result{
		Report: repJSON, Evaluation: evJSON, Band: ev.Hygiene.Band, Score: ev.Hygiene.Score, ReadinessLevel: ev.Readiness.Level,
		HNDLExposed: ev.Readiness.HNDLExposed, Critical: ev.Counts[eval.Critical], High: ev.Counts[eval.High],
		Medium: ev.Counts[eval.Medium], Low: ev.Counts[eval.Low], Info: ev.Counts[eval.Info], Incomplete: rep.Incomplete,
	}
	if id := rep.Identification; id != nil {
		res.Service = id.Software
		if res.Service == "" {
			res.Service = "SSH-" + id.ProtoVersion
		}
	}
	res.HostKey = defaultHostKey(rep)
	return res, nil
}

// defaultHostKey names the host key a current client gets, else the first one fetched.
func defaultHostKey(rep *sshprobe.Report) string {
	label := func(k sshprobe.HostKey) string {
		switch {
		case k.Algorithm == "RSA" && k.Bits > 0:
			return fmt.Sprintf("RSA %d", k.Bits)
		case k.Curve != "":
			return k.Algorithm + " " + k.Curve
		}
		return k.Algorithm
	}
	if n := rep.Negotiated; n != nil && n.HostKey != "" {
		for _, k := range rep.HostKeys {
			for _, a := range k.ServedBy {
				if a == n.HostKey {
					return label(k)
				}
			}
		}
	}
	if len(rep.HostKeys) > 0 {
		return label(rep.HostKeys[0])
	}
	return ""
}

// executeSSH runs one SSH scan: the same lifecycle as a TLS scan (cancellation, time limit,
// failure with a partial report, evaluation, one stored result).
func (r *Runner) executeSSH(parent context.Context, sc store.ScanSummary, asset store.Asset) {
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

	prog := &progress{r: r, ctx: ctx, id: sc.ID, table: sshStages, floor: 0, next: sshStages[0].floor}
	g := r.guard.ForTarget(asset.Host) // the scan scope applies to every connection (REQ-SHP-7)
	o := sshprobe.Options{Timeout: r.opts.Scan.Timeout, MinInterval: r.opts.Scan.MinInterval,
		Dial: g.Dial, LookupIP: g.LookupIP, Now: r.opts.Now, Progress: prog.message, Tick: prog.tick}

	r.note(sc.ID, r.st.AddEvent(sc.ID, "SSH scan started: "+asset.Address()))
	rep, err := sshprobe.Scan(ctx, sshprobe.Target{Host: asset.Host, Port: asset.Port}, o)
	if err != nil {
		if ctx.Err() != nil && parent.Err() == nil && r.canceledByUser(sc.ID) {
			return
		}
		reason := err.Error()
		var pe *tlsprobe.PanicError
		switch {
		case errors.As(err, &pe):
			r.log.Error("the SSH prober panicked", "scan", sc.ID, "target", asset.Address(), "panic", pe.Value, "stack", string(pe.Stack))
			reason = internalFailure
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			reason = "the scan exceeded its time limit"
		}
		var partial []byte
		if rep != nil && rep.Identification != nil && pe == nil {
			partial, _ = json.Marshal(rep)
		}
		r.note(sc.ID, r.st.AddEvent(sc.ID, "scan failed: "+reason))
		r.fail(sc.ID, reason, partial)
		return
	}
	if ctx.Err() != nil && r.canceledByUser(sc.ID) {
		return
	}
	r.note(sc.ID, r.st.UpdateProgress(sc.ID, stageEvaluating, floorEvaluating, rep.Connections))
	r.note(sc.ID, r.st.AddEvent(sc.ID, "evaluating results"))
	ev := r.EvaluateSSH(rep)
	res, err := resultOfSSH(rep, ev)
	if err != nil {
		r.fail(sc.ID, err.Error(), nil)
		return
	}
	res.FinalEvent = fmt.Sprintf("done: SSH hygiene %s (%d), PQC readiness L%d (%s), %d connections",
		ev.Hygiene.Band, ev.Hygiene.Score, ev.Readiness.Level, ev.Readiness.Label, rep.Connections)
	switch err := r.st.FinishScan(sc.ID, res); {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		r.log.Error("storing a finished scan failed", "scan", sc.ID, "err", err)
		r.fail(sc.ID, "the result could not be stored; the server log has the details", nil)
	}
}

// endpointAssets are the CBOM components of one endpoint scan of either protocol, and the
// endpoint's name for the CBOM's subject.
func endpointAssets(d decodedReport) ([]collector.CryptoAsset, string) {
	if d.ssh != nil {
		return sshcbom.FromSSHReport(d.ssh), fmt.Sprintf("%s:%d", d.ssh.Target.Host, d.ssh.Target.Port)
	}
	return tlscbom.FromTLSReport(d.tls), fmt.Sprintf("%s:%d", d.tls.Target.Host, d.tls.Target.Port)
}
