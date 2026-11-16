package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/namefind"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// Finding endpoints from a domain (PRD-022, internal). A discovery finds the host names under a
// domain, resolves them and tries a short list of ports. Its result is a review list: nothing is
// added or scanned until a person accepts names.

// DiscoveryOptions configures the Discoverer.
type DiscoveryOptions struct {
	// Resolver answers DNS queries (default: the system resolver).
	Resolver namefind.Resolver
	// CT searches Certificate Transparency when the setting allows it (default: crt.sh).
	CT namefind.CTSearcher
	// Timeout bounds one whole run (default 2 hours).
	Timeout time.Duration
	// QPS limits DNS queries per second (default 50).
	QPS int
	// Dial replaces the guarded dialer of the port checks (tests).
	Dial func(ctx context.Context, address string, port int) (net.Conn, error)
	Log  *slog.Logger
}

// ErrDiscoveryBusy means a discovery is already running; one runs at a time.
var ErrDiscoveryBusy = errors.New("a discovery is already running; wait for it to finish or cancel it")

// Discoverer runs discoveries in the background, one at a time.
type Discoverer struct {
	st    *store.Store
	guard Guard
	opts  DiscoveryOptions
	log   *slog.Logger

	mu      sync.Mutex
	base    context.Context
	running int64
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewDiscoverer creates a Discoverer. Call Start before the first run.
func NewDiscoverer(st *store.Store, guard Guard, opts DiscoveryOptions) *Discoverer {
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.CT == nil {
		opts.CT = namefind.CrtSh{}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Hour
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &Discoverer{st: st, guard: guard, opts: opts, log: opts.Log, base: context.Background()}
}

// Start sets the context every run lives under: when it ends, running discoveries stop.
func (d *Discoverer) Start(ctx context.Context) {
	d.mu.Lock()
	d.base = ctx
	d.mu.Unlock()
}

// Wait blocks until no discovery is running.
func (d *Discoverer) Wait() { d.wg.Wait() }

// CTService names the Certificate Transparency service a run would ask.
func (d *Discoverer) CTService() string { return d.opts.CT.Name() }

// CTAllowed reports whether Settings allows the Certificate Transparency source.
func (d *Discoverer) CTAllowed() bool {
	v, err := d.st.Setting(store.SettingDiscoveryCT)
	if err != nil {
		d.log.Error("reading the discovery setting; treating it as off", "err", err)
		return false
	}
	return v == "on"
}

// Begin starts a run and returns its record. Only one runs at a time.
func (d *Discoverer) Begin(domain string, sources, list []string, actor string) (store.Discovery, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running != 0 {
		return store.Discovery{}, ErrDiscoveryBusy
	}
	rec, err := d.st.CreateDiscovery(domain, sources, actor)
	if err != nil {
		return store.Discovery{}, err
	}
	ctx, cancel := context.WithTimeout(d.base, d.opts.Timeout)
	d.running, d.cancel = rec.ID, cancel
	d.wg.Add(1)
	go d.run(ctx, cancel, rec, list)
	return rec, nil
}

// Cancel stops a running discovery.
func (d *Discoverer) Cancel(id int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running == id && d.cancel != nil {
		d.cancel()
	}
}

func (d *Discoverer) run(ctx context.Context, cancel context.CancelFunc, rec store.Discovery, list []string) {
	defer d.wg.Done()
	defer func() {
		cancel()
		d.mu.Lock()
		d.running, d.cancel = 0, nil
		d.mu.Unlock()
	}()
	fail := func(msg string) {
		if err := d.st.FinishDiscovery(rec.ID, store.DiscoveryFailed, msg, nil, nil); err != nil {
			d.log.Error("recording a failed discovery", "id", rec.ID, "err", err)
		}
	}
	defer func() {
		if p := recover(); p != nil {
			d.log.Error("a discovery panicked", "id", rec.ID, "panic", p, "stack", string(debug.Stack()))
			fail("internal error")
		}
	}()

	var stored []string
	if contains(rec.Sources, namefind.SourceStored) {
		var err error
		if stored, err = d.st.KnownNamesUnder(rec.Domain); err != nil {
			d.log.Error("reading the names already held", "err", err)
		}
	}
	var ct namefind.CTSearcher
	if d.CTAllowed() {
		ct = d.opts.CT
	}
	// The stage is written at most once a second: a run reports progress thousands of times.
	var pmu sync.Mutex
	var last time.Time
	progress := func(stage string, done, total int) {
		pmu.Lock()
		defer pmu.Unlock()
		if time.Since(last) < time.Second && done != total {
			return
		}
		last = time.Now()
		if total > 0 {
			stage = fmt.Sprintf("%s: %d of %d", stage, done, total)
		}
		if err := d.st.SetDiscoveryStage(rec.ID, stage); err != nil {
			d.log.Warn("recording discovery progress", "err", err)
		}
	}
	base := Guard{AllowLoopback: d.guard.AllowLoopback}
	// Only addresses CheckIP allowed are dialled; the fixed rules are enforced again on the real
	// connection.
	dial := func(ctx context.Context, address string, port int) (net.Conn, error) {
		return base.Dial(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	}
	if d.opts.Dial != nil {
		dial = d.opts.Dial
	}
	res, err := namefind.Run(ctx, namefind.Options{
		Domain: rec.Domain, Sources: rec.Sources, Stored: stored, List: list, CT: ct,
		Resolver: d.opts.Resolver, QPS: d.opts.QPS, Progress: progress,
		// A name is checked against the scan scope as a scan of it would be.
		CheckIP: func(host string, ip net.IP) error { return d.guard.ForTarget(host).CheckIP(ip) },
		Dial:    dial,
	})
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		fail("the run took longer than " + d.opts.Timeout.String() + " and was stopped")
		return
	case ctx.Err() != nil || errors.Is(err, context.Canceled):
		// Canceled by a person (already recorded) or by the server stopping.
		if _, cerr := d.st.CancelDiscovery(rec.ID); cerr != nil {
			d.log.Error("recording a canceled discovery", "id", rec.ID, "err", cerr)
		}
		return
	case err != nil:
		fail(err.Error())
		return
	}
	names := make([]store.DiscoveryName, 0, len(res.Names))
	for _, n := range res.Names {
		names = append(names, store.DiscoveryName{Name: n.Name, Sources: n.Sources, Addresses: n.Addresses, CNAME: n.CNAME,
			External: n.External, Ports: n.Ports, Refused: stripBlocked(n.Refused), Mail: n.Mail})
	}
	report := discoveryReport{Sources: res.Sources, Wildcard: res.Wildcard, WildcardCerts: res.WildcardCerts,
		Truncated: res.Truncated, Outside: res.Outside, MaxNames: namefind.DefaultMaxNames,
		Ports: append([]int{}, namefind.WebPorts...), MailPort: namefind.MailPort}
	if err := d.st.FinishDiscovery(rec.ID, store.DiscoveryDone, "", report, names); err != nil {
		d.log.Error("storing a discovery", "id", rec.ID, "err", err)
		fail("the result could not be stored")
	}
}

// discoveryReport is what a finished run says besides its names (REQ-DD-12): what each source
// did, and what the run could not see.
type discoveryReport struct {
	Sources       []namefind.SourceReport `json:"sources"`
	Wildcard      bool                    `json:"wildcard"`
	WildcardCerts []string                `json:"wildcardCerts"`
	Truncated     bool                    `json:"truncated"`
	Outside       int                     `json:"outside"`
	MaxNames      int                     `json:"maxNames"`
	Ports         []int                   `json:"ports"`
	MailPort      int                     `json:"mailPort"`
}

func stripBlocked(reason string) string {
	return strings.TrimPrefix(reason, ErrBlocked.Error()+": ")
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// CheckDomain decides whether names under domain may be looked for (REQ-DD-10). Without a scan
// scope any domain may. With one, the domain must be inside a scope domain, or the scope must
// have networks: then each found name is checked against them, and refused when outside.
func (g Guard) CheckDomain(domain string) error {
	if g.Scope.Empty() || g.Scope.nameIn(domain) || len(g.Scope.nets) > 0 {
		return nil
	}
	return fmt.Errorf("%w: %s is outside the scan scope (%s)", ErrBlocked, domain, strings.Join(g.Scope.entries, ", "))
}

// ---- API ------------------------------------------------------------------------------------

func (s *Server) discoverer(w http.ResponseWriter) *Discoverer {
	if s.cfg.Discovery == nil {
		writeErr(w, http.StatusServiceUnavailable, "finding endpoints from a domain is not available on this server")
		return nil
	}
	return s.cfg.Discovery
}

// discoverySettings is how the Certificate Transparency source stands, for Settings and the form.
func (s *Server) discoverySettings() map[string]any {
	d := s.cfg.Discovery
	if d == nil {
		return map[string]any{"available": false, "certificateTransparency": false, "service": ""}
	}
	return map[string]any{"available": true, "certificateTransparency": d.CTAllowed(), "service": d.CTService()}
}

func (s *Server) listDiscoveries(w http.ResponseWriter, _ *http.Request) {
	list, err := s.cfg.Store.ListDiscoveries()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"discoveries": list, "settings": s.discoverySettings(),
		"scanScope": append([]string{}, s.cfg.Guard.Scope.Entries()...)})
}

// startDiscovery begins a run: {"domain": "example.com", "sources": ["stored","dns","ct","wordlist","list"],
// "list": "one name per line"}. Without sources it uses the two that send nothing outside this
// network's own DNS: what the store already holds, and the domain's records.
func (s *Server) startDiscovery(w http.ResponseWriter, r *http.Request) {
	d := s.discoverer(w)
	if d == nil {
		return
	}
	var in struct {
		Domain  string   `json:"domain"`
		Sources []string `json:"sources"`
		List    string   `json:"list"`
	}
	if !decodeMax(w, r, &in, maxBulkBody) {
		return
	}
	domain, err := namefind.NormalizeDomain(in.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.cfg.Guard.CheckDomain(domain); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sources := []string{}
	for _, src := range in.Sources {
		src = strings.ToLower(strings.TrimSpace(src))
		if !contains(namefind.AllSources, src) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("unknown source %q; the sources are %s", src, strings.Join(namefind.AllSources, ", ")))
			return
		}
		if !contains(sources, src) {
			sources = append(sources, src)
		}
	}
	if len(sources) == 0 {
		sources = []string{namefind.SourceStored, namefind.SourceDNS}
	}
	if contains(sources, namefind.SourceCT) && !d.CTAllowed() {
		writeErr(w, http.StatusBadRequest, "searching certificate logs is turned off. It sends the domain name to "+d.CTService()+
			"; an administrator can turn it on in Settings")
		return
	}
	var list []string
	for _, line := range strings.Split(strings.ReplaceAll(in.List, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			// A pasted URL or host:port is reduced to its host.
			if t, err := normalizeTarget(line); err == nil {
				line = t.host
			}
			list = append(list, line)
		}
	}
	if len(list) > maxBulkLines {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("at most %d names in the list", maxBulkLines))
		return
	}
	if len(list) > 0 && !contains(sources, namefind.SourceList) {
		sources = append(sources, namefind.SourceList)
	}
	sort.Slice(sources, func(i, j int) bool {
		return indexOf(namefind.AllSources, sources[i]) < indexOf(namefind.AllSources, sources[j])
	})
	rec, err := d.Begin(domain, sources, list, s.actor(r))
	if errors.Is(err, ErrDiscoveryBusy) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	s.recordDiscovery(r, rec.ID, "started", domain+"; sources: "+strings.Join(sources, ", "))
	writeJSON(w, http.StatusAccepted, rec)
}

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return len(list)
}

func (s *Server) recordDiscovery(r *http.Request, id int64, action, detail string) {
	reason, _ := reasonOf(r)
	if err := s.cfg.Store.RecordAction(s.actor(r), s.clientOf(r), "discovery", id, action, detail, reason); err != nil {
		s.log.Error("audit write failed", "action", "discovery "+action, "err", err)
	}
}

func (s *Server) getDiscovery(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	rec, err := s.cfg.Store.GetDiscovery(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	names, err := s.cfg.Store.DiscoveryNames(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	extendWriteDeadline(w, s.log, bulkWriteTimeout)
	writeJSON(w, 200, map[string]any{"discovery": rec, "names": names})
}

func (s *Server) cancelDiscovery(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Store.GetDiscovery(id); err != nil {
		storeErr(w, err)
		return
	}
	was, err := s.cfg.Store.CancelDiscovery(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if d := s.cfg.Discovery; d != nil {
		d.Cancel(id)
	}
	if was {
		s.recordDiscovery(r, id, "canceled", "")
	}
	rec, err := s.cfg.Store.GetDiscovery(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) deleteDiscovery(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	rec, err := s.cfg.Store.GetDiscovery(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if rec.Status == store.DiscoveryRunning {
		writeErr(w, http.StatusConflict, "this discovery is still running; cancel it first")
		return
	}
	if err := s.cfg.Store.DeleteDiscovery(id); err != nil {
		storeErr(w, err)
		return
	}
	s.recordDiscovery(r, id, "deleted", rec.Domain)
	w.WriteHeader(http.StatusNoContent)
}

// AcceptResult is the outcome for one endpoint an accepted name became.
type AcceptResult struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	Status string `json:"status"` // added | duplicate | invalid
	Reason string `json:"reason,omitempty"`
}

// acceptDiscovery adds names of a finished run as endpoints, one per port that answered:
// {"names": ["a.example.com"], "all": false, "scan": true, "tags": ["web"]}. Port 22 becomes an
// SSH server, every other port a TLS endpoint. A name on which nothing answered, or that may not
// be reached, is skipped and counted. Every endpoint is tagged with the domain.
func (s *Server) acceptDiscovery(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Names []string `json:"names"`
		All   bool     `json:"all"`
		Scan  bool     `json:"scan"`
		Tags  []string `json:"tags"`
	}
	if !decodeMax(w, r, &in, maxBulkBody) {
		return
	}
	rec, err := s.cfg.Store.GetDiscovery(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if rec.Status != store.DiscoveryDone {
		writeErr(w, http.StatusConflict, "this discovery has no result to accept: it is "+rec.Status)
		return
	}
	if !in.All && len(in.Names) == 0 {
		writeErr(w, http.StatusBadRequest, "name the hosts to add, or pass all")
		return
	}
	found, err := s.cfg.Store.DiscoveryNames(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	want := map[string]bool{}
	for _, n := range in.Names {
		want[strings.ToLower(strings.TrimSpace(n))] = true
	}
	tag := rec.Domain
	if len(tag) > 30 {
		tag = "discovery-" + strconv.FormatInt(id, 10)
	}
	tags, err := normalizeTags(append([]string{tag}, in.Tags...))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	extendWriteDeadline(w, s.log, bulkWriteTimeout)
	results := []AcceptResult{}
	counts := map[string]int{}
	var accepted []string
	var ids []int64
	skipped, unknown := 0, len(want)
	for _, n := range found {
		if !in.All && !want[n.Name] {
			continue
		}
		if want[n.Name] {
			unknown--
		}
		if r.Context().Err() != nil {
			return
		}
		if n.Refused != "" || len(n.Ports) == 0 {
			skipped++
			continue
		}
		for _, port := range n.Ports {
			protocol := "tls"
			if port == 22 {
				protocol = "ssh"
			}
			target := net.JoinHostPort(n.Name, strconv.Itoa(port))
			a, status, msg := s.newAsset(r.Context(), createReq{Target: target, Tags: tags, Protocol: protocol})
			res := AcceptResult{Name: n.Name, Target: target}
			switch status {
			case 0:
				res.Status = "added"
				ids = append(ids, a.ID)
			case http.StatusConflict:
				res.Status, res.Reason = "duplicate", msg
			default:
				res.Status, res.Reason = "invalid", msg
			}
			counts[res.Status]++
			if res.Status != "added" && len(results) < 500 {
				results = append(results, res)
			}
		}
		accepted = append(accepted, n.Name)
	}
	if err := s.cfg.Store.MarkDiscoveryAccepted(id, accepted); err != nil {
		storeErr(w, err)
		return
	}
	queued := 0
	if in.Scan {
		for _, aid := range ids {
			if _, existing, err := s.queue(aid, "bulk", s.actor(r)); err == nil && !existing {
				queued++
			}
		}
	}
	s.recordDiscovery(r, id, "names accepted", fmt.Sprintf("%s; %d names, %d endpoints added, %d already present, %d scans queued",
		rec.Domain, len(accepted), counts["added"], counts["duplicate"], queued))
	writeJSON(w, 200, map[string]any{
		"names": len(accepted), "added": counts["added"], "duplicate": counts["duplicate"], "invalid": counts["invalid"],
		"skipped": skipped, "unknown": unknown, "queued": queued, "tag": tag, "problems": results,
	})
}

// putDiscoverySettings turns the Certificate Transparency source on or off:
// {"certificateTransparency": "on" | "off"}.
func (s *Server) putDiscoverySettings(w http.ResponseWriter, r *http.Request) {
	d := s.discoverer(w)
	if d == nil {
		return
	}
	var in struct {
		CT string `json:"certificateTransparency"`
	}
	if !decode(w, r, &in) {
		return
	}
	v := strings.ToLower(strings.TrimSpace(in.CT))
	if v != "on" && v != "off" {
		writeErr(w, http.StatusBadRequest, "certificateTransparency must be on or off")
		return
	}
	if err := s.cfg.Store.SetSetting(store.SettingDiscoveryCT, v); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "discovery-settings-changed", s.actor(r), "certificate log search ("+d.CTService()+") "+v)
	writeJSON(w, http.StatusOK, s.discoverySettings())
}
