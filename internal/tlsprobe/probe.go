package tlsprobe

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/cipherhorizon/internal/tlsprobe/wire"
)

// Options bound and shape a scan. The zero value is usable and conservative.
type Options struct {
	// Timeout bounds each connection (dial plus exchange). Default 8s.
	Timeout time.Duration
	// Concurrency is how many connections may be in flight to the target at once.
	// Default 4. A scan makes a few hundred short connections; this keeps it gentle.
	Concurrency int
	// MaxConnections is a hard cap on connections for the whole scan. Default 2000.
	// When it is reached the scan stops probing and the report is marked incomplete.
	MaxConnections int
	// MinInterval is the minimum spacing between the starts of two connections.
	MinInterval time.Duration
	// SkipCertificates omits the crypto/tls-based certificate and negotiation steps.
	SkipCertificates bool
	// HTTPChecks, when set, sends one plain HTTP GET / after the handshake and
	// reads the Strict-Transport-Security header. Off by default: this is the
	// only check in the package that sends anything beyond a TLS handshake.
	HTTPChecks bool
	// OSTrust, when set, also checks each chain against the operating system's
	// trust store at scan time (REQ-TTRS-3). Off by default: the bundled root
	// stores are applied in evaluation, and on some systems the OS verifier
	// fetches missing intermediates from the network, which would contact a
	// host other than the target.
	OSTrust bool

	// Dial opens a connection. Default: net.Dialer. Tests and the future
	// STARTTLS/SSRF-guard layers replace it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// LookupIP resolves a host name. Default: net.DefaultResolver.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// Rand supplies the ClientHello randoms. Default crypto/rand.
	Rand io.Reader
	// Now returns the current time. Default time.Now.
	Now func() time.Time
	// Progress, if set, is told what the scan is doing.
	Progress func(msg string)
	// Tick, if set, is called with the running connection count each time a
	// connection is started. It may be called concurrently.
	Tick func(connections int)
}

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.MaxConnections <= 0 {
		o.MaxConnections = 2000
	}
	if o.Dial == nil {
		d := &net.Dialer{}
		o.Dial = d.DialContext
	}
	if o.LookupIP == nil {
		o.LookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, err
		}
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// ParseTarget parses "host", "host:port", "[v6]:port" or a bare IPv6 literal.
// The default port is 443.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, errors.New("empty target")
	}
	host, port := s, 443
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("invalid port %q", p)
		}
		host, port = h, n
	} else if strings.Contains(s, ":") && net.ParseIP(s) == nil && !strings.HasPrefix(s, "[") {
		return Target{}, fmt.Errorf("invalid target %q", s)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return Target{}, errors.New("empty host")
	}
	t := Target{Host: host, Port: port}
	if net.ParseIP(host) == nil {
		t.SNI = host
	}
	return t, nil
}

// prober carries the state shared by all probes of one scan.
type prober struct {
	opts   Options
	target Target
	addr   string // ip:port being probed

	sem   chan struct{}
	conns atomic.Int64

	rndMu sync.Mutex

	spacingMu sync.Mutex
	nextStart time.Time

	incomplete atomic.Bool
	// recovered is the first panic caught in a probe goroutine.
	recovered atomic.Pointer[PanicError]
	budgetHit atomic.Bool
	notesMu   sync.Mutex
	notes     []string
	// stageIncon collects, for the running stage, what proved nothing.
	stageIncon []string
}

func newProber(opts Options, t Target, addr string) *prober {
	return &prober{opts: opts, target: t, addr: addr, sem: make(chan struct{}, opts.Concurrency)}
}

func (p *prober) note(format string, args ...any) {
	p.notesMu.Lock()
	defer p.notesMu.Unlock()
	p.notes = append(p.notes, fmt.Sprintf(format, args...))
}

func (p *prober) progress(msg string) {
	if p.opts.Progress != nil {
		p.opts.Progress(msg)
	}
}

// random reads from the shared randomness source under a lock.
func (p *prober) random() io.Reader { return &lockedReader{p: p} }

type lockedReader struct{ p *prober }

func (r *lockedReader) Read(b []byte) (int, error) {
	r.p.rndMu.Lock()
	defer r.p.rndMu.Unlock()
	return r.p.opts.Rand.Read(b)
}

// PanicError is returned by Scan when the prober itself failed: a bug, most likely triggered by
// an answer nobody anticipated. Stack is for the log, never for the person who asked for the scan.
type PanicError struct {
	Value any
	Stack []byte
}

func newPanicError(v any) *PanicError { return &PanicError{Value: v, Stack: debug.Stack()} }

func (e *PanicError) Error() string { return fmt.Sprintf("internal error in the scanner: %v", e.Value) }

// catch is deferred by every probe goroutine: a panic there would otherwise end the whole
// process, since recover works only in the goroutine that panicked. The first one is kept and
// returned from Scan, and the report is marked incomplete.
func (p *prober) catch() {
	if v := recover(); v != nil {
		p.recovered.CompareAndSwap(nil, newPanicError(v))
		p.incomplete.Store(true)
	}
}

// errBudget is returned once the connection budget is spent.
var errBudget = errors.New("connection budget exhausted")

// acquire takes a concurrency slot, honours the spacing and budget, and returns
// the release func. Every connection the scan makes goes through here.
func (p *prober) acquire(ctx context.Context) (func(), error) {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release := func() { <-p.sem }

	n := p.conns.Add(1)
	if n > int64(p.opts.MaxConnections) {
		p.conns.Add(-1)
		p.incomplete.Store(true)
		p.budgetHit.Store(true)
		release()
		return nil, errBudget
	}
	if p.opts.Tick != nil {
		p.opts.Tick(int(n))
	}
	if d := p.opts.MinInterval; d > 0 {
		p.spacingMu.Lock()
		now := time.Now()
		start := p.nextStart
		if start.Before(now) {
			start = now
		}
		p.nextStart = start.Add(d)
		p.spacingMu.Unlock()
		if wait := time.Until(start); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				release()
				return nil, ctx.Err()
			}
		}
	}
	return release, nil
}

// Kind classifies what a probe got back.
type kind int

const (
	kindServerHello kind = iota // a ServerHello (or HelloRetryRequest) arrived
	kindAlert                   // the server refused with an alert
	kindClosed                  // closed/reset with no answer: a refusal, but a weak one
	kindNotTLS                  // the port answered, but not in TLS
	kindGarbage                 // TLS-looking bytes that did not parse
	kindTimeout                 // no answer in time: inconclusive
	kindError                   // dial or I/O error: inconclusive
)

// outcome is the result of one hello exchange.
type outcome struct {
	kind   kind
	flight *wire.Flight
	err    error
}

func (o outcome) serverHello() *wire.ServerHello {
	if o.flight == nil {
		return nil
	}
	return o.flight.ServerHello
}

func (o outcome) alert() *wire.Alert {
	if o.flight == nil {
		return nil
	}
	return o.flight.Alert
}

// conclusive says whether the outcome is an answer from the server (of any kind),
// as opposed to a network problem.
func (o outcome) conclusive() bool {
	switch o.kind {
	case kindTimeout, kindError:
		return false
	}
	return true
}

func (o outcome) evidence() Evidence {
	switch o.kind {
	case kindServerHello:
		return EvidenceServerHello
	case kindAlert:
		return EvidenceAlert
	case kindClosed, kindNotTLS, kindGarbage:
		return EvidenceClosed
	}
	return EvidenceInconclusive
}

func (o outcome) detail() string {
	switch {
	case o.alert() != nil:
		return o.alert().String()
	case o.err != nil:
		return o.err.Error()
	}
	return ""
}

// exchange sends a ClientHello and reads the reply. A connection that fails at
// the network level is retried once, since a single dropped connection must not
// be mistaken for "the server refused".
func (p *prober) exchange(ctx context.Context, hello *wire.ClientHello) outcome {
	raw, err := hello.Marshal()
	if err != nil {
		return outcome{kind: kindError, err: err}
	}
	out := p.exchangeRaw(ctx, raw)
	if out.kind == kindError || out.kind == kindTimeout {
		if ctx.Err() == nil {
			out = p.exchangeRaw(ctx, raw)
		}
	}
	return out
}

func (p *prober) exchangeRaw(ctx context.Context, raw []byte) outcome {
	conn, release, err := p.connect(ctx)
	if err != nil {
		return outcome{kind: classifyNetErr(err), err: err}
	}
	defer release()
	defer conn.Close() //nolint:errcheck // probe connection

	if _, err := conn.Write(raw); err != nil {
		return outcome{kind: classifyNetErr(err), err: err}
	}
	flight, err := wire.ReadFlight(conn)
	return classifyFlight(flight, err)
}

// connect dials the target under the limits and arms the per-connection deadline.
func (p *prober) connect(ctx context.Context) (net.Conn, func(), error) {
	release, err := p.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	conn, err := p.opts.Dial(cctx, "tcp", p.addr)
	if err != nil {
		cancel()
		release()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(p.opts.Timeout))
	return conn, func() { cancel(); release() }, nil
}

func classifyFlight(f *wire.Flight, err error) outcome {
	if f != nil && f.ServerHello != nil {
		return outcome{kind: kindServerHello, flight: f}
	}
	if f != nil && f.Alert != nil {
		return outcome{kind: kindAlert, flight: f}
	}
	var notTLS *wire.NotTLSError
	switch {
	case err == nil:
		return outcome{kind: kindGarbage, flight: f, err: errors.New("no ServerHello and no alert")}
	case errors.As(err, &notTLS):
		return outcome{kind: kindNotTLS, flight: f, err: err}
	case errors.Is(err, wire.ErrNoResponse):
		return outcome{kind: kindClosed, flight: f, err: err}
	}
	if k := classifyNetErr(err); k != kindGarbage {
		return outcome{kind: k, flight: f, err: err}
	}
	return outcome{kind: kindGarbage, flight: f, err: err}
}

// classifyNetErr separates "no answer in time" and connection resets (a server
// hanging up on a hello it dislikes) from genuine network failure.
func classifyNetErr(err error) kind {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return kindTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), isReset(err):
		return kindClosed
	case errors.Is(err, errBudget), errors.Is(err, context.Canceled):
		return kindError
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return kindError
	}
	return kindGarbage // a parse error: TLS-shaped bytes that made no sense
}

func isReset(err error) bool {
	s := err.Error()
	return strings.Contains(s, "connection reset") || strings.Contains(s, "forcibly closed") ||
		strings.Contains(s, "broken pipe")
}
