package sshprobe

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/wire"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
)

// Options bound a scan. The zero value is usable.
type Options struct {
	// Timeout bounds each connection. Default 8s.
	Timeout time.Duration
	// Concurrency is how many connections may be open to the target at once. Default 4.
	Concurrency int
	// MaxConnections caps the whole scan. Default and ceiling: MaxScanConnections.
	MaxConnections int
	// MinInterval is the minimum spacing between connection starts.
	MinInterval time.Duration
	// Dial, LookupIP, Now, Progress and Tick are as in tlsprobe.Options: the server's guard
	// replaces Dial and LookupIP, so the scan scope applies to every connection.
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	Now      func() time.Time
	Progress func(msg string)
	Tick     func(connections int)
}

// MaxScanConnections is the most connections one SSH scan makes (PRD-008 REQ-SHP-7).
const MaxScanConnections = 24

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.MaxConnections <= 0 || o.MaxConnections > MaxScanConnections {
		o.MaxConnections = MaxScanConnections
	}
	if o.Dial == nil {
		d := &net.Dialer{}
		o.Dial = d.DialContext
	}
	if o.LookupIP == nil {
		o.LookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// ClientIdentification is what the scanner says it is: honestly, a scanner.
func ClientIdentification() string {
	return "SSH-2.0-CipherHorizon_" + strings.ReplaceAll(version.Version, " ", "_")
}

// ParseTarget reads host, host:port, [v6]:port or ssh://host[:port]; the default port is 22.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "ssh://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return Target{}, errors.New("empty target")
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		host, portStr = strings.Trim(s, "[]"), "22"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("invalid port %q", portStr)
	}
	if host == "" {
		return Target{}, errors.New("empty host")
	}
	return Target{Host: host, Port: port}, nil
}

type prober struct {
	opts   Options
	target Target
	addr   string

	sem       chan struct{}
	conns     atomic.Int64
	spacingMu sync.Mutex
	nextStart time.Time

	mu    sync.Mutex
	notes []string // reserved for observations about the probing itself
}

// PanicError is a bug in the scanner, reported as an error with its stack.
type PanicError = tlsprobe.PanicError

var errBudget = errors.New("the scan's connection budget is used up")

// session is one connection that got as far as the server's KEXINIT.
type session struct {
	conn   net.Conn
	rd     *bufio.Reader
	id     wire.Identification
	pre    []string
	vs     []byte // the server's identification, as hashed (no CR LF)
	is     []byte // the server's KEXINIT payload
	kexini *wire.KexInit
}

func (p *prober) progress(msg string) {
	if p.opts.Progress != nil {
		p.opts.Progress(msg)
	}
}

func (p *prober) note(format string, args ...any) {
	p.mu.Lock()
	p.notes = append(p.notes, fmt.Sprintf(format, args...))
	p.mu.Unlock()
}

// open dials, exchanges identifications and reads the server's KEXINIT. The caller closes conn
// and calls release.
func (p *prober) open(ctx context.Context) (*session, func(), error) {
	// Reserve a connection from the budget atomically: a load-then-add lets concurrent host key
	// attempts all see room and overshoot the budget. A reservation that never dials is given back.
	var n int64
	for {
		c := p.conns.Load()
		if int(c) >= p.opts.MaxConnections {
			return nil, nil, errBudget
		}
		if p.conns.CompareAndSwap(c, c+1) {
			n = c + 1
			break
		}
	}
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		p.conns.Add(-1)
		return nil, nil, ctx.Err()
	}
	release := func() { <-p.sem }
	if p.opts.MinInterval > 0 {
		p.spacingMu.Lock()
		wait := time.Until(p.nextStart)
		p.nextStart = time.Now().Add(max(wait, 0) + p.opts.MinInterval)
		p.spacingMu.Unlock()
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				release()
				p.conns.Add(-1)
				return nil, nil, ctx.Err()
			}
		}
	}
	if p.opts.Tick != nil {
		p.opts.Tick(int(n))
	}
	dctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	conn, err := p.opts.Dial(dctx, "tcp", p.addr)
	if err != nil {
		release()
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	rel := func() { stop(); release() }
	_ = conn.SetDeadline(time.Now().Add(p.opts.Timeout))
	if _, err := io.WriteString(conn, ClientIdentification()+"\r\n"); err != nil {
		_ = conn.Close()
		rel()
		return nil, nil, err
	}
	s := &session{conn: conn, rd: bufio.NewReaderSize(conn, 4096)}
	s.id, s.pre, err = wire.ReadIdentification(s.rd)
	if err != nil {
		_ = conn.Close()
		rel()
		return s, nil, err
	}
	s.vs = []byte(strings.TrimRight(s.id.Raw, "\r\n"))
	if !s.id.SSH2() {
		return s, rel, nil // SSH-1 only: there is no KEXINIT to read
	}
	for {
		pl, err := wire.ReadPacket(s.rd)
		if err != nil {
			_ = conn.Close()
			rel()
			return s, nil, fmt.Errorf("reading the server's KEXINIT: %w", err)
		}
		switch pl[0] {
		case wire.MsgIgnore, wire.MsgDebug:
			continue
		case wire.MsgDisconnect:
			_ = conn.Close()
			rel()
			return s, nil, fmt.Errorf("the server disconnected: %s", wire.ParseDisconnect(pl).Description)
		}
		k, err := wire.ParseKexInit(pl)
		if err != nil {
			_ = conn.Close()
			rel()
			return s, nil, err
		}
		s.is, s.kexini = pl, k
		return s, rel, nil
	}
}

// exchange sends our KEXINIT with the given lists and one key-exchange init message, and returns
// the server's reply together with the exchange hash it should have signed.
func (p *prober) exchange(s *session, kexName string, kex, hostKey, ciphers, macs, comp []string) (*wire.KexReply, []byte, error) {
	m, ok := kexMethods[kexName]
	if !ok {
		return nil, nil, fmt.Errorf("%s is not a key exchange this scanner carries out", kexName)
	}
	ki := &wire.KexInit{Kex: kex, HostKey: hostKey, CipherC2S: ciphers, CipherS2C: ciphers, MACC2S: macs, MACS2C: macs,
		CompressionC2S: comp, CompS2C: comp, LanguageC2S: []string{}, LanguageS2C: []string{}}
	if _, err := rand.Read(ki.Cookie[:]); err != nil {
		return nil, nil, err
	}
	ic := ki.Marshal()
	qc, finish, err := m.start()
	if err != nil {
		return nil, nil, err
	}
	init := &wire.Builder{}
	init.Byte(wire.MsgKexInit30)
	init.String(qc)
	for _, payload := range [][]byte{ic, init.B} {
		pkt, err := wire.Packet(payload, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if _, err := s.conn.Write(pkt); err != nil {
			return nil, nil, err
		}
	}
	for {
		pl, err := wire.ReadPacket(s.rd)
		if err != nil {
			return nil, nil, err
		}
		switch pl[0] {
		case wire.MsgIgnore, wire.MsgDebug:
			continue
		case wire.MsgDisconnect:
			return nil, nil, fmt.Errorf("%w: %s", errRefused, wire.ParseDisconnect(pl).Description)
		}
		rep, err := wire.ParseKexReply(pl)
		if err != nil {
			return nil, nil, err
		}
		k, err := finish(rep.Value)
		if err != nil {
			return rep, nil, err
		}
		return rep, exchangeHash(m.hash, []byte(ClientIdentification()), s.vs, ic, s.is, rep.HostKey, qc, rep.Value, k), nil
	}
}

// errRefused marks a server that said no (a disconnect) rather than failing to answer.
var errRefused = errors.New("the server refused")

// Scan probes one SSH endpoint.
func Scan(ctx context.Context, t Target, opts Options) (rep *Report, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &tlsprobe.PanicError{Value: v, Stack: debug.Stack()}
			if rep != nil {
				rep.Incomplete = true
			}
		}
	}()
	opts.defaults()
	rep = &Report{SchemaVersion: SchemaVersion, Target: t, Started: opts.Now(), HostKeys: []HostKey{}, HostKeyAttempts: []HostKeyAttempt{}}

	ips, err := opts.LookupIP(ctx, t.Host)
	if err != nil || len(ips) == 0 {
		rep.Stages = notReached(nil, "the name did not resolve")
		if err == nil {
			err = errors.New("no addresses")
		}
		return rep, fmt.Errorf("resolving %s: %w", t.Host, err)
	}
	ip := ips[0]
	for _, a := range ips {
		rep.Addresses = append(rep.Addresses, a.String())
		if ip.To4() == nil && a.To4() != nil {
			ip = a
		}
	}
	p := &prober{opts: opts, target: t, addr: net.JoinHostPort(ip.String(), strconv.Itoa(t.Port)), sem: make(chan struct{}, opts.Concurrency)}
	rep.Address = p.addr
	defer func() {
		rep.DurationMS = opts.Now().Sub(rep.Started).Milliseconds()
		rep.Connections = int(p.conns.Load())
		rep.Notes = append(rep.Notes, p.notes...)
	}()
	clock := &stageClock{p: p}

	// Stage 1 and 2: the identification and the algorithm lists, from one connection.
	p.progress("reading the server's identification")
	clock.begin()
	s, release, err := p.open(ctx)
	if s != nil && s.id.Raw != "" {
		rep.Identification = &Identification{Raw: s.id.Raw, ProtoVersion: s.id.ProtoVersion, Software: s.id.Software, Comment: s.id.Comment,
			SSH1: strings.HasPrefix(s.id.ProtoVersion, "1."), SSH1Only: strings.HasPrefix(s.id.ProtoVersion, "1.") && s.id.ProtoVersion != "1.99", Preamble: s.pre}
	}
	if rep.Identification == nil {
		why := "the service did not send an SSH identification line"
		switch {
		case s != nil && len(s.pre) > 0:
			why += " (it sent: " + s.pre[0] + ")"
		case s != nil:
			// Connected, but nothing SSH came back: a TLS port closes on our identification.
			why += "; it closed the connection or answered in another protocol. Check the port, or scan it as TLS"
		case err != nil:
			why = "the endpoint could not be reached: " + err.Error()
		}
		rep.Incomplete = true
		rep.Stages = append(rep.Stages, clock.end(StageIdentification, tlsprobe.OutcomeInconclusive, why, tlsprobe.ReasonNotReached, probesIdentification))
		rep.Stages = notReached(rep.Stages, "no SSH identification was read")
		return rep, errors.New(why)
	}
	rep.Stages = append(rep.Stages, clock.end(StageIdentification, tlsprobe.OutcomeDone, "", "", probesIdentification))
	if rep.Identification.SSH1Only {
		if release != nil {
			_ = s.conn.Close()
			release()
		}
		why := "the server speaks only SSH-1, which has no algorithm negotiation to read"
		rep.Stages = append(rep.Stages, Stage{Name: StageAlgorithms, Outcome: tlsprobe.OutcomeSkipped, Reason: why, ReasonCode: tlsprobe.ReasonNotApplicable},
			Stage{Name: StageNegotiation, Outcome: tlsprobe.OutcomeSkipped, Reason: why, ReasonCode: tlsprobe.ReasonNotApplicable},
			Stage{Name: StageHostKeys, Outcome: tlsprobe.OutcomeSkipped, Reason: why, ReasonCode: tlsprobe.ReasonNotApplicable})
		return rep, nil
	}
	if err != nil || s.kexini == nil {
		why := "the server's algorithm lists (KEXINIT) could not be read"
		if err != nil {
			why += ": " + err.Error()
		}
		rep.Incomplete = true
		rep.Stages = append(rep.Stages, Stage{Name: StageAlgorithms, Outcome: tlsprobe.OutcomeInconclusive, Reason: why, ReasonCode: tlsprobe.ReasonNotReached})
		rep.Stages = notReached(rep.Stages, "the algorithm lists were not read")
		return rep, errors.New(why)
	}
	_ = s.conn.Close()
	release()
	rep.Algorithms = algorithmsOf(s.kexini)
	rep.Stages = append(rep.Stages, Stage{Name: StageAlgorithms, Outcome: tlsprobe.OutcomeDone, Probes: probesAlgorithms})

	// Stage 3: negotiate as a current client.
	p.progress("negotiating as a current client")
	clock.begin()
	n := negotiate(rep.Algorithms, clientKex, clientHostKey, clientCiphers, clientMACs, clientCompression)
	rep.Negotiated = &n
	switch {
	case n.Kex == "":
		n.Evidence, n.Error = EvidenceComputed, "no key exchange or host key algorithm in common with the current client"
		rep.Stages = append(rep.Stages, clock.end(StageNegotiation, tlsprobe.OutcomeDone, n.Error, "", probesNegotiation))
	case kexMethods[n.Kex].start == nil:
		n.Evidence = EvidenceComputed
		rep.Stages = append(rep.Stages, clock.end(StageNegotiation, tlsprobe.OutcomeDone,
			n.Kex+" is chosen by the two lists (RFC 4253 section 7.1); this scanner does not carry it out, so the choice is computed, not observed", "", probesNegotiation))
	default:
		key, v, nerr := p.fetchKey(ctx, n.Kex, append(append([]string(nil), clientKex...), clientSignals...), clientHostKey, clientCiphers, clientMACs, clientCompression, n.HostKey)
		n.Evidence = EvidenceObserved
		if nerr != nil {
			n.Error = nerr.Error()
			rep.Incomplete = rep.Incomplete || !errors.Is(nerr, errRefused)
			rep.Stages = append(rep.Stages, clock.end(StageNegotiation, tlsprobe.OutcomeInconclusive, "the key exchange did not complete: "+nerr.Error(), "", probesNegotiation))
		} else {
			n.Completed, n.Verified = true, v.OK
			addKey(rep, key, n.HostKey, v)
			rep.Stages = append(rep.Stages, clock.end(StageNegotiation, tlsprobe.OutcomeDone, "", "", probesNegotiation))
		}
	}
	rep.Negotiated = &n

	// Stage 4: every advertised host key algorithm, one key exchange each.
	p.progress("fetching host keys")
	clock.begin()
	p.hostKeys(ctx, rep)
	rep.Stages = append(rep.Stages, hostKeyStage(clock, rep))
	if ctx.Err() != nil {
		rep.Incomplete = true
		return rep, ctx.Err()
	}
	return rep, nil
}

// fetchKey opens a connection, runs kexName offering the given lists, and returns the host key the
// server sent with its signature check. want is the host key algorithm the signature is in.
func (p *prober) fetchKey(ctx context.Context, kexName string, kex, hostKey, ciphers, macs, comp []string, want string) (*wire.PublicKey, wire.Verified, error) {
	s, release, err := p.open(ctx)
	if err != nil {
		return nil, wire.Verified{}, err
	}
	defer release()
	defer func() { _ = s.conn.Close() }()
	if s.kexini == nil {
		return nil, wire.Verified{}, errors.New("no KEXINIT")
	}
	reply, h, err := p.exchange(s, kexName, kex, hostKey, ciphers, macs, comp)
	if err != nil {
		return nil, wire.Verified{}, err
	}
	key, err := wire.ParsePublicKey(reply.HostKey)
	if err != nil {
		return nil, wire.Verified{}, fmt.Errorf("the host key did not parse: %w", err)
	}
	if h == nil {
		return key, wire.Verified{Note: "the exchange could not be finished, so the signature was not checked"}, nil
	}
	return key, key.Verify(want, h, reply.Signature), nil
}

// hostKeys asks for each advertised host key algorithm in turn.
func (p *prober) hostKeys(ctx context.Context, rep *Report) {
	var kexName string
	for _, k := range hostKeyKexOrder {
		if slices.Contains(rep.Algorithms.Kex, k) {
			kexName = k
			break
		}
	}
	type result struct {
		key *wire.PublicKey
		v   wire.Verified
		err error
	}
	results := make([]result, len(rep.Algorithms.HostKey))
	var wg sync.WaitGroup
	for i, alg := range rep.Algorithms.HostKey {
		if kexName == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if v := recover(); v != nil {
					results[i].err = fmt.Errorf("internal error: %v", v)
				}
			}()
			key, v, err := p.fetchKey(ctx, kexName, []string{kexName}, []string{alg}, rep.Algorithms.CipherC2S, rep.Algorithms.MACC2S, rep.Algorithms.CompressionC2S, alg)
			results[i] = result{key, v, err}
		}()
	}
	wg.Wait()
	cut := 0
	for _, r := range results {
		if errors.Is(r.err, errBudget) {
			cut++
		}
	}
	if cut > 0 {
		p.note("the connection budget (%d) ran out: %d host key algorithms were not fetched", p.opts.MaxConnections, cut)
		rep.Incomplete = true
	}
	for i, alg := range rep.Algorithms.HostKey {
		at := HostKeyAttempt{Algorithm: alg, Kex: kexName}
		r := results[i]
		switch {
		case kexName == "":
			at.Outcome, at.Detail = AttemptNoCommonKex, "the server offers no key exchange this scanner carries out ("+strings.Join(rep.Algorithms.Kex, ", ")+")"
		case r.err != nil && errors.Is(r.err, errRefused):
			at.Outcome, at.Detail = AttemptRefused, r.err.Error()
		case r.err != nil:
			at.Outcome, at.Detail = AttemptInconclusive, r.err.Error()
		default:
			at.Outcome = AttemptKey
			addKey(rep, r.key, alg, r.v)
		}
		rep.HostKeyAttempts = append(rep.HostKeyAttempts, at)
	}
}

// addKey records a host key once per fingerprint, with every algorithm that returned it.
func addKey(rep *Report, k *wire.PublicKey, alg string, v wire.Verified) {
	for i := range rep.HostKeys {
		hk := &rep.HostKeys[i]
		if hk.Fingerprint == k.Fingerprint {
			if !slices.Contains(hk.ServedBy, alg) {
				hk.ServedBy = append(hk.ServedBy, alg)
			}
			if v.OK {
				hk.Verified, hk.VerifyNote = true, ""
			}
			return
		}
	}
	rep.HostKeys = append(rep.HostKeys, HostKey{Type: k.Type, Algorithm: k.Algorithm, Bits: k.Bits, Curve: k.Curve, PQ: k.PQ,
		Fingerprint: k.Fingerprint, Blob: base64.StdEncoding.EncodeToString(k.Blob()), ServedBy: []string{alg},
		Verified: v.OK, VerifyNote: v.Note, Certificate: k.Cert})
}

// algorithmsOf breaks a KEXINIT into the report's lists.
func algorithmsOf(k *wire.KexInit) *Algorithms {
	a := &Algorithms{HostKey: k.HostKey, CipherC2S: k.CipherC2S, CipherS2C: k.CipherS2C, MACC2S: k.MACC2S, MACS2C: k.MACS2C,
		CompressionC2S: k.CompressionC2S, CompressionS2C: k.CompS2C, Kex: []string{}}
	for _, name := range k.Kex {
		switch {
		case name == "kex-strict-s-v00@openssh.com":
			a.StrictKex = true
		case name == "ext-info-s":
			a.ExtInfo = true
		case registry.IsPseudo(name):
			a.Signals = append(a.Signals, name)
		default:
			a.Kex = append(a.Kex, name)
		}
	}
	return a
}

func hostKeyStage(clock *stageClock, rep *Report) Stage {
	var bad []string
	got := 0
	for _, a := range rep.HostKeyAttempts {
		switch a.Outcome {
		case AttemptKey:
			got++
		case AttemptNoCommonKex, AttemptInconclusive:
			bad = append(bad, a.Algorithm+": "+a.Detail)
		}
	}
	switch {
	case len(rep.HostKeyAttempts) == 0:
		return clock.end(StageHostKeys, tlsprobe.OutcomeSkipped, "the server advertises no host key algorithm", tlsprobe.ReasonNotApplicable, probesHostKeys)
	case got == 0 && len(rep.HostKeys) == 0:
		why := "no host key could be fetched"
		if len(bad) > 0 {
			why += ": " + bad[0]
		}
		return clock.end(StageHostKeys, tlsprobe.OutcomeInconclusive, why, tlsprobe.ReasonNotReached, probesHostKeys)
	}
	st := clock.end(StageHostKeys, tlsprobe.OutcomeDone, "", "", probesHostKeys)
	st.Inconclusive = bad
	return st
}

// What each stage sends, in words.
var (
	probesIdentification = []string{"one connection: send this scanner's identification, read the server's and its algorithm lists (KEXINIT), then close"}
	probesAlgorithms     = []string{"read from the server's KEXINIT on the first connection: nothing more is sent"}
	probesNegotiation    = []string{"one connection offering OpenSSH 10.6's default lists; the key exchange is run to the server's reply and its signature checked, then the connection is closed before any key is used"}
	probesHostKeys       = []string{"one connection per advertised host key algorithm, offering only that algorithm, run to the server's reply; never a login"}
)

// stageClock attributes connections to the stage that made them.
type stageClock struct {
	p     *prober
	start int64
}

func (c *stageClock) begin() { c.start = c.p.conns.Load() }

func (c *stageClock) end(name, outcome, reason, code string, probes []string) Stage {
	return Stage{Name: name, Outcome: outcome, Reason: reason, ReasonCode: code, Connections: int(c.p.conns.Load() - c.start), Probes: probes}
}

// notReached adds a skipped record for every stage not yet recorded.
func notReached(have []Stage, why string) []Stage {
	done := map[string]bool{}
	for _, s := range have {
		done[s.Name] = true
	}
	for _, n := range StageNames {
		if !done[n] {
			have = append(have, Stage{Name: n, Outcome: tlsprobe.OutcomeSkipped, Reason: why, ReasonCode: tlsprobe.ReasonNotReached})
		}
	}
	return have
}
