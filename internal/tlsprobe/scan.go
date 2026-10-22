package tlsprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/wire"
)

// Scan probes one endpoint. It returns a non-nil Report whenever it learned
// anything, together with an error when the endpoint could not be scanned (for
// example, it is unreachable or does not speak TLS).
//
// The scan is bounded by Options (timeouts, concurrency, a hard connection
// budget) and by ctx. Only handshake messages are exchanged: no application
// data is sent and no key material is generated.
//
// A panic anywhere in the scan, including its probe goroutines, is recovered and returned as a
// *PanicError: a malformed answer from a hostile endpoint must fail that scan, not the process.
func Scan(ctx context.Context, t Target, opts Options) (rep *Report, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = newPanicError(v)
			if rep != nil {
				rep.Incomplete = true
			}
		}
	}()
	opts.defaults()
	initCandidates()

	rep = &Report{SchemaVersion: SchemaVersion, Target: t, Started: opts.Now(),
		Protocols: []ProtocolResult{}, Suites: []SuiteResult{}}

	ip, all, err := resolve(ctx, opts, t.Host)
	if err != nil {
		rep.Stages = notReached(nil, "the name did not resolve")
		return rep, fmt.Errorf("resolving %s: %w", t.Host, err)
	}
	for _, a := range all {
		rep.Addresses = append(rep.Addresses, a.String())
	}
	p := newProber(opts, t, net.JoinHostPort(ip.String(), strconv.Itoa(t.Port)))
	rep.Address = p.addr
	defer func() {
		rep.DurationMS = opts.Now().Sub(rep.Started).Milliseconds()
		rep.Connections = int(p.conns.Load())
		rep.Notes = append(rep.Notes, p.notes...)
		rep.Incomplete = rep.Incomplete || p.incomplete.Load()
		if pe := p.recovered.Load(); pe != nil && err == nil {
			err = pe
		}
	}()

	sc := &stageClock{p: p}

	// A STARTTLS service is asked once before anything else: if it will not switch to TLS (or is
	// not the protocol), every probe would fail the same way, so the scan stops here and says why
	// (PRD-007 REQ-SX-4).
	if t.StartTLS != "" {
		p.progress("negotiating STARTTLS (" + StartTLSName(t.StartTLS) + ")")
		conn, release, cerr := p.connect(ctx)
		if cerr != nil {
			rep.Incomplete = true
			why := "the service did not switch to TLS"
			var se *StartTLSError
			if !errors.As(cerr, &se) {
				why = "the endpoint could not be reached"
			}
			rep.Stages = notReached(nil, why)
			return rep, cerr
		}
		_ = conn.Close()
		release()
	}

	// Stage 1: which protocol versions does the server speak?
	p.progress("testing protocol versions")
	sc.begin()
	protos := p.detectProtocols(ctx)
	for _, pr := range protos {
		rep.Protocols = append(rep.Protocols, pr.result)
	}
	if err := reachability(protos); err != nil {
		rep.Incomplete = true
		rep.Stages = append(rep.Stages, sc.end(StageProtocols, OutcomeInconclusive, err.Error(), ReasonNotReached, probesProtocols))
		rep.Stages = notReached(rep.Stages, "the endpoint could not be scanned")
		return rep, err
	}
	for _, pr := range protos {
		if !pr.result.Supported && pr.result.Evidence == EvidenceInconclusive {
			p.inconclusive("%s: inconclusive (%s)", pr.result.Version, pr.result.Detail)
		}
	}
	rep.Stages = append(rep.Stages, sc.end(StageProtocols, OutcomeDone, "", "", probesProtocols))
	if ctx.Err() != nil {
		rep.Incomplete = true
		rep.Stages = notReached(rep.Stages, "the scan ran out of time")
		return rep, ctx.Err()
	}

	// Stage 2: enumerate suites per supported version, in parallel.
	p.progress("enumerating cipher suites")
	sc.begin()
	var (
		wg      sync.WaitGroup
		legacy  = map[wire.Version]*legacyEnum{}
		mu      sync.Mutex
		tls13   *tls13Enum
		highest wire.Version
	)
	for _, pr := range protos {
		v := pr.version
		if !pr.result.Supported || v == wire.VersionSSL20 || v == wire.VersionTLS13 {
			continue
		}
		if v > highest {
			highest = v
		}
		wg.Add(1)
		go func(v wire.Version, small bool) {
			defer wg.Done()
			defer p.catch()
			e := p.enumerateLegacy(ctx, v, small)
			mu.Lock()
			legacy[v] = e
			mu.Unlock()
		}(v, pr.small)
	}
	for _, pr := range protos {
		if pr.version == wire.VersionTLS13 && pr.result.Supported {
			wg.Add(1)
			go func(small bool) {
				defer wg.Done()
				defer p.catch()
				e := p.enumerateTLS13(ctx, small)
				mu.Lock()
				tls13 = e
				mu.Unlock()
			}(pr.small)
		}
	}
	wg.Wait()

	versions := make([]wire.Version, 0, len(legacy))
	for v := range legacy {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })

	if tls13 != nil {
		rep.Suites = append(rep.Suites, suiteResults(wire.VersionTLS13, tls13.suites, tls13.suitePref)...)
		rep.Groups = append(rep.Groups, groupResults(wire.VersionTLS13, tls13.groups, tls13.groupPref)...)
		rep.Preference = append(rep.Preference,
			PreferenceResult{Version: "TLSv1.3", Subject: "suites", Order: tls13.suitePref},
			PreferenceResult{Version: "TLSv1.3", Subject: "groups", Order: tls13.groupPref})
		if len(tls13.groups) == 0 {
			p.note("TLSv1.3 is supported but no key-exchange groups could be enumerated (the server may not send HelloRetryRequest for an empty key_share); see 'negotiated' for what a real client gets")
		}
	}
	for _, v := range versions {
		e := legacy[v]
		rep.Suites = append(rep.Suites, suiteResults(v, e.suites, e.pref)...)
		rep.Preference = append(rep.Preference, PreferenceResult{Version: v.String(), Subject: "suites", Order: e.pref})
	}
	if tls13 == nil && len(legacy) == 0 {
		rep.Stages = append(rep.Stages, sc.end(StageSuites, OutcomeSkipped,
			"only SSLv2 answered; SSLv2 cipher kinds are listed under protocols", ReasonNotApplicable, nil))
	} else {
		rep.Stages = append(rep.Stages, sc.end(StageSuites, OutcomeDone, "", "", probesSuites))
	}

	// Stage 3: ephemeral-ECDH curves and DH parameters for TLS 1.2 and earlier.
	// TLS 1.3 groups were read in stage 2, from the same HelloRetryRequests.
	sc.begin()
	if highest != 0 {
		e := legacy[highest]
		p.progress("probing key exchange")
		if s, ok := pickSuite(e.suites, func(s registry.Suite) bool {
			return s.Kx == "ECDHE" && s.Auth != "anon" && !strings.Contains(s.Name, "_PSK_")
		}); ok {
			curves, pref := p.enumerateCurves(ctx, highest, s.ID, e.small)
			rep.Groups = append(rep.Groups, groupResults(highest, curves, pref)...)
			rep.Preference = append(rep.Preference, PreferenceResult{Version: highest.String(), Subject: "groups", Order: pref})
		}
		if s, ok := pickSuite(e.suites, func(s registry.Suite) bool { return s.Kx == "DHE" && s.Auth != "anon" && !s.Export }); ok {
			rep.DH = p.sampleDH(ctx, highest, s, e.small)
		}
	}
	switch {
	case highest != 0:
		rep.Stages = append(rep.Stages, sc.end(StageKeyExchange, OutcomeDone, "", "", probesKeyExchange))
	case tls13 != nil:
		rep.Stages = append(rep.Stages, sc.end(StageKeyExchange, OutcomeDone,
			"TLS 1.3 only: the groups were read during suite enumeration", "", probesKeyExchange13))
	default:
		rep.Stages = append(rep.Stages, sc.end(StageKeyExchange, OutcomeSkipped,
			"no TLS version with a key exchange to test", ReasonNotApplicable, nil))
	}

	// Stage 3b: the TLS 1.3 signature schemes the server holds keys for (PRD-008 REQ-PQS-3).
	sc.begin()
	if tls13 != nil {
		p.progress("testing signature schemes")
		rep.Signatures = p.signatures(ctx, tls13small(protos), tls13.groups)
		switch rep.Signatures.Control {
		case SigAccepted:
			rep.Stages = append(rep.Stages, sc.end(StageSignatures, OutcomeInconclusive, rep.Signatures.ControlWhy, "", probesSignatures))
		case SigInconclusive:
			rep.Stages = append(rep.Stages, sc.end(StageSignatures, OutcomeInconclusive,
				"the control hello got no clear answer ("+rep.Signatures.ControlWhy+"), so the per-scheme answers prove nothing", "", probesSignatures))
		default:
			st := sc.end(StageSignatures, OutcomeDone, "", "", probesSignatures)
			for _, s := range rep.Signatures.Schemes {
				if s.Result == SigInconclusive {
					st.Inconclusive = append(st.Inconclusive, s.Name+": "+s.Why)
				}
			}
			rep.Stages = append(rep.Stages, st)
		}
	} else {
		rep.Stages = append(rep.Stages, sc.skip(StageSignatures, "TLS 1.3 is not supported; signature schemes are tested in TLS 1.3 only", ReasonNotApplicable))
	}

	// Stage 4: server features read from hello extensions. SSLv3 has none, and we
	// send none in an SSLv3 hello, so nothing can be concluded from it.
	sc.begin()
	if highest >= wire.VersionTLS10 {
		rep.Features = p.features(ctx, protos, legacy, highest)
		rep.Stages = append(rep.Stages, sc.end(StageFeatures, OutcomeDone, "", "", probesFeatures))
	} else {
		rep.Stages = append(rep.Stages, sc.end(StageFeatures, OutcomeSkipped,
			"these behaviours are read from TLS 1.0–1.2 hellos, and the server speaks none of those versions", ReasonNotApplicable, nil))
	}

	// Stage 5: certificates and what a current client negotiates. Revocation
	// data (the stapled OCSP response and SCTs) rides on the same handshakes.
	if opts.SkipCertificates {
		why := "certificate checks were turned off for this scan"
		rep.Stages = append(rep.Stages, sc.skip(StageCerts, why, ReasonOptionOff), sc.skip(StageRevocation, why, ReasonOptionOff))
	} else {
		p.progress("fetching certificates")
		sc.begin()
		rep.Certificates, rep.Negotiated, rep.Features.ClientCertRequested, rep.NoSNI = p.certificates(ctx, legacy)
		probes := probesCerts
		if t.SNI != "" {
			probes = append(append([]string(nil), probes...), "one handshake without server_name, to see the certificate such clients get")
		}
		if len(rep.Certificates) == 0 {
			why := "no handshake returned a certificate"
			if rep.Negotiated != nil && rep.Negotiated.Error != "" {
				why += ": " + rep.Negotiated.Error
			}
			rep.Stages = append(rep.Stages, sc.end(StageCerts, OutcomeInconclusive, why, ReasonNotReached, probes),
				sc.skip(StageRevocation, "no certificate was received", ReasonNotReached))
		} else {
			rep.Stages = append(rep.Stages, sc.end(StageCerts, OutcomeDone, "", "", probes),
				Stage{Name: StageRevocation, Outcome: OutcomeDone, Probes: probesRevocation})
		}
	}

	// Stage 6: the HTTP-layer check (HSTS), attempted only when the handshake it
	// would ride on succeeded.
	switch {
	case t.StartTLS != "":
		rep.Stages = append(rep.Stages, sc.skip(StageHTTP, "not an HTTP service: "+StartTLSName(t.StartTLS)+" over STARTTLS", ReasonNotApplicable))
	case !opts.HTTPChecks:
		rep.Stages = append(rep.Stages, sc.skip(StageHTTP, "HTTP checks are off for this scan (--http-checks=false)", ReasonOptionOff))
	case rep.Negotiated == nil || rep.Negotiated.Error != "":
		rep.Stages = append(rep.Stages, sc.skip(StageHTTP, "no full TLS handshake succeeded, so no HTTP request could be sent", ReasonNotReached))
	default:
		p.progress("checking HSTS")
		sc.begin()
		res, why := p.hstsCheck(ctx)
		switch {
		case res == nil && why == notHTTP:
			// Not an HTTP service: not applicable, not a failure (REQ-THTP-3).
			rep.Stages = append(rep.Stages, sc.end(StageHTTP, OutcomeSkipped, why, ReasonNotApplicable, probesHTTP))
		case res == nil:
			rep.Stages = append(rep.Stages, sc.end(StageHTTP, OutcomeInconclusive, why, "", probesHTTP))
		default:
			rep.HSTSHeader = res
			v := res.Valid()
			rep.HSTS = &v
			rep.Stages = append(rep.Stages, sc.end(StageHTTP, OutcomeDone, "", "", probesHTTP))
		}
	}

	sortReport(rep)
	return rep, nil
}

// resolve picks the address to probe: the first IPv4 address, else the first
// address, and returns all of them for the report.
func resolve(ctx context.Context, opts Options, host string) (net.IP, []net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, []net.IP{ip}, nil
	}
	ips, err := opts.LookupIP(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("no addresses")
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, ips, nil
		}
	}
	return ips[0], ips, nil
}

// ---- stage 1: protocol versions ---------------------------------------------------------

type protoProbe struct {
	version wire.Version
	result  ProtocolResult
	kind    kind
	small   bool // the small candidate list was needed, so later stages use it too
}

var probedVersions = []wire.Version{
	wire.VersionSSL20, wire.VersionSSL30, wire.VersionTLS10, wire.VersionTLS11, wire.VersionTLS12, wire.VersionTLS13,
}

func (p *prober) detectProtocols(ctx context.Context) []protoProbe {
	out := make([]protoProbe, len(probedVersions))
	var wg sync.WaitGroup
	for i, v := range probedVersions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer p.catch()
			out[i] = p.probeVersion(ctx, v)
		}()
	}
	wg.Wait()
	return out
}

func (p *prober) probeVersion(ctx context.Context, v wire.Version) protoProbe {
	res := protoProbe{version: v, result: ProtocolResult{Version: v.String(), Code: uint16(v)}}
	if v == wire.VersionSSL20 {
		return p.probeSSLv2(ctx, res)
	}

	try := func(small bool) outcome {
		var (
			h   *wire.ClientHello
			err error
		)
		switch {
		case v == wire.VersionTLS13 && small:
			h, err = p.tls13Hello(commonTLS13, commonGroups)
		case v == wire.VersionTLS13:
			h, err = p.tls13Hello(tls13IDs, allGroupIDs)
		case small:
			h, err = p.legacyHello(v, commonSuites, commonGroups)
		default:
			h, err = p.legacyHello(v, legacyIDs, ecGroupIDs)
		}
		if err != nil {
			return outcome{kind: kindError, err: err}
		}
		return p.exchange(ctx, h)
	}

	supported := func(o outcome) bool {
		sh := o.serverHello()
		return sh != nil && sh.SelectedVersion == v && (v == wire.VersionTLS13 || sh.Version == v)
	}

	o := try(false)
	// A refusal of the big offer is not yet a refusal of the version: some servers
	// choke on very large hellos. Retry with a short, conventional list.
	if !supported(o) && (o.kind == kindAlert || o.kind == kindClosed || o.kind == kindGarbage) {
		if o2 := try(true); supported(o2) || o2.kind == kindServerHello {
			o, res.small = o2, true
		}
	}
	res.kind = o.kind
	res.result.Supported = supported(o)
	res.result.Evidence = o.evidence()
	res.result.Detail = o.detail()
	if sh := o.serverHello(); sh != nil && !res.result.Supported {
		res.result.Detail = "server chose " + sh.SelectedVersion.String()
	}
	return res
}

func (p *prober) probeSSLv2(ctx context.Context, res protoProbe) protoProbe {
	raw, err := wire.MarshalSSLv2ClientHello(p.random(), wire.SSLv2CipherKinds())
	if err != nil {
		res.result.Evidence, res.result.Detail, res.kind = EvidenceInconclusive, err.Error(), kindError
		return res
	}
	conn, release, err := p.connect(ctx)
	if err != nil {
		res.kind = classifyNetErr(err)
		res.result.Evidence, res.result.Detail = EvidenceInconclusive, err.Error()
		return res
	}
	defer release()
	defer conn.Close() //nolint:errcheck // probe connection

	if _, err := conn.Write(raw); err != nil {
		res.kind = classifyNetErr(err)
		res.result.Evidence, res.result.Detail = EvidenceInconclusive, err.Error()
		return res
	}
	sh, err := wire.ReadSSLv2ServerHello(conn)
	var v2err *wire.SSLv2Error
	switch {
	case err == nil:
		names := make([]string, len(sh.CipherKinds))
		for i, k := range sh.CipherKinds {
			names[i] = wire.SSLv2CipherName(k)
		}
		res.kind, res.result.Supported, res.result.Evidence = kindServerHello, true, EvidenceServerHello
		res.result.Detail = "ciphers: " + strings.Join(names, ", ")
	case errors.As(err, &v2err):
		// The server speaks SSLv2 (it answered in SSLv2) but refused our offer.
		res.kind, res.result.Supported, res.result.Evidence = kindServerHello, true, EvidenceServerHello
		res.result.Detail = err.Error()
	case errors.Is(err, wire.ErrNotSSLv2):
		res.kind, res.result.Evidence, res.result.Detail = kindClosed, EvidenceClosed, "not an SSLv2 server"
	default:
		k := classifyNetErr(err)
		res.kind, res.result.Evidence, res.result.Detail = k, outcome{kind: k}.evidence(), err.Error()
	}
	return res
}

// reachability decides whether the endpoint can be scanned at all, from what the
// version probes saw.
func reachability(protos []protoProbe) error {
	var anyAnswer, notTLS, inconclusive int
	var detail string
	for _, pr := range protos {
		if pr.version == wire.VersionSSL20 && !pr.result.Supported {
			continue // SSLv2 has its own framing; a non-SSLv2 reply says nothing about the port
		}
		switch pr.kind {
		case kindServerHello, kindAlert, kindClosed, kindGarbage:
			anyAnswer++
		case kindNotTLS:
			notTLS++
		default:
			inconclusive++
			detail = pr.result.Detail
		}
	}
	switch {
	case anyAnswer > 0:
		return nil
	case notTLS > 0:
		return errors.New("the port answered, but not with TLS (is this a plain-text service, or does it need STARTTLS?)")
	default:
		return fmt.Errorf("no response from target: %s", detail)
	}
}

// ---- stage 2: cipher-suite enumeration --------------------------------------------------

type legacyEnum struct {
	suites []uint16 // in the order the server picked them
	pref   string   // "server" | "client" | "unknown"
	first  *wire.ServerHello
	small  bool
	// chains are the distinct certificate chains the server sent in these
	// plaintext flights (DER, leaf first), with the suite that drew each.
	chains []rawChain
}

// rawChain is a certificate chain read from a raw TLS 1.2-and-earlier flight.
type rawChain struct {
	suite uint16
	ders  [][]byte
}

// maxRawChains bounds how many distinct chains one version's enumeration keeps.
const maxRawChains = 4

func (p *prober) legacyGroups(small bool) []uint16 {
	if small {
		return commonGroups
	}
	return ecGroupIDs
}

// enumerateLegacy finds every suite the server accepts at version v by
// offering the remaining candidates, noting the server's pick, removing it, and
// asking again until the server has nothing left to pick.
func (p *prober) enumerateLegacy(ctx context.Context, v wire.Version, small bool) *legacyEnum {
	e := &legacyEnum{small: small, pref: "unknown"}
	remaining := append([]uint16(nil), legacyIDs...)
	if small {
		remaining = append([]uint16(nil), commonSuites...)
	}
	groups := p.legacyGroups(small)

	for len(remaining) > 0 && ctx.Err() == nil {
		h, err := p.legacyHello(v, remaining, groups)
		if err != nil {
			p.note("%s: %v", v, err)
			break
		}
		o := p.exchange(ctx, h)
		sh := o.serverHello()
		if sh == nil {
			if !o.conclusive() {
				p.inconclusive("%s: suite enumeration stopped early (%s)", v, o.detail())
			}
			break
		}
		if sh.Version != v || !contains(remaining, sh.Suite) {
			p.note("%s: server answered outside the offer (version %s, suite 0x%04X); enumeration stopped", v, sh.Version, sh.Suite)
			break
		}
		if e.first == nil {
			e.first = sh
		}
		e.keepChain(sh.Suite, o.flight.Certificates)
		e.suites = append(e.suites, sh.Suite)
		remaining = without(remaining, sh.Suite)
	}

	e.pref = p.preference(e.suites, func(offer []uint16) (uint16, bool) {
		h, err := p.legacyHello(v, offer, groups)
		if err != nil {
			return 0, false
		}
		sh := p.exchange(ctx, h).serverHello()
		if sh == nil {
			return 0, false
		}
		return sh.Suite, true
	})
	return e
}

// keepChain records a chain the first time its leaf is seen.
func (e *legacyEnum) keepChain(suite uint16, ders [][]byte) {
	if len(ders) == 0 || len(e.chains) >= maxRawChains {
		return
	}
	for _, c := range e.chains {
		if string(c.ders[0]) == string(ders[0]) {
			return
		}
	}
	e.chains = append(e.chains, rawChain{suite: suite, ders: ders})
}

// preference asks who decides between accepted items. For adjacent pairs
// (items[i], items[i+1]) it offers them in REVERSE order: a server with its own
// preference still returns items[i]; one that follows the client returns
// items[i+1]. Several pairs are tried because some servers are neither (Go's own
// server, for instance, follows the client for ChaCha20-versus-AES). Agreement
// gives "server" or "client"; disagreement gives "mixed".
func (p *prober) preference(items []uint16, pick func(offer []uint16) (uint16, bool)) string {
	var server, client int
	for i := 0; i+1 < len(items) && i < 3; i++ {
		got, ok := pick([]uint16{items[i+1], items[i]})
		switch {
		case !ok:
		case got == items[i]:
			server++
		case got == items[i+1]:
			client++
		}
	}
	switch {
	case server > 0 && client > 0:
		return "mixed"
	case server > 0:
		return "server"
	case client > 0:
		return "client"
	}
	return "unknown"
}

type tls13Enum struct {
	suites, groups       []uint16
	suitePref, groupPref string
}

// enumerateTLS13 finds the TLS 1.3 suites and key-exchange groups. Both come from
// HelloRetryRequests, which name the server's choice: one suite/group at a time,
// removing each pick until the server refuses.
func (p *prober) enumerateTLS13(ctx context.Context, small bool) *tls13Enum {
	e := &tls13Enum{suitePref: "unknown", groupPref: "unknown"}
	suiteList, groupList := tls13IDs, allGroupIDs
	if small {
		suiteList, groupList = commonTLS13, commonGroups
	}

	// Suites, offering every group so the group never limits the choice.
	remaining := append([]uint16(nil), suiteList...)
	for len(remaining) > 0 && ctx.Err() == nil {
		h, err := p.tls13Hello(remaining, groupList)
		if err != nil {
			break
		}
		sh := p.exchange(ctx, h).serverHello()
		if sh == nil || !sh.HelloRetryRequest && sh.SelectedVersion != wire.VersionTLS13 || !contains(remaining, sh.Suite) {
			break
		}
		e.suites = append(e.suites, sh.Suite)
		remaining = without(remaining, sh.Suite)
	}
	e.suitePref = p.preference(e.suites, func(offer []uint16) (uint16, bool) {
		h, err := p.tls13Hello(offer, groupList)
		if err != nil {
			return 0, false
		}
		sh := p.exchange(ctx, h).serverHello()
		if sh == nil {
			return 0, false
		}
		return sh.Suite, true
	})

	// Groups, offering the full suite list.
	gremaining := append([]uint16(nil), groupList...)
	for len(gremaining) > 0 && ctx.Err() == nil {
		h, err := p.tls13Hello(suiteList, gremaining)
		if err != nil {
			break
		}
		sh := p.exchange(ctx, h).serverHello()
		if sh == nil || !sh.HasKeyShare || !contains(gremaining, sh.KeyShareGroup) {
			break
		}
		e.groups = append(e.groups, sh.KeyShareGroup)
		gremaining = without(gremaining, sh.KeyShareGroup)
	}
	e.groupPref = p.preference(e.groups, func(offer []uint16) (uint16, bool) {
		h, err := p.tls13Hello(suiteList, offer)
		if err != nil {
			return 0, false
		}
		sh := p.exchange(ctx, h).serverHello()
		if sh == nil || !sh.HasKeyShare {
			return 0, false
		}
		return sh.KeyShareGroup, true
	})
	return e
}

// ---- stage 3: ECDHE curves and DH parameters --------------------------------------------

// enumerateCurves lists the curves a TLS 1.2-and-earlier server uses with an ECDHE
// suite, by offering one suite and the remaining curves until the server has none.
func (p *prober) enumerateCurves(ctx context.Context, v wire.Version, suite uint16, small bool) ([]uint16, string) {
	remaining := append([]uint16(nil), p.legacyGroups(small)...)
	var found []uint16
	pick := func(groups []uint16) (uint16, bool) {
		h, err := p.legacyHello(v, []uint16{suite}, groups)
		if err != nil {
			return 0, false
		}
		f := p.exchange(ctx, h)
		if f.serverHello() == nil || f.flight == nil || f.flight.ServerKeyExchange == nil {
			return 0, false
		}
		ke, err := wire.ParseServerKeyExchange("ECDHE", false, f.flight.ServerKeyExchange)
		if err != nil || ke.ExplicitCurve || !contains(groups, ke.CurveID) {
			return 0, false
		}
		return ke.CurveID, true
	}
	for len(remaining) > 0 && ctx.Err() == nil {
		id, ok := pick(remaining)
		if !ok {
			break
		}
		found = append(found, id)
		remaining = without(remaining, id)
	}
	pref := p.preference(found, func(offer []uint16) (uint16, bool) { return pick(offer) })
	return found, pref
}

// sampleDH reads one DHE ServerKeyExchange for the prime's size and identity.
func (p *prober) sampleDH(ctx context.Context, v wire.Version, s registry.Suite, small bool) *DHResult {
	h, err := p.legacyHello(v, []uint16{s.ID}, p.legacyGroups(small))
	if err != nil {
		return nil
	}
	o := p.exchange(ctx, h)
	if o.serverHello() == nil || o.flight.ServerKeyExchange == nil {
		return nil
	}
	ke, err := wire.ParseServerKeyExchange("DHE", strings.Contains(s.Name, "_PSK_"), o.flight.ServerKeyExchange)
	if err != nil {
		p.note("DHE parameters unreadable: %v", err)
		return nil
	}
	sum := sha256.Sum256(ke.Prime)
	r := &DHResult{PrimeBits: ke.PrimeBits, GeneratorBits: ke.GeneratorBits, PrimeSHA256: hex.EncodeToString(sum[:]), Suite: s.Name}
	r.IsPrime, r.SafePrime = primality(ke.Prime)
	return r
}

// maxPrimalityBits bounds the moduli tested for primality (a few milliseconds at 8192 bits).
const maxPrimalityBits = 8192

// primality says whether p is prime and, if so, whether it is a safe prime. ProbablyPrime(20) is
// Miller-Rabin with 20 random bases plus Baillie-PSW, which has no known counterexample.
func primality(b []byte) (isPrime, safe *bool) {
	p := new(big.Int).SetBytes(b)
	if p.BitLen() < 2 || p.BitLen() > maxPrimalityBits {
		return nil, nil
	}
	ip := p.ProbablyPrime(20)
	if !ip {
		return &ip, nil
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	sp := q.ProbablyPrime(20)
	return &ip, &sp
}

// ---- stage 4: features ---------------------------------------------------------------------

func (p *prober) features(ctx context.Context, protos []protoProbe, legacy map[wire.Version]*legacyEnum, highest wire.Version) Features {
	var f Features
	b := func(v bool) *bool { return &v }

	if e := legacy[highest]; e != nil && e.first != nil {
		sh := e.first
		f.SecureRenegotiation = b(sh.HasExt(wire.ExtRenegotiationInfo))
		f.ExtendedMasterSecret = b(sh.HasExt(wire.ExtExtendedMasterSecret))
		f.SessionTickets = b(sh.HasExt(wire.ExtSessionTicket))
		f.EncryptThenMAC = b(sh.HasExt(wire.ExtEncryptThenMAC))
		f.OCSPStapling = b(sh.HasExt(wire.ExtStatusRequest))
		f.Heartbeat = b(sh.HasExt(wire.ExtHeartbeat))

		// Compression: offer DEFLATE first and see whether the server takes it.
		if len(e.suites) > 0 {
			if h, err := p.legacyHello(highest, e.suites[:1], p.legacyGroups(e.small)); err == nil {
				h.Compression = []byte{1, 0}
				if sh := p.exchange(ctx, h).serverHello(); sh != nil {
					f.Compression = b(sh.Compression != 0)
				}
			}
		}
	}

	// TLS_FALLBACK_SCSV: offer a lower version the server supports, with the SCSV.
	// A server that supports something higher must refuse with inappropriate_fallback.
	var supported []wire.Version
	for _, pr := range protos {
		if pr.result.Supported && pr.version >= wire.VersionSSL30 && pr.version <= wire.VersionTLS12 {
			supported = append(supported, pr.version)
		}
	}
	sort.Slice(supported, func(i, j int) bool { return supported[i] < supported[j] })
	if len(supported) >= 2 {
		lower := supported[len(supported)-2]
		if e := legacy[lower]; e != nil && len(e.suites) > 0 && lower != wire.VersionSSL30 {
			if h, err := p.legacyHello(lower, append([]uint16{scsvFallback}, e.suites[:1]...), p.legacyGroups(e.small)); err == nil {
				o := p.exchange(ctx, h)
				switch {
				case o.alert() != nil && o.alert().Description == 86:
					f.FallbackSCSV = b(true)
				case o.serverHello() != nil:
					f.FallbackSCSV = b(false)
				}
			}
		}
	}
	return f
}

// ---- assembling results ------------------------------------------------------------------

func pickSuite(ids []uint16, want func(registry.Suite) bool) (registry.Suite, bool) {
	for _, id := range ids {
		if s, ok := registry.SuiteByID(id); ok && want(s) {
			return s, true
		}
	}
	return registry.Suite{}, false
}

func suiteResults(v wire.Version, ids []uint16, pref string) []SuiteResult {
	out := make([]SuiteResult, 0, len(ids))
	for i, id := range ids {
		s, ok := registry.SuiteByID(id)
		r := SuiteResult{Version: v.String(), ID: id, Name: registry.SuiteName(id)}
		if ok {
			r.IANARecommended = string(rune(s.Recommended))
			r.Kx, r.Auth, r.Cipher, r.KeyBits, r.Mode, r.BlockBits, r.MAC = s.Kx, s.Auth, s.Cipher, s.KeyBits, s.Mode, s.BlockBits, s.MAC
			r.AEAD, r.Export, r.Anon, r.Ephemeral = s.AEAD, s.Export, s.Anon, s.Ephemeral
		}
		if pref == "server" {
			r.Rank = i + 1
		}
		out = append(out, r)
	}
	return out
}

func groupResults(v wire.Version, ids []uint16, pref string) []GroupResult {
	out := make([]GroupResult, 0, len(ids))
	for i, id := range ids {
		g, ok := registry.GroupByID(id)
		r := GroupResult{Version: v.String(), ID: id, Name: registry.GroupName(id)}
		if ok {
			r.IANARecommended = string(rune(g.Recommended))
			r.PQ, r.Hybrid, r.Obsolete = g.PQ, g.Hybrid, g.Obsolete
		}
		if pref == "server" {
			r.Rank = i + 1
		}
		out = append(out, r)
	}
	return out
}

// versionOrder sorts newest first, with SSLv2 last.
func versionOrder(s string) int {
	switch s {
	case "TLSv1.3":
		return 0
	case "TLSv1.2":
		return 1
	case "TLSv1.1":
		return 2
	case "TLSv1.0":
		return 3
	case "SSLv3":
		return 4
	}
	return 5
}

func sortReport(r *Report) {
	sort.SliceStable(r.Protocols, func(i, j int) bool {
		return versionOrder(r.Protocols[i].Version) < versionOrder(r.Protocols[j].Version)
	})
	sort.SliceStable(r.Suites, func(i, j int) bool {
		a, b := r.Suites[i], r.Suites[j]
		if versionOrder(a.Version) != versionOrder(b.Version) {
			return versionOrder(a.Version) < versionOrder(b.Version)
		}
		if a.Rank != b.Rank && a.Rank != 0 && b.Rank != 0 {
			return a.Rank < b.Rank
		}
		return a.ID < b.ID
	})
	sort.SliceStable(r.Groups, func(i, j int) bool {
		a, b := r.Groups[i], r.Groups[j]
		if versionOrder(a.Version) != versionOrder(b.Version) {
			return versionOrder(a.Version) < versionOrder(b.Version)
		}
		if a.Rank != b.Rank && a.Rank != 0 && b.Rank != 0 {
			return a.Rank < b.Rank
		}
		return a.ID < b.ID
	})
}
