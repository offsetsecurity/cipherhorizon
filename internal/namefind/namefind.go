// Package namefind finds the host names under a domain (PRD-022, internal).
//
// No single source knows every name, so a run combines several and keeps, for each name, which
// source reported it. Then every name is resolved and a short list of ports is tried, so the
// caller can show what is really there before anything is added or scanned.
//
// The package decides nothing about what may be reached: the caller passes the address check and
// the dial function (the server's Guard), and every connection goes through them.
package namefind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source ids, in the order they are reported.
const (
	SourceDomain   = "domain"   // the domain itself
	SourceStored   = "stored"   // names in certificates already in the store
	SourceDNS      = "dns"      // the domain's own DNS records
	SourceCT       = "ct"       // Certificate Transparency search (sends the domain to a third party)
	SourceWordlist = "wordlist" // guessing common labels
	SourceList     = "list"     // a list the operator supplied
)

// AllSources lists every source a caller may ask for, in report order.
var AllSources = []string{SourceStored, SourceDNS, SourceCT, SourceWordlist, SourceList}

// Limits of one run.
const (
	DefaultMaxNames = 50000
	DefaultQPS      = 50
	defaultWorkers  = 24
	dialTimeout     = 3 * time.Second
)

// WebPorts are tried on every name that resolves; MailPort only on names an MX record gave.
var (
	WebPorts = []int{443, 8443, 22}
	MailPort = 25
)

// Resolver is the part of net.Resolver a run uses; tests supply their own.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// Options configures a run.
type Options struct {
	// Domain is the registered or delegated domain to look under, such as "example.com".
	Domain string
	// Sources are the source ids to use. The domain itself is always included.
	Sources []string
	// Stored are names from certificates the caller already holds (SourceStored).
	Stored []string
	// List are names the operator supplied (SourceList).
	List []string
	// CT searches Certificate Transparency (SourceCT). Nil means the source is unavailable.
	CT CTSearcher

	Resolver Resolver
	// CheckIP says whether host may be connected to at ip; an error is the reason it may not.
	CheckIP func(host string, ip net.IP) error
	// Dial opens a TCP connection to address:port. It is only called with an address CheckIP
	// allowed for the name being checked.
	Dial func(ctx context.Context, address string, port int) (net.Conn, error)

	// MaxNames stops collecting (default 50,000). QPS limits DNS queries per second (default 50).
	MaxNames int
	QPS      int
	// SkipPorts leaves out the port checks (names and addresses only).
	SkipPorts bool
	// Progress, when set, is told the stage and how far it is. It is called from several goroutines.
	Progress func(stage string, done, total int)
}

// Name is one host name under the domain and what the run learned about it.
type Name struct {
	Name string `json:"name"`
	// Sources are the ids of the sources that reported the name.
	Sources []string `json:"sources"`
	// Addresses are what the name resolves to; empty when it does not resolve.
	Addresses []string `json:"addresses"`
	// CNAME is the canonical name when the name is an alias.
	CNAME string `json:"cname,omitempty"`
	// External says the canonical name is outside the domain: the service is hosted elsewhere.
	External bool `json:"external"`
	// Ports are the ports that accepted a connection.
	Ports []int `json:"ports"`
	// Refused is why the name may not be connected to (the scan scope or a blocked address).
	Refused string `json:"refused,omitempty"`
	// Mail says an MX record names this host.
	Mail bool `json:"mail,omitempty"`
	// Wildcard says the name resolves only to what the zone answers for any name under the
	// domain. It may be a real site on that server or no site at all: DNS cannot tell them apart,
	// and a port that answers there answers for every name.
	Wildcard bool `json:"wildcard,omitempty"`
}

// SourceReport says what became of one source.
type SourceReport struct {
	ID string `json:"id"`
	// Status is "ran", "off" (not asked for or not available) or "failed".
	Status string `json:"status"`
	// Found is how many names under the domain the source reported.
	Found int `json:"found"`
	// Detail is the reason for "off" or "failed", or a note about what ran.
	Detail string `json:"detail,omitempty"`
}

// Result is the outcome of a run.
type Result struct {
	Domain  string         `json:"domain"`
	Names   []Name         `json:"names"`
	Sources []SourceReport `json:"sources"`
	// Wildcard says the zone answers for any name under the domain, with WildcardAddresses. Names
	// that resolve only there are marked; guessed names that only matched it were dropped.
	Wildcard          bool     `json:"wildcard"`
	WildcardAddresses []string `json:"wildcardAddresses"`
	// WildcardCerts are wildcard names seen in certificates: names behind them cannot be listed.
	WildcardCerts []string `json:"wildcardCerts"`
	// Truncated says collecting stopped at MaxNames.
	Truncated bool `json:"truncated"`
	// Outside counts supplied names that were not under the domain and were left out.
	Outside int `json:"outside"`
}

// NormalizeDomain lower-cases a domain and checks its shape. It accepts "example.com",
// "Example.COM." and "*.example.com"; it refuses addresses, single labels and anything with a
// scheme, a port or a path.
func NormalizeDomain(in string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimPrefix(d, "*.")
	d = strings.Trim(d, ".")
	if d == "" {
		return "", errors.New("enter a domain, such as example.com")
	}
	if strings.ContainsAny(d, "/:@ \t") {
		return "", errors.New("enter the domain alone, without a scheme, port or path")
	}
	if net.ParseIP(d) != nil {
		return "", errors.New("an address has no names under it; enter a domain")
	}
	if !strings.Contains(d, ".") {
		return "", errors.New("enter a full domain, such as example.com")
	}
	if !validName(d) {
		return "", fmt.Errorf("%q is not a domain name", in)
	}
	return d, nil
}

func validName(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// under reports whether name is the domain or below it, and returns it cleaned.
func under(name, domain string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.Trim(n, ".")
	if !validName(n) {
		return "", false
	}
	return n, n == domain || strings.HasSuffix(n, "."+domain)
}

// collector gathers names with their sources.
type collector struct {
	mu     sync.Mutex
	domain string
	max    int
	names  map[string]*Name
	full   bool
}

// add records name as reported by source. It returns false when the name is not under the domain.
func (c *collector) add(name, source string) bool {
	n, ok := under(name, c.domain)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.names[n]
	if e == nil {
		if len(c.names) >= c.max {
			c.full = true
			return true
		}
		e = &Name{Name: n, Sources: []string{}, Addresses: []string{}, Ports: []int{}}
		c.names[n] = e
	}
	for _, s := range e.Sources {
		if s == source {
			return true
		}
	}
	e.Sources = append(e.Sources, source)
	return true
}

func (c *collector) markMail(name string) {
	n, ok := under(name, c.domain)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.names[n]; e != nil {
		e.Mail = true
	}
}

// Run finds the names under o.Domain. It returns an error only for a request that cannot be
// honoured; a source that fails is reported in the result and the run goes on.
func Run(ctx context.Context, o Options) (*Result, error) {
	domain, err := NormalizeDomain(o.Domain)
	if err != nil {
		return nil, err
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.MaxNames <= 0 {
		o.MaxNames = DefaultMaxNames
	}
	if o.QPS <= 0 {
		o.QPS = DefaultQPS
	}
	if o.Progress == nil {
		o.Progress = func(string, int, int) {}
	}
	want := map[string]bool{}
	for _, s := range o.Sources {
		want[s] = true
	}
	lim := newLimiter(ctx, o.QPS)
	defer lim.stop()
	r := &run{o: o, domain: domain, lim: lim}
	c := &collector{domain: domain, max: o.MaxNames, names: map[string]*Name{}}
	res := &Result{Domain: domain, WildcardCerts: []string{}, WildcardAddresses: []string{}}
	c.add(domain, SourceDomain)

	report := func(id, status string, found int, detail string) {
		res.Sources = append(res.Sources, SourceReport{ID: id, Status: status, Found: found, Detail: detail})
	}
	wild := map[string]bool{}
	addAll := func(names []string, source string) (found int) {
		for _, n := range names {
			n = strings.TrimSpace(n)
			if strings.HasPrefix(n, "*.") {
				if w, ok := under(n[2:], domain); ok {
					wild["*."+w] = true
					n = w
				}
			}
			if c.add(n, source) {
				found++
			} else if n != "" && source == SourceList {
				res.Outside++
			}
		}
		return found
	}

	// 1. Names in certificates already held.
	o.Progress("collecting names", 0, 0)
	if want[SourceStored] {
		report(SourceStored, "ran", addAll(o.Stored, SourceStored), "")
	} else {
		report(SourceStored, "off", 0, "not asked for")
	}

	// 2. The domain's own records.
	if want[SourceDNS] {
		names, mail, derr := r.walkDNS(ctx)
		found := addAll(names, SourceDNS)
		for _, m := range mail {
			c.markMail(m)
		}
		switch {
		case derr != nil && found == 0:
			report(SourceDNS, "failed", 0, derr.Error())
		default:
			report(SourceDNS, "ran", found, "")
		}
	} else {
		report(SourceDNS, "off", 0, "not asked for")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 3. Certificate Transparency.
	switch {
	case !want[SourceCT]:
		report(SourceCT, "off", 0, "not asked for")
	case o.CT == nil:
		report(SourceCT, "off", 0, "not turned on for this server")
	default:
		o.Progress("searching certificate logs", 0, 0)
		names, cerr := o.CT.Search(ctx, domain)
		if cerr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			report(SourceCT, "failed", 0, o.CT.Name()+" did not answer: "+cerr.Error())
		} else {
			report(SourceCT, "ran", addAll(names, SourceCT), "asked "+o.CT.Name())
		}
	}

	// 4. A supplied list.
	if want[SourceList] {
		report(SourceList, "ran", addAll(o.List, SourceList), "")
	} else {
		report(SourceList, "off", 0, "not asked for")
	}

	// A zone that answers for any name makes every name under it look alive: a name from a
	// certificate issued years ago, or a guess. What it answers for names that cannot exist is
	// found first, for every run (three queries), so such names can be told apart.
	wildAddrs := r.wildcardAddresses(ctx)
	res.Wildcard = len(wildAddrs) > 0
	for a := range wildAddrs {
		res.WildcardAddresses = append(res.WildcardAddresses, a)
	}
	sort.Strings(res.WildcardAddresses)

	// 5. Guessing. A guess that only matched the wildcard is dropped below.
	if want[SourceWordlist] {
		for _, l := range Labels() {
			c.add(l+"."+domain, SourceWordlist)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Resolve everything; aliases that point at another name under the domain add that name.
	r.resolveAll(ctx, c, wildAddrs)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if want[SourceWordlist] {
		// A guess that does not resolve, or only matched the wildcard, was never a name.
		found := 0
		for n, e := range c.names {
			if len(e.Sources) != 1 || e.Sources[0] != SourceWordlist {
				if hasSource(e, SourceWordlist) {
					found++
				}
				continue
			}
			if len(e.Addresses) == 0 || allIn(e.Addresses, wildAddrs) {
				delete(c.names, n)
				continue
			}
			found++
		}
		detail := fmt.Sprintf("%d common labels tried", len(Labels()))
		if res.Wildcard {
			detail += "; the zone answers for any name, so guesses that only matched that answer were dropped"
		}
		report(SourceWordlist, "ran", found, detail)
	} else {
		report(SourceWordlist, "off", 0, "not asked for")
	}

	if !o.SkipPorts {
		r.checkPorts(ctx, c)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// Any other name that resolves only to the wildcard answer is kept and marked. The domain
	// itself is never covered by its own wildcard, so it is not marked.
	if res.Wildcard {
		for n, e := range c.names {
			if n != domain && len(e.Addresses) > 0 && allIn(e.Addresses, wildAddrs) {
				e.Wildcard = true
			}
		}
	}

	res.Truncated = c.full
	for w := range wild {
		res.WildcardCerts = append(res.WildcardCerts, w)
	}
	sort.Strings(res.WildcardCerts)
	res.Names = make([]Name, 0, len(c.names))
	for _, e := range c.names {
		sort.Strings(e.Sources)
		res.Names = append(res.Names, *e)
	}
	sort.Slice(res.Names, func(i, j int) bool { return res.Names[i].Name < res.Names[j].Name })
	sort.SliceStable(res.Sources, func(i, j int) bool { return sourceOrder(res.Sources[i].ID) < sourceOrder(res.Sources[j].ID) })
	return res, nil
}

func sourceOrder(id string) int {
	for i, s := range AllSources {
		if s == id {
			return i
		}
	}
	return len(AllSources)
}

func hasSource(n *Name, s string) bool {
	for _, x := range n.Sources {
		if x == s {
			return true
		}
	}
	return false
}

func allIn(addrs []string, set map[string]bool) bool {
	if len(set) == 0 {
		return false
	}
	for _, a := range addrs {
		if !set[a] {
			return false
		}
	}
	return true
}

// limiter spaces DNS queries: one token every 1/qps seconds.
type limiter struct {
	tokens chan struct{}
	done   chan struct{}
}

func newLimiter(ctx context.Context, qps int) *limiter {
	l := &limiter{tokens: make(chan struct{}, qps), done: make(chan struct{})}
	go func() {
		t := time.NewTicker(time.Second / time.Duration(qps))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-l.done:
				return
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			}
		}
	}()
	return l
}

func (l *limiter) wait(ctx context.Context) bool {
	select {
	case <-l.tokens:
		return true
	case <-ctx.Done():
		return false
	}
}

func (l *limiter) stop() { close(l.done) }
