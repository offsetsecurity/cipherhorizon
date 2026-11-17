package namefind

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type run struct {
	o      Options
	domain string
	lim    *limiter
}

// srvServices are the service records worth asking for: each names hosts that speak TLS or SSH.
var srvServices = [][2]string{
	{"autodiscover", "tcp"}, {"caldavs", "tcp"}, {"carddavs", "tcp"}, {"imaps", "tcp"}, {"imap", "tcp"},
	{"pop3s", "tcp"}, {"submission", "tcp"}, {"submissions", "tcp"}, {"sip", "tls"}, {"sips", "tcp"},
	{"sipfederationtls", "tcp"}, {"xmpp-client", "tcp"}, {"xmpp-server", "tcp"}, {"xmpps-client", "tcp"},
	{"ldap", "tcp"}, {"ldaps", "tcp"}, {"kerberos", "tcp"}, {"matrix", "tcp"}, {"https", "tcp"}, {"ssh", "tcp"},
}

func notFound(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d) && d.IsNotFound
}

// walkDNS reads the records of the domain that name hosts: name servers, mail servers, the SPF
// include chain and service records. It returns the names, and which of them are mail servers.
// Names outside the domain are returned too; the collector leaves them out.
func (r *run) walkDNS(ctx context.Context) (names, mail []string, err error) {
	res := r.o.Resolver
	keep := func(e error) {
		if e != nil && !notFound(e) && err == nil && ctx.Err() == nil {
			err = e
		}
	}
	if r.lim.wait(ctx) {
		ns, e := res.LookupNS(ctx, r.domain)
		keep(e)
		for _, n := range ns {
			names = append(names, n.Host)
		}
	}
	if r.lim.wait(ctx) {
		mx, e := res.LookupMX(ctx, r.domain)
		keep(e)
		for _, m := range mx {
			names = append(names, m.Host)
			mail = append(mail, m.Host)
		}
	}
	// SPF: a:, mx: and include: name hosts or further policies. Only policies under the domain
	// are followed; a supplier's policy lists the supplier's hosts, not this domain's.
	seen := map[string]bool{}
	queue := []string{r.domain}
	for depth := 0; len(queue) > 0 && depth < 4; depth++ {
		var next []string
		for _, q := range queue {
			if seen[q] || !r.lim.wait(ctx) {
				continue
			}
			seen[q] = true
			txts, e := res.LookupTXT(ctx, q)
			keep(e)
			for _, t := range txts {
				hosts, includes := parseSPF(t)
				names = append(names, hosts...)
				for _, inc := range includes {
					if n, ok := under(inc, r.domain); ok {
						names = append(names, n)
						next = append(next, n)
					}
				}
			}
		}
		queue = next
	}
	for _, s := range srvServices {
		if !r.lim.wait(ctx) {
			break
		}
		_, srvs, e := res.LookupSRV(ctx, s[0], s[1], r.domain)
		keep(e)
		for _, v := range srvs {
			if v.Target != "." && v.Target != "" {
				names = append(names, v.Target)
			}
		}
	}
	return names, mail, err
}

// parseSPF returns the host names an SPF policy mentions (a:, mx:) and the policies it includes.
func parseSPF(txt string) (hosts, includes []string) {
	fields := strings.Fields(txt)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return nil, nil
	}
	for _, f := range fields[1:] {
		f = strings.TrimLeft(strings.ToLower(f), "+-~?")
		switch {
		case strings.HasPrefix(f, "include:"):
			includes = append(includes, f[len("include:"):])
		case strings.HasPrefix(f, "redirect="):
			includes = append(includes, f[len("redirect="):])
		case strings.HasPrefix(f, "a:"), strings.HasPrefix(f, "mx:"):
			h := f[strings.Index(f, ":")+1:]
			if i := strings.Index(h, "/"); i >= 0 { // a:host/24
				h = h[:i]
			}
			hosts = append(hosts, h)
		}
	}
	return hosts, includes
}

// wildcardAddresses asks for three names that cannot exist. What they resolve to is what the zone
// answers for any name; empty when the zone has no wildcard.
func (r *run) wildcardAddresses(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < 3; i++ {
		if !r.lim.wait(ctx) {
			break
		}
		var b [8]byte
		_, _ = rand.Read(b[:])
		addrs, err := r.o.Resolver.LookupIPAddr(ctx, "zz-"+hex.EncodeToString(b[:])+"."+r.domain)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			out[a.IP.String()] = true
		}
	}
	return out
}

// resolveAll resolves every collected name. An alias that points at another name under the domain
// adds that name, so it runs in rounds until nothing new appears.
func (r *run) resolveAll(ctx context.Context, c *collector, wildAddrs map[string]bool) {
	done := map[string]bool{}
	for round := 0; round < 5 && ctx.Err() == nil; round++ {
		c.mu.Lock()
		var todo []string
		for n := range c.names {
			if !done[n] {
				todo = append(todo, n)
				done[n] = true
			}
		}
		total := len(c.names)
		c.mu.Unlock()
		if len(todo) == 0 {
			return
		}
		sort.Strings(todo)
		var finished int
		var fmu sync.Mutex
		each(ctx, defaultWorkers, todo, func(name string) {
			r.resolveOne(ctx, c, name, wildAddrs)
			fmu.Lock()
			finished++
			n := finished
			fmu.Unlock()
			if n%25 == 0 || n == len(todo) {
				r.o.Progress("resolving names", total-len(todo)+n, total)
			}
		})
	}
}

func (r *run) resolveOne(ctx context.Context, c *collector, name string, wildAddrs map[string]bool) {
	if !r.lim.wait(ctx) {
		return
	}
	addrs, err := r.o.Resolver.LookupIPAddr(ctx, name)
	if err != nil || len(addrs) == 0 {
		return
	}
	ips := make([]string, 0, len(addrs))
	refused := ""
	for _, a := range addrs {
		ips = append(ips, a.IP.String())
		if r.o.CheckIP != nil && refused == "" {
			if e := r.o.CheckIP(name, a.IP); e != nil {
				refused = e.Error()
			}
		}
	}
	sort.Strings(ips)
	c.mu.Lock()
	e := c.names[name]
	guessOnly := e != nil && len(e.Sources) == 1 && e.Sources[0] == SourceWordlist
	if e != nil {
		e.Addresses, e.Refused = ips, refused
	}
	c.mu.Unlock()
	if e == nil || (guessOnly && allIn(ips, wildAddrs)) {
		return // a guess that only matched the wildcard is dropped later; no need to ask more
	}
	if name != r.domain && allIn(ips, wildAddrs) {
		// Only the wildcard's answer: its alias, if any, is the wildcard's too, the same for every
		// name. Not asking halves the queries on a domain where thousands of names match.
		return
	}
	if !r.lim.wait(ctx) {
		return
	}
	cn, err := r.o.Resolver.LookupCNAME(ctx, name)
	if err != nil {
		return
	}
	cn = strings.ToLower(strings.Trim(cn, "."))
	if cn == "" || cn == name {
		return
	}
	_, inside := under(cn, r.domain)
	if inside {
		c.add(cn, SourceDNS)
	}
	c.mu.Lock()
	e.CNAME, e.External = cn, !inside
	c.mu.Unlock()
}

// checkPorts tries the short port list on every name that resolved and may be reached. Names that
// share an address share the answer, so a thousand names on one load balancer cost one check.
func (r *run) checkPorts(ctx context.Context, c *collector) {
	if r.o.Dial == nil {
		return
	}
	c.mu.Lock()
	var todo []string
	for n, e := range c.names {
		if len(e.Addresses) > 0 && e.Refused == "" {
			todo = append(todo, n)
		}
	}
	c.mu.Unlock()
	sort.Strings(todo)
	type probe struct {
		once sync.Once
		open bool
	}
	var pmu sync.Mutex
	probes := map[string]*probe{}
	var finished int
	var fmu sync.Mutex
	each(ctx, 64, todo, func(name string) {
		c.mu.Lock()
		e := c.names[name]
		addr, mail := pickAddress(e.Addresses), e.Mail
		c.mu.Unlock()
		ports := append([]int(nil), WebPorts...)
		if mail {
			ports = append(ports, MailPort)
		}
		open := make([]bool, len(ports))
		var wg sync.WaitGroup
		for i, port := range ports {
			wg.Add(1)
			go func(i, port int) {
				defer wg.Done()
				key := net.JoinHostPort(addr, strconv.Itoa(port))
				pmu.Lock()
				p := probes[key]
				if p == nil {
					p = &probe{}
					probes[key] = p
				}
				pmu.Unlock()
				p.once.Do(func() {
					dctx, cancel := context.WithTimeout(ctx, dialTimeout)
					defer cancel()
					conn, err := r.o.Dial(dctx, addr, port)
					if err == nil {
						_ = conn.Close()
						p.open = true
					}
				})
				open[i] = p.open
			}(i, port)
		}
		wg.Wait()
		got := []int{}
		for i, ok := range open {
			if ok {
				got = append(got, ports[i])
			}
		}
		c.mu.Lock()
		e.Ports = got
		c.mu.Unlock()
		fmu.Lock()
		finished++
		n := finished
		fmu.Unlock()
		if n%25 == 0 || n == len(todo) {
			r.o.Progress("checking ports", n, len(todo))
		}
	})
}

// pickAddress prefers an IPv4 address: a server without IPv6 routing still reaches it.
func pickAddress(addrs []string) string {
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	return addrs[0]
}

// each runs fn over items with at most n at once, and stops handing out work when ctx ends.
func each(ctx context.Context, n int, items []string, fn func(string)) {
	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < n && i < len(items); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				fn(it)
			}
		}()
	}
loop:
	for _, it := range items {
		select {
		case ch <- it:
		case <-ctx.Done():
			break loop
		}
	}
	close(ch)
	wg.Wait()
}
