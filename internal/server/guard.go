// Package server is the product's HTTP surface: the JSON API, the embedded UI,
// the scan runner and the scheduler.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// Guard decides which addresses a scan may connect to. A scanner that dials
// user-supplied targets is an SSRF vector, so the rule is enforced where it cannot
// be bypassed: on the actual remote address of every connection, in the dialer's
// Control hook (after DNS, before connect), which also defeats DNS rebinding.
//
// Refused always: unspecified, multicast, broadcast and link-local addresses
// (which includes the 169.254.169.254 cloud-metadata endpoint), plus a few
// well-known metadata addresses outside those ranges. Loopback is refused unless
// AllowLoopback is set. Private (RFC 1918) ranges are allowed: scanning internal
// systems is the point of a self-hosted tool.
type Guard struct {
	AllowLoopback bool
	// Scope, when set, limits scans further to the operator's --scan-allow list.
	Scope *Scope

	pinNets bool // set by ForTarget: every address must be inside Scope's networks
}

// ErrBlocked is wrapped by every refusal.
var ErrBlocked = errors.New("target address is not allowed")

var extraBlocked = []net.IP{
	net.ParseIP("fd00:ec2::254"),   // AWS IPv6 instance metadata
	net.ParseIP("100.100.100.200"), // Alibaba Cloud metadata
	net.ParseIP("192.0.0.192"),     // Oracle Cloud metadata
	net.ParseIP("255.255.255.255"), // limited broadcast
	net.ParseIP("168.63.129.16"),   // Azure wire server
	net.ParseIP("fd00:ec2::23"),    // AWS DNS resolver, IPv6
	net.ParseIP("169.254.169.253"), // AWS DNS resolver (also link-local)
}

var (
	// thisNetwork is 0.0.0.0/8: "this host on this network"; on some systems
	// an address in it reaches the local machine.
	thisNetwork = mustCIDR("0.0.0.0/8")
	// nat64 is the well-known NAT64 prefix; the last four bytes are an IPv4
	// address that a translator would connect to.
	nat64 = mustCIDR("64:ff9b::/96")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err) // a constant
	}
	return n
}

// CheckIP returns nil if a scan may connect to ip.
func (g Guard) CheckIP(ip net.IP) error {
	// A NAT64 address is only a way of writing an IPv4 one: apply the IPv4 rules.
	if ip != nil && ip.To4() == nil && nat64.Contains(ip) {
		if err := g.CheckIP(ip.To16()[12:16]); err != nil {
			return fmt.Errorf("%w (reached through the NAT64 address %s)", err, ip)
		}
	}
	switch {
	case ip == nil:
		return fmt.Errorf("%w: not an IP address", ErrBlocked)
	case ip.IsUnspecified() || thisNetwork.Contains(ip):
		return fmt.Errorf("%w: %s is the unspecified address", ErrBlocked, ip)
	case ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast():
		return fmt.Errorf("%w: %s is a multicast address", ErrBlocked, ip)
	case ip.IsLinkLocalUnicast():
		return fmt.Errorf("%w: %s is link-local (this range includes cloud metadata services)", ErrBlocked, ip)
	case ip.IsLoopback() && !g.AllowLoopback:
		return fmt.Errorf("%w: %s is a loopback address (start the server with --allow-loopback to scan this machine)", ErrBlocked, ip)
	}
	for _, b := range extraBlocked {
		if b != nil && b.Equal(ip) {
			return fmt.Errorf("%w: %s is a known cloud-metadata address", ErrBlocked, ip)
		}
	}
	if g.pinNets && !g.Scope.ipIn(ip) && (ip.To4() != nil || !nat64.Contains(ip) || !g.Scope.ipIn(ip.To16()[12:16])) {
		return g.Scope.outside(ip)
	}
	return nil
}

// CheckLiteral checks a host that is an IP literal; names are checked when
// they are resolved and again when connected to.
func (g Guard) CheckLiteral(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		return g.CheckIP(ip)
	}
	return nil
}

// Control is a net.Dialer Control hook that refuses blocked remote addresses at
// connect time.
func (g Guard) Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	return g.CheckIP(net.ParseIP(host))
}

// Dial is a dial function that enforces the guard on the real connection.
func (g Guard) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Control: g.Control}
	return d.DialContext(ctx, network, addr)
}

// LookupIP resolves a name and refuses it if any address it resolves to is
// blocked, so a name pointing at an internal service fails with a clear reason
// before any connection is attempted.
func (g Guard) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if err := g.CheckIP(a.IP); err != nil {
			return nil, fmt.Errorf("%s resolves to a blocked address: %w", host, err)
		}
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// Scope limits what may be scanned beyond the Guard's fixed rules (PRD-007 REQ-AC-1): the
// operator's --scan-allow list of networks (a CIDR or a single address) and domains (a name and
// every name under it). An empty scope allows everything the Guard allows.
//
// A target is in scope when its name is under one of the domains, or when every address it
// connects to is inside one of the networks. The networks are enforced where the Guard is, on
// the real remote address of every connection, so a name that is changed to point elsewhere
// after it was added is refused when the scan connects.
type Scope struct {
	nets    []*net.IPNet
	domains []string // lower case, no leading or trailing dot
	entries []string // as given, for messages
}

// ParseScope reads --scan-allow entries: "10.0.0.0/8", "192.0.2.7", "example.com" or
// ".example.com" (the two domain forms mean the same).
func ParseScope(entries []string) (*Scope, error) {
	sc := &Scope{}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		switch {
		case e == "":
			continue
		case strings.Contains(e, "/"):
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return nil, fmt.Errorf("scan scope %q: not a CIDR network", raw)
			}
			sc.nets = append(sc.nets, n)
		case net.ParseIP(e) != nil:
			ip := net.ParseIP(e)
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			sc.nets = append(sc.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		default:
			d := strings.ToLower(strings.Trim(e, "."))
			if !validDomain(d) {
				return nil, fmt.Errorf("scan scope %q: not a network, an address or a domain", raw)
			}
			sc.domains = append(sc.domains, d)
		}
		sc.entries = append(sc.entries, e)
	}
	return sc, nil
}

func validDomain(d string) bool {
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

// Empty reports whether the scope allows everything the Guard allows.
func (sc *Scope) Empty() bool { return sc == nil || len(sc.entries) == 0 }

// Entries are the scope as the operator wrote it.
func (sc *Scope) Entries() []string {
	if sc == nil {
		return nil
	}
	return append([]string(nil), sc.entries...)
}

// nameIn reports whether host is one of the domains or under one.
func (sc *Scope) nameIn(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range sc.domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func (sc *Scope) ipIn(ip net.IP) bool {
	for _, n := range sc.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (sc *Scope) outside(ip net.IP) error {
	return fmt.Errorf("%w: %s is outside the scan scope (%s)", ErrBlocked, ip, strings.Join(sc.entries, ", "))
}

// ForTarget is the Guard for one scan of host: when a scope is set and host is not under one of
// its domains, every address the scan connects to must also be inside one of its networks.
func (g Guard) ForTarget(host string) Guard {
	if g.Scope.Empty() || (net.ParseIP(host) == nil && g.Scope.nameIn(host)) {
		g.pinNets = false
		return g
	}
	g.pinNets = true
	return g
}

// CheckTarget decides whether an endpoint may be added (REQ-AC-1, add-time). An address must be
// allowed by the Guard and, with a scope, be inside it. A name must be under a scope domain or,
// failing that, resolve only to addresses inside the scope's networks; it is checked again on
// every connection.
func (g Guard) CheckTarget(ctx context.Context, host string) error {
	if err := g.CheckLiteral(host); err != nil {
		return err
	}
	if g.Scope.Empty() {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if !g.Scope.ipIn(ip) {
			return g.Scope.outside(ip)
		}
		return nil
	}
	if g.Scope.nameIn(host) {
		return nil
	}
	if len(g.Scope.nets) == 0 {
		return fmt.Errorf("%w: %s is outside the scan scope (%s)", ErrBlocked, host, strings.Join(g.Scope.entries, ", "))
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := g.ForTarget(host).LookupIP(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return fmt.Errorf("%w: %s could not be resolved to check it against the scan scope (%s)", ErrBlocked, host, strings.Join(g.Scope.entries, ", "))
		}
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: %s has no address", ErrBlocked, host)
	}
	return nil
}
