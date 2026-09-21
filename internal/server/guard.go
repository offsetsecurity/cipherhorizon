// Package server is the product's HTTP surface: the JSON API, the embedded UI,
// the scan runner and the scheduler.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
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

// CheckIP returns nil if a scan may connect to ip.
func (g Guard) CheckIP(ip net.IP) error {
	switch {
	case ip == nil:
		return fmt.Errorf("%w: not an IP address", ErrBlocked)
	case ip.IsUnspecified():
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
