package server

import (
	"errors"
	"net"
	"testing"
)

func TestPublicGuardRefusesWhatIsNotPublic(t *testing.T) {
	g := Guard{Public: true, AllowLoopback: true} // AllowLoopback does not loosen the public profile
	for _, s := range []string{
		"127.0.0.1", "127.8.9.10", "::1",
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.0.1",
		"100.64.0.1", "100.127.255.255",
		"169.254.0.1", "169.254.169.254", "fe80::1",
		"224.0.0.1", "239.255.255.255", "ff02::1", "ff0e::1",
		"255.255.255.255", "0.0.0.0", "0.255.255.255", "::",
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "3fff::1",
		"198.18.0.1", "198.19.255.255", "2001:2::1",
		"192.0.0.1", "192.0.0.192",
		"240.0.0.1", "254.255.255.255",
		"fc00::1", "fdff:ffff::1", "fec0::1", "100::1",
		"100.100.100.200", "168.63.129.16", "fd00:ec2::254", "fd00:ec2::23", "169.254.169.253",
		// IPv6 forms that carry an IPv4 address, judged by that address.
		"::ffff:127.0.0.1", "::ffff:192.168.1.1",
		"64:ff9b::7f00:1", "64:ff9b::c0a8:101", "64:ff9b:1::a00:1",
		"2002:7f00:1::", "2002:a9fe:a9fe::1", "2002:c0a8:101::1",
		"2001:0:a00:1::f7f7:f7f7",   // Teredo, private server
		"2001:0:808:808::f5ff:fffe", // Teredo, client 10.0.0.1
		"::10.0.0.1", "::169.254.169.254",
	} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("%q is not an address", s)
		}
		if err := g.CheckIP(ip); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want a refusal", s, err)
		}
	}
	if err := g.CheckIP(nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("nil: err = %v", err)
	}
}

func TestPublicGuardAllowsPublicAddresses(t *testing.T) {
	g := Guard{Public: true}
	for _, s := range []string{
		"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1",
		"192.0.1.1", "192.0.3.1", "198.17.255.255", "198.20.0.1",
		"2606:4700:4700::1111", "2a00:1450:4001::1",
		"::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
		"2001:0:808:808::f7f7:f7f7", // Teredo: server 8.8.8.8, client 8.8.8.8
	} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("%q is not an address", s)
		}
		if err := g.CheckIP(ip); err != nil {
			t.Errorf("%s: refused: %v", s, err)
		}
	}
}

// The public profile changes nothing for the server's guard, which scans private networks.
func TestDefaultGuardStillAllowsPrivateRanges(t *testing.T) {
	g := Guard{}
	for _, s := range []string{"10.0.0.1", "192.168.1.1", "100.64.0.1", "fd12::1", "192.0.2.1", "2002:a00:1::1"} {
		if err := g.CheckIP(net.ParseIP(s)); err != nil {
			t.Errorf("%s: refused without the public profile: %v", s, err)
		}
	}
	if err := (Guard{AllowLoopback: true}).CheckIP(net.ParseIP("127.0.0.1")); err != nil {
		t.Errorf("loopback with AllowLoopback: %v", err)
	}
}

func TestPublicGuardRefusalStartsWithTheFixedText(t *testing.T) {
	err := Guard{Public: true}.CheckIP(net.ParseIP("64:ff9b::a00:1"))
	if err == nil || len(err.Error()) < len(ErrBlocked.Error()) || err.Error()[:len(ErrBlocked.Error())] != ErrBlocked.Error() {
		t.Errorf("refusal %q must start with %q: callers match on it", err, ErrBlocked)
	}
}
