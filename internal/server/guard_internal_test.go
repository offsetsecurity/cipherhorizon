package server

import (
	"context"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/revocation"
)

// The CRL fetcher keeps its own copy of the cloud-metadata addresses (it must not import the
// server). Even with private and loopback addresses allowed it must refuse every address the
// scan guard refuses as metadata.
func TestCRLPolicyRefusesEveryMetadataAddress(t *testing.T) {
	loose := revocation.Policy{AllowPrivate: true, AllowLoopback: true}
	for _, ip := range extraBlocked {
		if err := loose.CheckIP(ip); err == nil {
			t.Errorf("the CRL policy allows %s, which the scan guard blocks", ip)
		}
	}
}

// An IPv6 address with a zone is an address, whatever text the zone carries: it is never a name
// under a scope domain, the add-time check judges it by its address, and every connection of its
// scan stays inside the scope's networks.
func TestScopeJudgesAZonedAddressByItsAddress(t *testing.T) {
	sc, err := ParseScope([]string{"example.com", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	g := Guard{Scope: sc}
	for _, host := range []string{
		"::ffff:192.0.2.1%x.example.com",
		"[::ffff:192.0.2.1%x.example.com]",
		"2001:db8::1%eth0.example.com",
	} {
		if sc.nameIn(host) {
			t.Errorf("%q counts as a name under example.com", host)
		}
		if !g.ForTarget(host).pinNets {
			t.Errorf("ForTarget(%q) does not hold connections to the scope's networks", host)
		}
		if err := g.CheckTarget(context.Background(), host); err == nil {
			t.Errorf("CheckTarget(%q) allowed an address outside the scope", host)
		}
	}
	// A zoned address inside a scope network is allowed, by its address.
	if err := g.CheckTarget(context.Background(), "::ffff:10.1.2.3%x.example.com"); err != nil {
		t.Errorf("an address inside the scope was refused: %v", err)
	}
	// The fixed rules apply to the address too.
	if err := (Guard{}).CheckTarget(context.Background(), "::ffff:169.254.169.254%x"); err == nil {
		t.Error("a zoned metadata address was allowed")
	}
	// Real names under the domain still are.
	for _, host := range []string{"example.com", "www.example.com", "WWW.Example.COM."} {
		if !sc.nameIn(host) || g.ForTarget(host).pinNets {
			t.Errorf("%q is not treated as a name under example.com", host)
		}
	}
	for _, host := range []string{"bad host.example.com", "x\r\n.example.com", "a:b.example.com"} {
		if sc.nameIn(host) {
			t.Errorf("%q counts as a name under example.com", host)
		}
	}
	// Looking for names under a string that is not a domain is not inside a domain-only scope.
	domainOnly, err := ParseScope([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (Guard{Scope: domainOnly}).CheckDomain("::ffff:192.0.2.1%x.example.com"); err == nil {
		t.Error("CheckDomain allowed a zoned address under a domain-only scope")
	}
}
