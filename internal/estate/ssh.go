package estate

import (
	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// Method names for SSH observations (PRD-008 REQ-SHO-5).
const (
	MethodSSHKexInit  = "ssh.kexinit@1"   // the server's own algorithm lists
	MethodSSHKexReply = "ssh.kex-reply@1" // a key exchange carried out to the server's reply
)

// FromSSHReport projects one SSH scan report into observations: the protocol, every advertised
// algorithm the catalogue knows as offered, the negotiated choices as negotiated, and the host
// key algorithms the server presented. Like a TLS report, every fact was read from the server's
// own reply (E3), and anything not read produces nothing.
func FromSSHReport(rep *sshprobe.Report) []Observation {
	if rep == nil || rep.Algorithms == nil {
		return nil
	}
	var out []Observation
	obs := func(e Entity, rel, method string, attrs map[string]string) {
		out = append(out, Observation{Entity: e, Relation: rel, Rung: evidence.RungExercised, Class: evidence.E3Exercised,
			Method: method, Quality: QualityAuthoritative, Attrs: dropEmpty(attrs)})
	}
	obs(Entity{Kind: KindProtocol, Key: ProtocolKey("SSH-2.0"), Name: "SSH-2.0", Attrs: map[string]string{"version": "SSH-2.0"}}, RelOffers, MethodSSHKexInit, nil)

	algorithm := func(kind, name string) (Entity, bool) {
		r, ok := registry.Lookup(kind, name)
		if !ok || r.Catalogue == "" {
			return Entity{}, false
		}
		return Entity{Kind: KindAlgorithm, Key: evidence.AlgorithmKey(r.Catalogue), Name: clean(r.Catalogue, MaxNameLen)}, true
	}
	a := rep.Algorithms
	// In a fixed order, so a projection is deterministic.
	for _, l := range []struct {
		kind  string
		names []string
	}{{registry.KindKex, a.Kex}, {registry.KindHostKey, a.HostKey},
		{registry.KindCipher, append(append([]string(nil), a.CipherC2S...), a.CipherS2C...)},
		{registry.KindMAC, append(append([]string(nil), a.MACC2S...), a.MACS2C...)}} {
		kind, names := l.kind, l.names
		seen := map[string]bool{}
		for _, n := range names {
			if e, ok := algorithm(kind, n); ok && !seen[n] {
				seen[n] = true
				obs(e, RelOffers, MethodSSHKexInit, map[string]string{"origin": clean("ssh "+kind+" "+n, 120)})
			}
		}
	}
	if n := rep.Negotiated; n != nil && n.Completed {
		for _, c := range [][2]string{{registry.KindKex, n.Kex}, {registry.KindCipher, n.Cipher}, {registry.KindMAC, n.MAC}} {
			kind, name := c[0], c[1]
			if e, ok := algorithm(kind, name); ok {
				obs(e, RelNegotiates, MethodSSHKexReply, map[string]string{"origin": clean("ssh "+kind+" "+name, 120)})
			}
		}
	}
	for _, k := range rep.HostKeys {
		if e, ok := algorithm(registry.KindHostKey, k.Type); ok {
			obs(e, RelPresents, MethodSSHKexReply, map[string]string{"origin": clean("ssh host key "+k.Type+" "+k.Fingerprint, 160)})
		}
	}
	return out
}
