package sshprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// D-16: the current client is OpenSSH 10.6's ssh_config(5) defaults, exactly. A change here is a
// methodology change: update docs/methodology.md with it.
func TestCurrentClientListsArePinned(t *testing.T) {
	kex, hk, ciphers, macs := CurrentClientLists()
	pins := map[string][]string{
		"kex":     {"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"},
		"ciphers": {"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"},
		"macs":    {"umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"},
	}
	for name, got := range map[string][]string{"kex": kex, "ciphers": ciphers, "macs": macs} {
		if !slices.Equal(got, pins[name]) {
			t.Errorf("%s: %v", name, got)
		}
	}
	if hk[0] != "ssh-ed25519-cert-v01@openssh.com" || hk[len(hk)-1] != "ssh-mldsa44-ed25519" || len(hk) != 20 {
		t.Errorf("host key algorithms: %v", hk)
	}
	// Every name the client sends is in the registry.
	for kind, l := range map[string][]string{registry.KindKex: kex, registry.KindHostKey: hk, registry.KindCipher: ciphers, registry.KindMAC: macs} {
		for _, n := range l {
			if _, ok := registry.Lookup(kind, n); !ok {
				t.Errorf("%s %s is not in the registry", kind, n)
			}
		}
	}
}

// The MODP primes are the published ones: their SHA-256 is in the reference data generated from
// RFC 2409 and RFC 3526.
func TestMODPGroupsAreThePublishedOnes(t *testing.T) {
	for name, hexp := range map[string]string{"Oakley Group 2 (1024-bit MODP)": oakleyGroup2, "MODP group 14 (2048-bit)": oakleyGroup14, "MODP group 16 (4096-bit)": oakleyGroup16} {
		p, ok := new(big.Int).SetString(hexp, 16)
		if !ok {
			t.Fatalf("%s does not parse", name)
		}
		sum := sha256.Sum256(p.Bytes())
		got, ok := refdata.LookupDHPrime(hex.EncodeToString(sum[:]))
		if !ok || got.Name != name {
			t.Errorf("%s: reference data says %+v (found %v)", name, got, ok)
		}
	}
}

// Negotiation follows RFC 4253 section 7.1: the client's order decides.
func TestNegotiationFollowsTheClientsOrder(t *testing.T) {
	srv := &Algorithms{Kex: []string{"curve25519-sha256", "sntrup761x25519-sha512", "mlkem768x25519-sha256"}, HostKey: []string{"rsa-sha2-256", "ssh-ed25519"},
		CipherC2S: []string{"aes256-ctr", "aes128-gcm@openssh.com"}, CipherS2C: []string{"aes256-ctr", "aes128-gcm@openssh.com"},
		MACC2S: []string{"hmac-sha2-512", "hmac-sha1"}, MACS2C: []string{"hmac-sha2-512", "hmac-sha1"}, CompressionC2S: []string{"none"}, CompressionS2C: []string{"none"}}
	n := negotiate(srv, clientKex, clientHostKey, clientCiphers, clientMACs, clientCompression)
	if n.Kex != "mlkem768x25519-sha256" || n.HostKey != "ssh-ed25519" || n.Cipher != "aes128-gcm@openssh.com" || n.MAC != "" {
		t.Errorf("%+v", n)
	}
	srv.CipherC2S, srv.CipherS2C = []string{"aes256-ctr"}, []string{"aes256-ctr"}
	if n := negotiate(srv, clientKex, clientHostKey, clientCiphers, clientMACs, clientCompression); n.MAC != "hmac-sha2-512" {
		t.Errorf("a CTR cipher needs a MAC: %+v", n)
	}
	srv.HostKey = []string{"ssh-dss"}
	if n := negotiate(srv, clientKex, clientHostKey, clientCiphers, clientMACs, clientCompression); n.Kex != "" {
		t.Errorf("no common host key algorithm, yet kex %q", n.Kex)
	}
}

// Every registry entry names its source.
func TestEverySSHAlgorithmHasASource(t *testing.T) {
	for _, a := range registry.All() {
		if a.Source == "" || a.Display == "" || a.Kind == "" {
			t.Errorf("%+v", a)
		}
		if a.FIPS && !a.PQ {
			t.Errorf("%s is FIPS post-quantum but not post-quantum", a.Name)
		}
		if strings.HasSuffix(a.Name, "-etm@openssh.com") && !a.ETM {
			t.Errorf("%s is not marked encrypt-then-MAC", a.Name)
		}
	}
}
