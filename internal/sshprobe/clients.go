package sshprobe

import "github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"

// CurrentClient names the client whose default lists the negotiation stage sends (PRD-008 PD-4).
const CurrentClient = "OpenSSH 10.6 defaults"

// The OpenSSH 10.6 client's default algorithm lists, in order, from ssh_config(5) (KexAlgorithms,
// HostKeyAlgorithms, Ciphers, MACs) as published for OpenSSH 10.6 (released 2026-10-06; 10.0 made
// mlkem768x25519-sha256 the default key exchange, 10.6 enabled ssh-mldsa44-ed25519 host keys).
// The client also appends ext-info-c and kex-strict-c-v00@openssh.com to its key exchange list.
// TestCurrentClientListsArePinned keeps this exact.
var (
	clientKex = []string{
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group18-sha512",
		"diffie-hellman-group14-sha256",
	}
	clientHostKey = []string{
		"ssh-ed25519-cert-v01@openssh.com",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
		"sk-ssh-ed25519-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
		"rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
		"ssh-mldsa44-ed25519-cert",
		"ssh-ed25519",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ecdsa-sha2-nistp256@openssh.com", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		"sk-ssh-ed25519@openssh.com",
		"rsa-sha2-512", "rsa-sha2-256",
		"ssh-mldsa44-ed25519",
	}
	clientCiphers = []string{
		"chacha20-poly1305@openssh.com",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
	}
	clientMACs = []string{
		"umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha1-etm@openssh.com",
		"umac-64@openssh.com", "umac-128@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
	}
	clientCompression = []string{"none", "zlib@openssh.com"}
	clientSignals     = []string{"ext-info-c", "kex-strict-c-v00@openssh.com"}
)

// CurrentClientLists returns copies of the pinned lists (for tests and the methodology page).
func CurrentClientLists() (kex, hostKey, ciphers, macs []string) {
	c := func(s []string) []string { return append([]string(nil), s...) }
	return c(clientKex), c(clientHostKey), c(clientCiphers), c(clientMACs)
}

// negotiate applies RFC 4253 section 7.1: for each list, the first algorithm in the client's list
// that the server also lists. A key exchange is chosen only if a host key algorithm is also
// common (every method here needs a signature-capable host key). With an AEAD cipher there is no
// separate MAC.
func negotiate(server *Algorithms, kex, hostKey, ciphers, macs, comp []string) Negotiated {
	n := Negotiated{Client: CurrentClient}
	first := func(client, srv []string) string {
		have := map[string]bool{}
		for _, s := range srv {
			have[s] = true
		}
		for _, c := range client {
			if have[c] {
				return c
			}
		}
		return ""
	}
	n.HostKey = first(hostKey, server.HostKey)
	if n.HostKey != "" {
		n.Kex = first(kex, server.Kex)
	}
	n.Cipher = first(ciphers, server.CipherS2C)
	if a, ok := registry.Lookup(registry.KindCipher, n.Cipher); !ok || !a.AEAD {
		n.MAC = first(macs, server.MACS2C)
	}
	n.Compression = first(comp, server.CompressionS2C)
	return n
}
