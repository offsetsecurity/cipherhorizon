package main

import (
	"fmt"
	"strings"

	sshtest "github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"golang.org/x/crypto/ssh"
)

// sshDemo are the SSH demo servers (PRD-008 REQ-SHN-1), at base+20 onwards, in this order.
var sshDemo = []struct{ name, expect string }{
	{"ssh-hybrid", "mlkem768x25519 + Ed25519/ECDSA keys          -> expect L3"},
	{"ssh-classical", "curve25519 only                             -> expect L1"},
	{"ssh-legacy", "SHA-1 kex, CBC, 3DES, HMAC-SHA1, RSA-1024 ssh-rsa -> expect many findings"},
	{"ssh-mldsa", "hybrid kex + an ML-DSA-65 host key         -> expect L4"},
	{"ssh-composite", "ssh-mldsa44-ed25519 host key, classical kex -> expect L1, PQ host key"},
	{"ssh-1", "an SSH-1.5 banner                           -> expect L0"},
	{"ssh-sntrup", "sntrup761 only (lists only, no key exchange) -> L3 computed, host keys not fetched"},
	{"ssh-hardened", "ssh-hybrid with encrypt-then-MAC MACs only  -> expect L3, meets the baseline"},
}

// modernMACs are what a current OpenSSH server offers: SHA-2, encrypt-then-MAC first.
var modernMACs = []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM, ssh.HMACSHA256, ssh.HMACSHA512}

// etmMACs are the MACs a hardened server keeps: encrypt-then-MAC only, as the baseline asks.
var etmMACs = []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM}

// startSSHDemo starts the SSH demo servers; addr gives base+offset.
func startSSHDemo(addr func(int) string) error {
	listen := func(off int, cfg sshtest.Config) error {
		cfg.Addr = addr(off)
		_, err := sshtest.Listen(cfg)
		return err
	}
	if err := listen(20, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
		MACs: modernMACs, Keys: []string{sshtest.KeyEd25519, sshtest.KeyECDSA}}); err != nil {
		return err
	}
	if err := listen(21, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeCurve25519}, MACs: modernMACs, Keys: []string{sshtest.KeyEd25519}}); err != nil {
		return err
	}
	if err := listen(22, sshtest.Config{
		KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1, ssh.InsecureKeyExchangeDH1SHA1, ssh.KeyExchangeCurve25519},
		Ciphers:      []string{ssh.InsecureCipherAES128CBC, ssh.InsecureCipherTripleDESCBC, ssh.CipherAES128CTR},
		MACs:         []string{ssh.HMACSHA1, ssh.InsecureHMACSHA196, ssh.HMACSHA256},
		Keys:         []string{sshtest.KeyRSA1024}, RSAAlgorithms: []string{ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256}}); err != nil {
		return err
	}
	if err := listen(23, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
		MACs: modernMACs, Keys: []string{sshtest.KeyEd25519, sshtest.KeyMLDSA65}}); err != nil {
		return err
	}
	ck, err := sshtest.NewCompositeKey()
	if err != nil {
		return err
	}
	if _, err := sshtest.ListenComposite(addr(24), ck); err != nil {
		return err
	}
	if _, err := sshtest.ListenScript(addr(25), sshtest.Script{Ident: "SSH-1.5-OldServer_1.2", NoKexInit: true}); err != nil {
		return err
	}
	if err := listen(27, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
		MACs: etmMACs, Keys: []string{sshtest.KeyEd25519, sshtest.KeyECDSA}}); err != nil {
		return err
	}
	_, err = sshtest.ListenScript(addr(26), sshtest.Script{Ident: "SSH-2.0-OpenSSH_9.6",
		Kex:     []string{"sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "kex-strict-s-v00@openssh.com"},
		HostKey: []string{"ssh-ed25519"}, Ciphers: []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"},
		MACs: []string{"hmac-sha2-256-etm@openssh.com"}})
	return err
}

func sshLines(addr func(int) string) string {
	var b strings.Builder
	for i, d := range sshDemo {
		fmt.Fprintf(&b, "  %s   %-14s %s\n", addr(20+i), d.name, d.expect)
	}
	return b.String()
}
