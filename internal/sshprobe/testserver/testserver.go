// Package testserver runs SSH servers on loopback for testing the SSH prober and for the demo
// targets: real servers from golang.org/x/crypto/ssh (an implementation independent of the
// prober's, so a misreading of the RFC cannot pass because both ends share it), and a scripted
// server for what no library will do (SSH-1 banners, preambles, hostile names, lists without
// strict key exchange, key exchanges no library implements).
//
// Test and demo support only: the release binary must not import it (internal/archtest).
package testserver

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Key kinds a server may hold.
const (
	KeyEd25519 = "ed25519"
	KeyECDSA   = "ecdsa-p256"
	KeyRSA     = "rsa-3072"
	KeyRSA1024 = "rsa-1024"
	KeyMLDSA65 = "mldsa65"
)

// Config configures an x/crypto server. Empty lists mean x/crypto's defaults.
type Config struct {
	KeyExchanges []string
	Ciphers      []string
	MACs         []string
	// Keys are the host keys, by kind; default Ed25519.
	Keys []string
	// HostKeyAlgorithms restricts the RSA key's signature algorithms (for example to ssh-rsa only).
	RSAAlgorithms []string
	// Certificate signs the first host key with a CA and serves the certificate instead.
	Certificate bool
	Addr        string
}

// Server is a running server.
type Server struct {
	Host  string
	Port  int
	Addr  string
	close func()
	// Fingerprints are the SHA-256 fingerprints of the served host keys, in the order given.
	Fingerprints []string
}

// Close stops the server.
func (s *Server) Close() {
	if s.close != nil {
		s.close()
	}
}

var (
	keyMu sync.Mutex
	keys  = map[string]ssh.Signer{}
)

// signer returns a host key of the kind, generated once per process.
func signer(kind string) (ssh.Signer, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if s, ok := keys[kind]; ok {
		return s, nil
	}
	var priv any
	var err error
	switch kind {
	case KeyEd25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case KeyECDSA:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyRSA:
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	case KeyRSA1024:
		priv, err = rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a deliberately weak test key
	case KeyMLDSA65:
		priv, err = mldsa.GenerateKey(mldsa.MLDSA65())
	default:
		return nil, errors.New("testserver: unknown key kind " + kind)
	}
	if err != nil {
		return nil, err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	keys[kind] = s
	return s, nil
}

// Start runs an x/crypto server until the test ends.
func Start(t testing.TB, cfg Config) *Server {
	t.Helper()
	s, err := Listen(cfg)
	if err != nil {
		t.Fatalf("ssh testserver: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// Listen runs an x/crypto server; the caller closes it.
func Listen(cfg Config) (*Server, error) {
	sc := &ssh.ServerConfig{NoClientAuth: true}
	sc.KeyExchanges, sc.Ciphers, sc.MACs = cfg.KeyExchanges, cfg.Ciphers, cfg.MACs
	kinds := cfg.Keys
	if len(kinds) == 0 {
		kinds = []string{KeyEd25519}
	}
	var fps []string
	for i, k := range kinds {
		s, err := signer(k)
		if err != nil {
			return nil, err
		}
		if (k == KeyRSA || k == KeyRSA1024) && len(cfg.RSAAlgorithms) > 0 {
			ms, err := ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), cfg.RSAAlgorithms)
			if err != nil {
				return nil, err
			}
			s = ms
		}
		if i == 0 && cfg.Certificate {
			cs, err := certify(s)
			if err != nil {
				return nil, err
			}
			s = cs
		}
		sc.AddHostKey(s)
		fps = append(fps, ssh.FingerprintSHA256(s.PublicKey()))
	}
	srv, err := listen(cfg.Addr, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		conn, chans, reqs, err := ssh.NewServerConn(c, sc)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "test server")
		}
		_ = conn.Close()
	})
	if err != nil {
		return nil, err
	}
	srv.Fingerprints = fps
	return srv, nil
}

// certify signs the key with a fresh CA as a host certificate valid for a day.
func certify(s ssh.Signer) (ssh.Signer, error) {
	ca, err := signer(KeyECDSA)
	if err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{Key: s.PublicKey(), Serial: 42, CertType: ssh.HostCert, KeyId: "test host",
		ValidPrincipals: []string{"localhost", "127.0.0.1"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(24 * time.Hour).Unix())} //nolint:gosec // positive times
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert, s)
}

func listen(addr string, handle func(net.Conn)) (*Server, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // test server
				handle(c)
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return &Server{Host: host, Port: port, Addr: l.Addr().String(), close: func() { _ = l.Close() }}, nil
}

// Script is a server that sends a banner (and optional preamble lines) and, for SSH-2, a KEXINIT
// built from the given lists, then reads until the client goes away. It never runs a key exchange.
type Script struct {
	Preamble   []string
	Ident      string // default "SSH-2.0-OpenSSH_9.6"
	Kex        []string
	HostKey    []string
	Ciphers    []string
	MACs       []string
	Comp       []string
	NoKexInit  bool // an SSH-1 server, or one that stops after the banner
	RawReplace []byte
}

// StartScript runs a Script server until the test ends.
func StartScript(t testing.TB, sc Script) *Server {
	t.Helper()
	s, err := ListenScript("", sc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// ListenScript runs a Script server; the caller closes it.
func ListenScript(addr string, sc Script) (*Server, error) {
	return listen(addr, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if sc.RawReplace != nil {
			_, _ = c.Write(sc.RawReplace)
			_, _ = io.Copy(io.Discard, c)
			return
		}
		for _, l := range sc.Preamble {
			_, _ = io.WriteString(c, l+"\r\n")
		}
		id := sc.Ident
		if id == "" {
			id = "SSH-2.0-OpenSSH_9.6"
		}
		_, _ = io.WriteString(c, id+"\r\n")
		if !sc.NoKexInit {
			_, _ = c.Write(packet(kexInit(sc)))
		}
		_, _ = io.Copy(io.Discard, c)
	})
}

func nameList(b []byte, names []string) []byte {
	s := ""
	for i, n := range names {
		if i > 0 {
			s += ","
		}
		s += n
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // test lists
	return append(b, s...)
}

func kexInit(sc Script) []byte {
	or := func(l []string, d ...string) []string {
		if l == nil {
			return d
		}
		return l
	}
	b := []byte{20}
	b = append(b, make([]byte, 16)...)
	for _, l := range [][]string{or(sc.Kex, "curve25519-sha256"), or(sc.HostKey, "ssh-ed25519"), or(sc.Ciphers, "aes128-ctr"), or(sc.Ciphers, "aes128-ctr"),
		or(sc.MACs, "hmac-sha2-256"), or(sc.MACs, "hmac-sha2-256"), or(sc.Comp, "none"), or(sc.Comp, "none"), {}, {}} {
		b = nameList(b, l)
	}
	return append(b, 0, 0, 0, 0, 0)
}

func packet(payload []byte) []byte {
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad)) //nolint:gosec // test packets
	out = append(out, byte(pad))
	out = append(out, payload...)
	return append(out, make([]byte, pad)...)
}

// Composite host keys (ssh-mldsa44-ed25519, draft-miller-sshm-composite-sigs) are served by a
// scripted server that also runs curve25519-sha256 and signs the exchange hash with both halves.
// No library implements the format yet, so this checks the prober against the draft's text, not
// against an independent implementation (QA-PLAN-006 records the limit).
type compositeKey struct {
	ml  *mldsa.PrivateKey
	ed  ed25519.PrivateKey
	pub []byte // the composite public key blob
}

// NewCompositeKey makes an ssh-mldsa44-ed25519 key.
func NewCompositeKey() (*compositeKey, error) {
	ml, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, err
	}
	edPub, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mlPub := ml.Public().(*mldsa.PublicKey).Bytes()
	blob := sshString(nil, []byte("ssh-mldsa44-ed25519"))
	blob = sshString(blob, append(append([]byte(nil), mlPub...), edPub...))
	return &compositeKey{ml: ml, ed: ed, pub: blob}, nil
}

// Fingerprint is OpenSSH's SHA-256 fingerprint of the key.
func (k *compositeKey) Fingerprint() string {
	return ssh.FingerprintSHA256(rawKey(k.pub))
}

func (k *compositeKey) sign(m []byte) ([]byte, error) {
	const label = "COMPSIG-MLDSA44-Ed25519-SHA512"
	d := sha512.Sum512(m)
	mp := append(append(append([]byte("CompositeAlgorithmSignatures2025"), label...), 0), d[:]...)
	mlSig, err := k.ml.Sign(rand.Reader, mp, &mldsa.Options{Context: label})
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 0, len(mlSig)+ed25519.SignatureSize)
	sig = append(append(sig, mlSig...), ed25519.Sign(k.ed, mp)...)
	out := sshString(nil, []byte("ssh-mldsa44-ed25519"))
	return sshString(out, sig), nil
}

func sshString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // test values
	return append(b, s...)
}

// rawKey lets ssh.FingerprintSHA256 hash a blob x/crypto does not parse.
type rawKey []byte

// Type names the key type.
func (r rawKey) Type() string { return "ssh-mldsa44-ed25519" }

// Marshal is the blob itself.
func (r rawKey) Marshal() []byte { return r }

// Verify is not supported: the key is only fingerprinted.
func (r rawKey) Verify([]byte, *ssh.Signature) error { return errors.New("not supported") }

// ListenComposite runs a server whose only host key is an ssh-mldsa44-ed25519 composite and whose
// only key exchange is curve25519-sha256.
func ListenComposite(addr string, k *compositeKey) (*Server, error) {
	return listen(addr, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		const vs = "SSH-2.0-OpenSSH_10.6"
		_, _ = io.WriteString(c, vs+"\r\n")
		is := kexInit(Script{Kex: []string{"curve25519-sha256", "kex-strict-s-v00@openssh.com"},
			HostKey: []string{"ssh-mldsa44-ed25519"}, Ciphers: []string{"aes256-gcm@openssh.com"}, MACs: []string{"hmac-sha2-256-etm@openssh.com"}})
		_, _ = c.Write(packet(is))
		rd := bufio.NewReader(c)
		vc, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		ic, err := readPacket(rd)
		if err != nil {
			return
		}
		init, err := readPacket(rd)
		if err != nil || len(init) < 5 || init[0] != 30 {
			return
		}
		qc := init[5:]
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		pub, err := ecdh.X25519().NewPublicKey(qc)
		if err != nil {
			return
		}
		shared, err := priv.ECDH(pub)
		if err != nil {
			return
		}
		qs := priv.PublicKey().Bytes()
		var h []byte
		for _, s := range [][]byte{[]byte(trimCRLF(vc)), []byte(vs), ic, is, k.pub, qc, qs} {
			h = sshString(h, s)
		}
		kb := new(big.Int).SetBytes(shared).Bytes()
		if len(kb) > 0 && kb[0]&0x80 != 0 {
			kb = append([]byte{0}, kb...)
		}
		h = sshString(h, kb)
		sum := sha256.Sum256(h)
		sig, err := k.sign(sum[:])
		if err != nil {
			return
		}
		reply := []byte{31}
		reply = sshString(reply, k.pub)
		reply = sshString(reply, qs)
		reply = sshString(reply, sig)
		_, _ = c.Write(packet(reply))
		_, _ = io.Copy(io.Discard, c)
	})
}

func trimCRLF(s string) string { return strings.TrimRight(s, "\r\n") }

func readPacket(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 5 || n > 35000 {
		return nil, errors.New("bad packet")
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body[:int(n)-1-int(hdr[4])], nil
}
