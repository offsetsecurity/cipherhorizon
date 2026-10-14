// Package wire reads and writes the parts of the SSH transport protocol (RFC 4253) a scanner
// needs before any key is derived: the identification line, the unencrypted binary packets,
// KEXINIT, the key-exchange init and reply messages, public-key and signature blobs and OpenSSH
// certificates. Everything the server sends is bounded and parsed defensively: a hostile server is
// the normal case, not the exception. It is pure (no network, no clock) and fuzzed.
package wire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unicode/utf8"
)

// Limits on what is read from a server.
const (
	// MaxIdentLine is RFC 4253 section 4.2's limit, CR LF included.
	MaxIdentLine = 255
	// MaxPreambleLines and MaxPreambleBytes bound the lines a server may send before its
	// identification (RFC 4253 section 4.2 allows such lines; nothing bounds them).
	MaxPreambleLines = 20
	MaxPreambleBytes = 8 << 10
	// MaxPacket is the packet_length every implementation must accept (RFC 4253 section 6.1);
	// nothing longer is read before encryption starts.
	MaxPacket = 35000
	// MaxNames caps a name-list; MaxName caps one name (RFC 4251 section 6 allows 64 characters).
	MaxNames = 128
	MaxName  = 64
)

// Message numbers (RFC 4250 section 4.1.2; 30/31 are shared by every key-exchange method).
const (
	MsgDisconnect = 1
	MsgIgnore     = 2
	MsgUnimpl     = 3
	MsgDebug      = 4
	MsgKexInit    = 20
	MsgNewKeys    = 21
	MsgKexInit30  = 30 // KEXDH_INIT, KEX_ECDH_INIT, KEX_HYBRID_INIT
	MsgKexReply31 = 31 // KEXDH_REPLY, KEX_ECDH_REPLY, KEX_HYBRID_REPLY
)

// ErrProtocol marks input that breaks the protocol (as opposed to an I/O error).
var ErrProtocol = errors.New("ssh protocol error")

func protoErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, args...))
}

// Identification is the server's identification line (RFC 4253 section 4.2):
// "SSH-protoversion-softwareversion SP comments".
type Identification struct {
	Raw          string // the line without CR LF, cleaned
	ProtoVersion string // "2.0", "1.99" (SSH-1 and SSH-2), "1.5" ...
	Software     string
	Comment      string
	Preamble     int // lines the server sent before it
}

// SSH2 reports whether the server speaks SSH-2 ("2.0", or "1.99" which means both).
func (id Identification) SSH2() bool { return id.ProtoVersion == "2.0" || id.ProtoVersion == "1.99" }

// Clean replaces control and non-printable characters and caps the length: what a server sends is
// never shown or stored raw.
func Clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0:
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ReadIdentification reads lines until one starts with "SSH-". It refuses more than
// MaxPreambleLines lines or MaxPreambleBytes bytes before it, and an identification line longer
// than MaxIdentLine.
func ReadIdentification(r *bufio.Reader) (Identification, []string, error) {
	var pre []string
	total := 0
	for {
		line, err := readLine(r, MaxPreambleBytes-total+1)
		if err != nil {
			return Identification{}, pre, err
		}
		total += len(line)
		if strings.HasPrefix(line, "SSH-") {
			if len(line) > MaxIdentLine {
				return Identification{}, pre, protoErr("identification line of %d bytes (the limit is %d)", len(line), MaxIdentLine)
			}
			id, perr := ParseIdentification(strings.TrimRight(line, "\r\n"))
			id.Preamble = len(pre)
			return id, pre, perr
		}
		pre = append(pre, Clean(strings.TrimRight(line, "\r\n"), 120))
		if len(pre) >= MaxPreambleLines || total >= MaxPreambleBytes {
			return Identification{}, pre, protoErr("no identification line after %d lines (%d bytes)", len(pre), total)
		}
	}
}

// readLine reads up to and including LF, at most max bytes.
func readLine(r *bufio.Reader, max int) (string, error) {
	var b []byte
	for len(b) < max {
		c, err := r.ReadByte()
		if err != nil {
			if len(b) > 0 && errors.Is(err, io.EOF) {
				return string(b), io.ErrUnexpectedEOF
			}
			return string(b), err
		}
		b = append(b, c)
		if c == '\n' {
			return string(b), nil
		}
	}
	return string(b), protoErr("a line longer than %d bytes", max)
}

// ParseIdentification splits an identification line.
func ParseIdentification(line string) (Identification, error) {
	id := Identification{Raw: Clean(line, MaxIdentLine)}
	rest, ok := strings.CutPrefix(line, "SSH-")
	if !ok {
		return id, protoErr("not an identification line")
	}
	proto, rest, ok := strings.Cut(rest, "-")
	if !ok || proto == "" {
		return id, protoErr("identification without a protocol version")
	}
	id.ProtoVersion = Clean(proto, 16)
	sw, comment, _ := strings.Cut(rest, " ")
	id.Software, id.Comment = Clean(sw, 128), Clean(comment, 128)
	return id, nil
}

// ---- binary packets ---------------------------------------------------------------------------

// ReadPacket reads one unencrypted binary packet (RFC 4253 section 6) and returns its payload.
func ReadPacket(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	pad := uint32(hdr[4])
	switch {
	case n > MaxPacket:
		return nil, protoErr("packet_length %d is over %d", n, MaxPacket)
	case n < 1+4 || pad < 4 || pad >= n:
		return nil, protoErr("packet_length %d with %d bytes of padding", n, pad)
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	payload := body[:n-1-pad]
	if len(payload) == 0 {
		return nil, protoErr("empty payload")
	}
	return payload, nil
}

// Packet frames a payload as an unencrypted binary packet with random padding to a multiple of 8.
func Packet(payload []byte, rnd io.Reader) ([]byte, error) {
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad)) //nolint:gosec // our own payloads are small
	out = append(out, byte(pad))
	out = append(out, payload...)
	p := make([]byte, pad)
	if _, err := io.ReadFull(rnd, p); err != nil {
		return nil, err
	}
	return append(out, p...), nil
}

// ---- encodings (RFC 4251 section 5) -------------------------------------------------------------

// Reader consumes SSH data types from a buffer. Every read is bounded by what is left; the first
// failure sticks, so a parser checks Err once at the end.
type Reader struct {
	b   []byte
	err error
}

// NewReader reads from b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Err is the first failure, or nil.
func (r *Reader) Err() error { return r.err }

// Rest is what has not been read.
func (r *Reader) Rest() []byte { return r.b }

func (r *Reader) fail(what string) {
	if r.err == nil {
		r.err = protoErr("truncated %s", what)
	}
	r.b = nil
}

// Byte reads one byte.
func (r *Reader) Byte() byte {
	if len(r.b) < 1 {
		r.fail("byte")
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

// Bool reads a boolean.
func (r *Reader) Bool() bool { return r.Byte() != 0 }

// Uint32 reads a uint32.
func (r *Reader) Uint32() uint32 {
	if len(r.b) < 4 {
		r.fail("uint32")
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

// Uint64 reads a uint64.
func (r *Reader) Uint64() uint64 {
	if len(r.b) < 8 {
		r.fail("uint64")
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

// Bytes reads n raw bytes.
func (r *Reader) Bytes(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.fail("bytes")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

// String reads a string (uint32 length, then the bytes).
func (r *Reader) String() []byte {
	n := r.Uint32()
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(r.b)) {
		r.fail("string")
		return nil
	}
	return r.Bytes(int(n))
}

// MPInt reads an mpint as a non-negative integer (a negative one is a protocol error here: no
// value this package reads may be negative).
func (r *Reader) MPInt() *big.Int {
	b := r.String()
	if r.err != nil {
		return nil
	}
	if len(b) > 0 && b[0]&0x80 != 0 {
		r.err = protoErr("negative mpint")
		return nil
	}
	return new(big.Int).SetBytes(b)
}

// NameList reads a name-list: comma separated, each name cleaned and capped, at most MaxNames.
func (r *Reader) NameList() []string {
	b := r.String()
	if r.err != nil || len(b) == 0 {
		return []string{}
	}
	parts := bytes.Split(b, []byte(","))
	if len(parts) > MaxNames {
		r.err = protoErr("a name-list of %d names (the limit is %d)", len(parts), MaxNames)
		return nil
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		out = append(out, Clean(string(p), MaxName))
	}
	return out
}

// Builder appends SSH data types.
type Builder struct{ B []byte }

// Byte appends a byte.
func (w *Builder) Byte(v byte) { w.B = append(w.B, v) }

// Bool appends a boolean.
func (w *Builder) Bool(v bool) {
	if v {
		w.B = append(w.B, 1)
		return
	}
	w.B = append(w.B, 0)
}

// Uint32 appends a uint32.
func (w *Builder) Uint32(v uint32) { w.B = binary.BigEndian.AppendUint32(w.B, v) }

// String appends a string.
func (w *Builder) String(v []byte) {
	w.Uint32(uint32(len(v))) //nolint:gosec // every value this program writes is far below 4 GiB
	w.B = append(w.B, v...)
}

// MPInt appends a non-negative mpint (RFC 4251 section 5): a leading zero byte when the top bit is set.
func (w *Builder) MPInt(v *big.Int) { w.String(MPIntBytes(v)) }

// MPIntBytes is the body of a non-negative mpint.
func MPIntBytes(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// NameList appends a name-list.
func (w *Builder) NameList(names []string) { w.String([]byte(strings.Join(names, ","))) }

// ---- KEXINIT (RFC 4253 section 7.1) --------------------------------------------------------------

// KexInit is an SSH_MSG_KEXINIT.
type KexInit struct {
	Cookie                   [16]byte
	Kex, HostKey             []string
	CipherC2S, CipherS2C     []string
	MACC2S, MACS2C           []string
	CompressionC2S, CompS2C  []string
	LanguageC2S, LanguageS2C []string
	FirstKexFollows          bool
}

// ParseKexInit reads a KEXINIT payload (message number included).
func ParseKexInit(p []byte) (*KexInit, error) {
	r := NewReader(p)
	if m := r.Byte(); m != MsgKexInit {
		if r.Err() != nil {
			return nil, r.Err()
		}
		return nil, protoErr("expected KEXINIT, got message %d", m)
	}
	k := &KexInit{}
	copy(k.Cookie[:], r.Bytes(16))
	for _, dst := range []*[]string{&k.Kex, &k.HostKey, &k.CipherC2S, &k.CipherS2C, &k.MACC2S, &k.MACS2C,
		&k.CompressionC2S, &k.CompS2C, &k.LanguageC2S, &k.LanguageS2C} {
		*dst = r.NameList()
	}
	k.FirstKexFollows = r.Bool()
	r.Uint32() // reserved
	if r.Err() != nil {
		return nil, r.Err()
	}
	return k, nil
}

// Marshal encodes the KEXINIT payload.
func (k *KexInit) Marshal() []byte {
	w := &Builder{}
	w.Byte(MsgKexInit)
	w.B = append(w.B, k.Cookie[:]...)
	for _, l := range [][]string{k.Kex, k.HostKey, k.CipherC2S, k.CipherS2C, k.MACC2S, k.MACS2C,
		k.CompressionC2S, k.CompS2C, k.LanguageC2S, k.LanguageS2C} {
		w.NameList(l)
	}
	w.Bool(k.FirstKexFollows)
	w.Uint32(0)
	return w.B
}

// ---- key-exchange messages -----------------------------------------------------------------------

// KexReply is the server's SSH_MSG_KEX_*_REPLY: its host key, its key-exchange value (Q_S for
// ECDH and the hybrids, f for finite-field Diffie-Hellman, kept raw) and its signature.
type KexReply struct {
	HostKey   []byte
	Value     []byte // Q_S, or the body of the mpint f
	Signature []byte
}

// MaxHostKeyBlob caps a host key or certificate blob, and MaxSignatureBlob a signature: generous
// for ML-DSA-87 composites (about 2.6 KB of key, 4.9 KB of signature) and certificates.
const (
	MaxHostKeyBlob   = 16 << 10
	MaxSignatureBlob = 16 << 10
)

// ParseKexReply reads message 31 (message number included).
func ParseKexReply(p []byte) (*KexReply, error) {
	r := NewReader(p)
	if m := r.Byte(); m != MsgKexReply31 {
		if r.Err() != nil {
			return nil, r.Err()
		}
		return nil, protoErr("expected the key-exchange reply (31), got message %d", m)
	}
	k := &KexReply{HostKey: r.String(), Value: r.String(), Signature: r.String()}
	if r.Err() != nil {
		return nil, r.Err()
	}
	if len(k.HostKey) > MaxHostKeyBlob || len(k.Signature) > MaxSignatureBlob {
		return nil, protoErr("host key of %d bytes or signature of %d bytes is over the limit", len(k.HostKey), len(k.Signature))
	}
	return k, nil
}

// Disconnect is an SSH_MSG_DISCONNECT.
type Disconnect struct {
	Reason      uint32
	Description string
}

// ParseDisconnect reads message 1, best effort.
func ParseDisconnect(p []byte) Disconnect {
	r := NewReader(p)
	r.Byte()
	d := Disconnect{Reason: r.Uint32()}
	d.Description = Clean(string(r.String()), 200)
	return d
}
