package wire

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
)

func kexinitPayload(lists ...string) []byte {
	b := &Builder{}
	b.Byte(MsgKexInit)
	b.B = append(b.B, make([]byte, 16)...)
	for i := 0; i < 10; i++ {
		v := ""
		if i < len(lists) {
			v = lists[i]
		}
		b.String([]byte(v))
	}
	b.Bool(false)
	b.Uint32(0)
	return b.B
}

func TestKexInitRoundTrip(t *testing.T) {
	k, err := ParseKexInit(kexinitPayload("curve25519-sha256,kex-strict-s-v00@openssh.com", "ssh-ed25519", "aes128-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-512", "none", "none,zlib@openssh.com"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(k.Kex, ",") != "curve25519-sha256,kex-strict-s-v00@openssh.com" || k.CipherS2C[0] != "aes256-ctr" || len(k.CompS2C) != 2 {
		t.Errorf("%+v", k)
	}
	again, err := ParseKexInit(k.Marshal())
	if err != nil || strings.Join(again.Kex, ",") != strings.Join(k.Kex, ",") {
		t.Errorf("round trip: %+v %v", again, err)
	}
}

func TestPacketBounds(t *testing.T) {
	pkt, err := Packet([]byte{MsgIgnore, 1, 2, 3}, rand.Reader)
	if err != nil || len(pkt)%8 != 0 {
		t.Fatalf("packet %d bytes, %v", len(pkt), err)
	}
	if p, err := ReadPacket(bytes.NewReader(pkt)); err != nil || !bytes.Equal(p, []byte{MsgIgnore, 1, 2, 3}) {
		t.Errorf("read back %v %v", p, err)
	}
	huge := binary.BigEndian.AppendUint32(nil, MaxPacket+1)
	if _, err := ReadPacket(bytes.NewReader(append(huge, 4))); err == nil {
		t.Error("a packet over 35000 bytes was accepted")
	}
	short := binary.BigEndian.AppendUint32(nil, 8)
	if _, err := ReadPacket(bytes.NewReader(append(short, 9, 0, 0, 0, 0, 0, 0, 0))); err == nil {
		t.Error("padding longer than the packet was accepted")
	}
}

func TestNameListCaps(t *testing.T) {
	long := strings.Repeat("a,", MaxNames+1)
	if _, err := ParseKexInit(kexinitPayload(long)); err == nil {
		t.Error("a name-list over the limit was accepted")
	}
	k, err := ParseKexInit(kexinitPayload("<script>\x01alert(1)" + strings.Repeat("x", 100)))
	if err != nil {
		t.Fatal(err)
	}
	if n := k.Kex[0]; len(n) > MaxName || strings.ContainsAny(n, "\x01") {
		t.Errorf("name not cleaned and capped: %q", n)
	}
}

func TestIdentificationParsing(t *testing.T) {
	id, pre, err := ReadIdentification(bufio.NewReader(strings.NewReader("hello\r\nSSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")))
	if err != nil || id.ProtoVersion != "2.0" || id.Software != "OpenSSH_9.6p1" || id.Comment != "Ubuntu-3ubuntu13" || len(pre) != 1 || id.Preamble != 1 {
		t.Fatalf("%+v %v %v", id, pre, err)
	}
	if _, _, err := ReadIdentification(bufio.NewReader(strings.NewReader("SSH-2.0-" + strings.Repeat("x", 300) + "\r\n"))); err == nil {
		t.Error("an identification over 255 bytes was accepted")
	}
}

func TestHostKeyParsing(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b := &Builder{}
	b.String([]byte("ssh-ed25519"))
	b.String(pub)
	k, err := ParsePublicKey(b.B)
	if err != nil || k.Algorithm != "Ed25519" || !strings.HasPrefix(k.Fingerprint, "SHA256:") || strings.HasSuffix(k.Fingerprint, "=") {
		t.Fatalf("%+v %v", k, err)
	}
	b = &Builder{}
	b.String([]byte("ssh-new-algorithm@example.com"))
	b.String([]byte{1, 2, 3})
	if k, err := ParsePublicKey(b.B); err != nil || k.Algorithm != "unknown" {
		t.Errorf("an unknown key type must be named, not refused: %+v %v", k, err)
	}
}

func FuzzIdentification(f *testing.F) {
	f.Add([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	f.Add([]byte("banner\nSSH-1.99-x y\r\n"))
	f.Add([]byte("SSH-\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		id, pre, err := ReadIdentification(bufio.NewReader(bytes.NewReader(b)))
		if len(id.Raw) > MaxIdentLine || len(pre) > MaxPreambleLines {
			t.Fatalf("bounds broken: %d %d", len(id.Raw), len(pre))
		}
		_ = err
	})
}

func FuzzKEXINIT(f *testing.F) {
	f.Add(kexinitPayload("curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none"))
	f.Add([]byte{MsgKexInit})
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := ParseKexInit(b)
		if err != nil {
			return
		}
		for _, l := range [][]string{k.Kex, k.HostKey, k.CipherC2S, k.MACS2C} {
			if len(l) > MaxNames {
				t.Fatalf("%d names", len(l))
			}
			for _, n := range l {
				if len(n) > MaxName {
					t.Fatalf("name of %d bytes", len(n))
				}
			}
		}
		// Framing a payload and reading it back must give the same bytes.
		pkt, err := Packet(b, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) <= MaxPacket-64 {
			if got, err := ReadPacket(bytes.NewReader(pkt)); err != nil || !bytes.Equal(got, b) {
				t.Fatalf("packet round trip: %v", err)
			}
		}
	})
}

func FuzzHostKeyBlob(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b := &Builder{}
	b.String([]byte("ssh-ed25519"))
	b.String(pub)
	f.Add(b.B)
	b = &Builder{}
	b.String([]byte("ssh-ed25519-cert-v01@openssh.com"))
	b.String([]byte("nonce"))
	b.String(pub)
	f.Add(b.B)
	b = &Builder{}
	b.String([]byte("ssh-rsa"))
	b.String([]byte{1, 0, 1})
	b.String(bytes.Repeat([]byte{0x7f}, 256))
	f.Add(b.B)
	f.Fuzz(func(t *testing.T, blob []byte) {
		k, err := ParsePublicKey(blob)
		if err != nil {
			return
		}
		if k.Cert != nil && len(k.Cert.Principals) > 16 {
			t.Fatalf("%d principals", len(k.Cert.Principals))
		}
		_ = k.Verify(k.Type, []byte("h"), blob) // must not panic on any input
	})
}

func FuzzKEXReply(f *testing.F) {
	b := &Builder{}
	b.Byte(MsgKexReply31)
	b.String([]byte("key"))
	b.String([]byte("value"))
	b.String([]byte("sig"))
	f.Add(b.B)
	f.Fuzz(func(t *testing.T, p []byte) {
		r, err := ParseKexReply(p)
		if err != nil {
			return
		}
		if len(r.HostKey) > MaxHostKeyBlob || len(r.Signature) > MaxSignatureBlob {
			t.Fatal("limits broken")
		}
	})
}
