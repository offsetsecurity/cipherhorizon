package certfiles

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func block(label string, der []byte) string {
	return "-----BEGIN " + label + "-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END " + label + "-----\n"
}

// A well-formed SEQUENCE that looks like a certificate to the ASN.1 layer, so a scanner
// that decoded a block it should have skipped would return it.
var seq = []byte{0x30, 0x03, 0x02, 0x01, 0x05}

// SR-06: only CERTIFICATE blocks are decoded. A key block that would decode cleanly
// (this one is valid base64 of a valid SEQUENCE) is counted and never returned.
func TestOnlyCertificateBlocksAreDecoded(t *testing.T) {
	in := block("PRIVATE KEY", seq) + block("RSA PRIVATE KEY", seq) + block("EC PRIVATE KEY", seq) +
		block("ENCRYPTED PRIVATE KEY", seq) + block("OPENSSH PRIVATE KEY", seq) + block("PUBLIC KEY", seq) + block("DH PARAMETERS", seq)
	res := scanPEM([]byte(in))
	if len(res.certs) != 0 {
		t.Fatalf("%d block(s) decoded from non-certificate labels", len(res.certs))
	}
	if res.keyBlocks != 5 || res.other != 2 {
		t.Errorf("keyBlocks=%d other=%d, want 5 and 2", res.keyBlocks, res.other)
	}

	in = block("CERTIFICATE", seq) + block("PRIVATE KEY", seq) + block("X509 CERTIFICATE", seq) + block("TRUSTED CERTIFICATE", append(append([]byte{}, seq...), 0x01, 0x02))
	res = scanPEM([]byte(in))
	if len(res.certs) != 3 || res.keyBlocks != 1 {
		t.Errorf("%d certificates, %d key blocks; want 3 and 1", len(res.certs), res.keyBlocks)
	}
	// The trusted-certificate format carries trust settings after the certificate; only the certificate is kept.
	for _, c := range res.certs {
		if !bytes.Equal(c, seq) {
			t.Errorf("certificate bytes %x, want the bare element %x", c, seq)
		}
	}
}

func TestPEMEdgeCases(t *testing.T) {
	cases := map[string]struct {
		in            string
		certs, malfmt int
	}{
		"empty":                    {"", 0, 0},
		"no armor":                 {"hello", 0, 0},
		"CRLF line endings":        {strings.ReplaceAll(block("CERTIFICATE", seq), "\n", "\r\n"), 1, 0},
		"text around the block":    {"Subject: x\n" + block("CERTIFICATE", seq) + "trailer\n", 1, 0},
		"header lines in the body": {"-----BEGIN CERTIFICATE-----\nProc-Type: 4,X\n\n" + base64.StdEncoding.EncodeToString(seq) + "\n-----END CERTIFICATE-----\n", 1, 0},
		"unterminated":             {"-----BEGIN CERTIFICATE-----\nAAAA\n", 0, 1},
		"begin without newline":    {"-----BEGIN CERTIFICATE-----", 0, 1},
		"bad base64":               {"-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n", 0, 1},
		"not a sequence":           {block("CERTIFICATE", []byte{0x04, 0x01, 0x00}), 0, 1},
		"mismatched end label":     {"-----BEGIN CERTIFICATE-----\nAAAA\n-----END OTHER-----\n", 0, 1},
		"label too long":           {"-----BEGIN " + strings.Repeat("X", 100) + "-----\nAAAA\n-----END X-----\n", 0, 1},
		"two certificates":         {block("CERTIFICATE", seq) + block("CERTIFICATE", seq), 2, 0},
	}
	for name, c := range cases {
		res := scanPEM([]byte(c.in))
		if len(res.certs) != c.certs || res.malformed < c.malfmt {
			t.Errorf("%s: %d certs, %d malformed; want %d and at least %d", name, len(res.certs), res.malformed, c.certs, c.malfmt)
		}
	}
}

func TestBoundsOnCertificateCount(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < maxCertsPerFile+3; i++ {
		sb.WriteString(block("CERTIFICATE", seq))
	}
	res := scanPEM([]byte(sb.String()))
	if len(res.certs) != maxCertsPerFile || !res.truncated {
		t.Errorf("%d certificates, truncated=%v; want %d and true", len(res.certs), res.truncated, maxCertsPerFile)
	}
	huge := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 1<<20) + "\n-----END CERTIFICATE-----\n"
	if res := scanPEM([]byte(huge)); len(res.certs) != 0 || res.malformed != 1 {
		t.Errorf("an oversized body: %d certs, %d malformed", len(res.certs), res.malformed)
	}
}

// FuzzScanPEM: whatever the input, the scanner does not panic, returns no more
// certificates than the input has certificate-labelled blocks, and never returns one
// larger than the bound.
func FuzzScanPEM(f *testing.F) {
	f.Add([]byte(block("CERTIFICATE", seq)))
	f.Add([]byte(block("PRIVATE KEY", seq) + block("CERTIFICATE", seq)))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN -----\n-----END -----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4\n\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res := scanPEM(data)
		labelled := bytes.Count(data, []byte("-----BEGIN CERTIFICATE-----")) + bytes.Count(data, []byte("-----BEGIN X509 CERTIFICATE-----")) +
			bytes.Count(data, []byte("-----BEGIN TRUSTED CERTIFICATE-----"))
		if len(res.certs) > labelled {
			t.Fatalf("%d certificates from %d certificate-labelled blocks", len(res.certs), labelled)
		}
		for _, c := range res.certs {
			if len(c) > maxCertDER || len(c) == 0 || c[0] != 0x30 {
				t.Fatalf("bad element of %d bytes", len(c))
			}
		}
	})
}

func FuzzFirstElement(f *testing.F) {
	f.Add(seq)
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if el, ok := firstElement(data); ok && (len(el) > maxCertDER || len(el) > len(data)) {
			t.Fatalf("element of %d bytes from %d", len(el), len(data))
		}
	})
}
